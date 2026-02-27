#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Microsoft Authenticator 数据库导出为 otpauth:// 格式
支持 Android (PhoneFactor) 和 iOS (.sqlite CoreData) 格式

使用方法:
  1. 将从 iPhone 导出的 .sqlite 文件放到与本脚本同一目录下。
  2. 在 WinPython Command Prompt 中运行: python MSAuthExportScript.py
"""

import sqlite3
import os
import sys
import base64
from datetime import datetime
from urllib.parse import quote

def base64_to_base32(base64_str):
    """
    将 Base64 编码的字符串转换为 Base32 编码
    用于处理 Microsoft 个人账户的密钥
    """
    try:
        decoded_bytes = base64.b64decode(base64_str)
        base32_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
        result = []
        bits = 0
        bit_count = 0

        for byte in decoded_bytes:
            bits = (bits << 8) | byte
            bit_count += 8

            while bit_count >= 5:
                bit_count -= 5
                index = (bits >> bit_count) & 0x1F
                result.append(base32_alphabet[index])

        if bit_count > 0:
            index = (bits << (5 - bit_count)) & 0x1F
            result.append(base32_alphabet[index])

        return ''.join(result)
    except Exception as e:
        return None

# ==========================================
# 1. 自动寻找数据库文件
# ==========================================
script_dir = os.path.dirname(os.path.abspath(__file__))
DB_PATH = None

# 查找同目录下的 .sqlite 文件或 PhoneFactor 文件
for f in os.listdir(script_dir):
    if f.endswith('.sqlite') or f.lower() == 'phonefactor':
        if not f.endswith('-wal') and not f.endswith('-shm'):
            DB_PATH = os.path.join(script_dir, f)
            break

if not DB_PATH:
    std_path = os.path.join(script_dir, 'databases', 'PhoneFactor')
    if os.path.exists(std_path):
        DB_PATH = std_path

if not DB_PATH or not os.path.exists(DB_PATH):
    print('错误: 未找到数据库文件！')
    print('请将从 iPhone 导出的 .sqlite 文件放置在与此脚本相同的文件夹中。')
    sys.exit(1)

DB_PATH = os.path.normpath(DB_PATH)

# ==========================================
# 2. 准备输出文件
# ==========================================
timestamp = datetime.now().strftime('%Y-%m-%d-%H%M%S')
output_filename = f'msauth-export-{timestamp}.txt'
OUTPUT_FILE = os.path.join(script_dir, output_filename)

print('=' * 60)
print('Microsoft Authenticator 导出工具 (兼容 iOS/Android)')
print('=' * 60)
print(f'读取数据库: {os.path.basename(DB_PATH)}')
print(f'输出文件:   {output_filename}')
print('=' * 60)

# ==========================================
# 3. 解析数据库并提取
# ==========================================
try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 探测表结构 (iOS 使用 ZACCOUNT, Android 使用 accounts)
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ZACCOUNT'")
    is_ios = cursor.fetchone() is not None

    if is_ios:
        print("\n-> 检测到 iPhone (iOS CoreData) 数据库结构")
        cursor.execute("PRAGMA table_info(ZACCOUNT)")
        cols = [info[1].upper() for info in cursor.fetchall()]
        
        # 精确匹配字段名，避免误匹配到 ZHASSECRET 等布尔值字段
        def get_col(possible_names, default_name):
            for name in possible_names:
                if name in cols:
                    return name
            return default_name

        c_name = get_col(['ZNAME', 'ZACCOUNTNAME'], 'ZNAME')
        c_user = get_col(['ZUSERNAME', 'ZEMAIL'], 'ZUSERNAME')
        # 严格过滤，确保提取的是真实的密钥列
        c_sec  = get_col(['ZOATHSECRETKEY', 'ZOATH_SECRET_KEY', 'ZSECRETKEY', 'ZSECRET'], 'ZOATHSECRETKEY')
        c_type = get_col(['ZACCOUNTTYPE', 'ZTYPE', 'Z_TYPE'], None)
        
        if c_type:
            query = f"SELECT {c_name}, {c_user}, {c_sec}, {c_type} FROM ZACCOUNT WHERE {c_sec} IS NOT NULL"
        else:
            query = f"SELECT {c_name}, {c_user}, {c_sec}, 0 AS dummy_type FROM ZACCOUNT WHERE {c_sec} IS NOT NULL"
    else:
        print("\n-> 检测到 Android 数据库结构")
        query = """
            SELECT name, username, oath_secret_key, account_type
            FROM accounts
            WHERE oath_secret_key IS NOT NULL
        """

    cursor.execute(query)
    rows = cursor.fetchall()

    if not rows:
        print('\n未找到任何有效的 2FA 账户')
        conn.close()
        sys.exit(0)

    print(f'-> 成功找到 {len(rows)} 个有效账户\n')

    otpauth_urls = []

    for index, row in enumerate(rows, 1):
        name, username, secret_key, account_type = row
        
        name = name or 'Unknown'
        username = username or ''
        account_type = account_type or 0

        # 如果提取出的 secret_key 依然不是字符串（例如被错误识别的数字），则跳过以防报错
        if not isinstance(secret_key, str):
            continue

        # 过滤掉空字符串
        if not secret_key.strip():
            continue

        if account_type == 1:
            # Microsoft 个人账户，需要 Base64 → Base32 转换
            secret_cleaned = secret_key.replace(' ', '').replace('\t', '').replace('\n', '').replace('\r', '')
            secret = base64_to_base32(secret_cleaned)
            if not secret:
                print(f'  [{index:2d}] 转换失败，跳过: {name} {username}')
                continue
            account_type_label = '(Type=1, Microsoft Base64)'
        elif account_type == 2:
            secret = secret_key.replace(' ', '').replace('\t', '').replace('\n', '').replace('\r', '').upper()
            account_type_label = '(Type=2, SHA256)'
        else:
            secret = secret_key.replace(' ', '').replace('\t', '').replace('\n', '').replace('\r', '').upper()
            account_type_label = '(Type=0, 标准 TOTP)'

        issuer_encoded = quote(name)
        account_encoded = quote(username) if username else ''
        label = f'{issuer_encoded}:{account_encoded}' if username else issuer_encoded
        algorithm = 'SHA256' if account_type == 2 else 'SHA1'

        otpauth_url = f'otpauth://totp/{label}?secret={secret}&digits=6&period=30&algorithm={algorithm}&issuer={issuer_encoded}'
        otpauth_urls.append(otpauth_url)

        try:
            display_issuer = name[:20] if len(name) <= 22 else name[:20] + '..'
            display_account = username[:24] if len(username) <= 26 else username[:24] + '..'
            print(f'  [{index:2d}] {display_issuer.ljust(22)} {display_account.ljust(26)} {account_type_label}')
        except (UnicodeEncodeError, UnicodeDecodeError):
            print(f'  [{index:2d}] [Account {index}] {account_type_label}')

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for url in otpauth_urls:
            f.write(url + '\n')

    conn.close()

    print('\n' + '=' * 60)
    print(f'✅ 成功导出 {len(otpauth_urls)} 个账户到文件: {output_filename}')
    print('=' * 60)
    print('\n提示: 你现在可以将生成的 txt 文件导入到 2FA Manager 中了。')
    print('安全警告: 导入完成后，请务必彻底删除数据库文件及生成的 txt 文本！\n')

except sqlite3.Error as e:
    print(f'\nSQLite 数据库读取错误: {e}')
    sys.exit(1)
except Exception as e:
    print(f'\n运行时错误: {e}')
    sys.exit(1)
