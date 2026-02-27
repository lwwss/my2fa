#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3
import os
import sys
import base64
from datetime import datetime
from urllib.parse import quote

def base64_to_base32(base64_str):
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
    print('错误: 未找到数据库文件！请将从 iPhone 导出的 .sqlite 文件放置在脚本同级目录。')
    sys.exit(1)

DB_PATH = os.path.normpath(DB_PATH)

# ==========================================
# 2. 准备输出文件
# ==========================================
timestamp = datetime.now().strftime('%Y-%m-%d-%H%M%S')
output_filename = f'msauth-export-{timestamp}.txt'
OUTPUT_FILE = os.path.join(script_dir, output_filename)

print('=' * 60)
print('Microsoft Authenticator 导出工具 (深度诊断版)')
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

    # 获取所有表名
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    all_tables = [t[0].upper() for t in cursor.fetchall()]

    is_ios = 'ZACCOUNT' in all_tables

    if is_ios:
        print("\n-> 检测到 iPhone (iOS CoreData) 数据库结构")
        cursor.execute("PRAGMA table_info(ZACCOUNT)")
        cols = [info[1].upper() for info in cursor.fetchall()]
        
        print(f"-> [诊断] ZACCOUNT 表的字段有: {cols}")
        
        def get_col(possible_names, default_name):
            for name in possible_names:
                if name in cols:
                    return name
            return default_name

        c_name = get_col(['ZNAME', 'ZACCOUNTNAME', 'ZISSUER'], 'ZNAME')
        c_user = get_col(['ZUSERNAME', 'ZEMAIL', 'ZACCOUNT'], 'ZUSERNAME')
        c_type = get_col(['ZACCOUNTTYPE', 'ZTYPE', 'Z_TYPE'], None)
        
        # 智能寻找密钥字段，规避布尔值（如 ZHASSECRET）
        c_sec = get_col(['ZOATHSECRETKEY', 'ZOATH_SECRET_KEY', 'ZSECRETKEY', 'ZSECRET', 'ZOATHSECRET', 'ZKEY'], None)
        
        if not c_sec:
            for c in cols:
                if ('SECRET' in c or 'KEY' in c) and 'HAS' not in c and 'TYPE' not in c:
                    c_sec = c
                    break
                    
        # 如果 ZACCOUNT 表里真的没有密钥字段，说明存在了关联表里
        if not c_sec:
            print("\n❌ 错误：在 ZACCOUNT 表中找不到密钥字段！")
            print(f"-> [诊断] 数据库里的所有表：{all_tables}")
            print("============================================================")
            print("请复制从【-> [诊断] ZACCOUNT 表的字段有...】开始的全部输出发给我！")
            print("你的版本可能将密钥存在了其他表（如 ZOATHTOKEN）中，我会立即为你更新关联查询代码。")
            sys.exit(1)
            
        print(f"-> 成功定位字段：服务名={c_name}, 账号={c_user}, 密钥={c_sec}")
        
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

        if not isinstance(secret_key, str) or not secret_key.strip():
            continue

        if account_type == 1:
            secret_cleaned = secret_key.replace(' ', '').replace('\t', '').replace('\n', '').replace('\r', '')
            secret = base64_to_base32(secret_cleaned)
            if not secret:
                continue
            account_type_label = '(Type=1, Microsoft)'
        elif account_type == 2:
            secret = secret_key.replace(' ', '').replace('\t', '').replace('\n', '').replace('\r', '').upper()
            account_type_label = '(Type=2, SHA256)'
        else:
            secret = secret_key.replace(' ', '').replace('\t', '').replace('\n', '').replace('\r', '').upper()
            account_type_label = '(Type=0, TOTP)'

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
        except:
            print(f'  [{index:2d}] [Account {index}] {account_type_label}')

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for url in otpauth_urls:
            f.write(url + '\n')

    conn.close()

    print('\n' + '=' * 60)
    print(f'✅ 成功导出 {len(otpauth_urls)} 个账户到文件: {output_filename}')
    print('=' * 60)

except sqlite3.Error as e:
    print(f'\nSQLite 数据库读取错误: {e}')
    sys.exit(1)
except Exception as e:
    print(f'\n运行时错误: {e}')
    sys.exit(1)
