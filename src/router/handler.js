/**
 * 路由处理器模块
 * 负责解析请求并分发到对应的处理函数
 */

// API 处理器
import {
	handleGetSecrets,
	handleAddSecret,
	handleUpdateSecret,
	handleDeleteSecret,
	handleGenerateOTP,
	handleBatchAddSecrets,
	handleBackupSecrets,
	handleGetBackups,
	handleRestoreBackup,
	handleExportBackup,
} from '../api/secrets/index.js';
import { handleFaviconProxy } from '../api/favicon.js';

// UI 页面生成器
import { createMainPage } from '../ui/page.js';
import { createSetupPage } from '../ui/setupPage.js';
import { createManifest, createDefaultIcon } from '../ui/manifest.js';
import { createServiceWorker } from '../ui/serviceworker.js';
import { getModuleCode } from '../ui/scripts/index.js';

// 工具函数
import { createErrorResponse } from '../utils/response.js';
import {
	verifyAuthWithDetails,
	requiresAuth,
	createUnauthorizedResponse,
	handleLogin,
	handleRefreshToken,
	checkIfSetupRequired,
	handleFirstTimeSetup,
	handleGet2FAStatus,         // 恢复 2FA 相关导入
	handleSetup2FA,             // 恢复 2FA 相关导入
	handleVerifyAndEnable2FA,   // 恢复 2FA 相关导入
	handleDisable2FA,           // 恢复 2FA 相关导入
	handleChangePassword,       // 恢复修改密码导入
} from '../utils/auth.js';
import { createPreflightResponse } from '../utils/security.js';
import { getLogger } from '../utils/logger.js';

/**
 * 伪装页面：获取并显示 Bing 每日壁纸
 */
async function createBingWallpaperPage() {
	// 默认备用图片，以防 API 请求失败
	let imageUrl = 'https://www.bing.com/th?id=OHR.StarryNight_ZH-CN2164472879_1920x1080.jpg';
	try {
		// 请求必应官方图片接口
		const res = await fetch('https://www.bing.com/HPImageArchive.aspx?format=js&idx=0&n=1&mkt=zh-CN');
		if (res.ok) {
			const data = await res.json();
			if (data.images && data.images.length > 0) {
				imageUrl = 'https://www.bing.com' + data.images[0].url;
			}
		}
	} catch (e) {
		// 忽略错误，使用默认备用图
	}

	const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body, html {
            margin: 0;
            padding: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
            background-color: #000;
        }
        .wallpaper {
            width: 100vw;
            height: 100vh;
            background-image: url('${imageUrl}');
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            animation: fadeIn 1.5s ease-in-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
    </style>
</head>
<body>
    <div class="wallpaper"></div>
</body>
</html>`;

	return new Response(html, {
		headers: {
			'Content-Type': 'text/html; charset=utf-8',
			'Cache-Control': 'public, max-age=3600', // 缓存1小时
		},
	});
}

/**
 * 处理HTTP请求的主要函数
 * @param {Request} request - HTTP请求对象
 * @param {Object} env - 环境变量对象，包含KV存储
 * @returns {Response} HTTP响应
 */
export async function handleRequest(request, env) {
	const url = new URL(request.url);
	const method = request.method;
	const pathname = url.pathname;
	const logger = getLogger(env);

	// 解析配置的隐藏入口路径（去掉开头可能包含的斜杠）
	const secretEntryPath = env.SECRET_ENTRY_PATH ? `/${env.SECRET_ENTRY_PATH.replace(/^\//, '')}` : null;

	try {
		// 🔧 首次设置路由（不需要认证）
		if (pathname === '/setup') {
			const setupRequired = await checkIfSetupRequired(env);
			if (!setupRequired) {
				// 已完成设置，重定向到自定义真实入口（如果配置了的话）或根目录
				return Response.redirect(new URL(secretEntryPath || '/', request.url).toString(), 302);
			}
			return await createSetupPage();
		}

		// 🔧 首次设置 API（不需要认证）
		if (pathname === '/api/setup' && method === 'POST') {
			return await handleFirstTimeSetup(request, env);
		}

		// 检查是否需要首次设置
		const setupRequired = await checkIfSetupRequired(env);
		if (setupRequired) {
			// 需要首次设置时：
			// 1. 如果访问了配置好的真实入口
			// 2. 或是没有配置真实入口且访问了根目录
			// 则重定向到设置页面
			if ((secretEntryPath && pathname === secretEntryPath) || (!secretEntryPath && pathname === '/')) {
				return Response.redirect(new URL('/setup', request.url).toString(), 302);
			}
		}

		// 判断当前访问是否是合法的隐藏入口
		const isSecretEntry = secretEntryPath && pathname === secretEntryPath;

		// 🔐 检查是否需要身份验证（使用详细验证以支持自动续期）
		let authDetails = null;
		// 拦截保护逻辑：排除合法的隐藏入口（隐藏入口 HTML 需要加载，并在前端弹出密码框）
		if (requiresAuth(pathname) && !isSecretEntry) {
			authDetails = await verifyAuthWithDetails(request, env);

			if (!authDetails || !authDetails.valid) {
				// 检查是否未配置 KV 存储
				if (!env.SECRETS_KV) {
					return createErrorResponse('服务未配置', '服务器未配置 KV 存储。请联系管理员配置 SECRETS_KV。', 503, request);
				}

				// 检查是否未设置密码
				const storedPasswordHash = await env.SECRETS_KV.get('user_password');
				if (!storedPasswordHash) {
					return createErrorResponse('未设置密码', '请访问 /setup 进行首次设置。', 503, request);
				}

				return createUnauthorizedResponse(null, request);
			}

			// 📊 记录认证详情（用于自动续期）
			request.authDetails = authDetails;
		}

		// 静态路由处理: 根目录伪装层
		if (pathname === '/' || pathname === '') {
			if (secretEntryPath) {
				// 如果已配置 SECRET_ENTRY_PATH，则根目录显示 Bing 壁纸进行伪装
				return await createBingWallpaperPage();
			} else {
				// 否则正常显示主页
				return await createMainPage();
			}
		}

		// 静态路由处理: 真实的隐藏入口
		if (isSecretEntry) {
			return await createMainPage();
		}

		// PWA Manifest
		if (pathname === '/manifest.json') {
			return createManifest(request);
		}

		// Service Worker
		if (pathname === '/sw.js') {
			return createServiceWorker(env);
		}

		// PWA 图标（使用默认SVG图标）
		if (pathname === '/icon-192.png' || pathname === '/icon-512.png') {
			const size = pathname.includes('512') ? 512 : 192;
			return createDefaultIcon(size);
		}

		// 懒加载模块路由（需要认证）
		if (pathname.startsWith('/modules/')) {
			const moduleName = pathname.substring(9).replace('.js', ''); // 去掉 '/modules/' 和 '.js'
			const allowedModules = ['import', 'export', 'backup', 'qrcode', 'tools', 'googleMigration'];

			if (!allowedModules.includes(moduleName)) {
				return createErrorResponse('模块未找到', `不存在的模块: ${moduleName}`, 404, request);
			}

			try {
				const moduleCode = getModuleCode(moduleName);
				return new Response(moduleCode, {
					headers: {
						'Content-Type': 'application/javascript; charset=utf-8',
						'Cache-Control': 'public, max-age=3600', // 缓存1小时
						'Access-Control-Allow-Origin': '*',
					},
				});
			} catch (error) {
				logger.error(`加载模块 ${moduleName} 失败`, { errorMessage: error.message }, error);
				return createErrorResponse('模块加载失败', error.message, 500, request);
			}
		}

		// 登录路由
		if (pathname === '/api/login' && method === 'POST') {
			return await handleLogin(request, env);
		}

		// Token 刷新路由
		if (pathname === '/api/refresh-token' && method === 'POST') {
			return await handleRefreshToken(request, env);
		}

		// API路由处理
		if (pathname.startsWith('/api/')) {
			const response = await handleApiRequest(pathname, method, request, env);

			// 🔄 自动续期：如果 Token 剩余时间 < 7天，在响应头中添加标记
			if (request.authDetails && request.authDetails.needsRefresh) {
				const newResponse = new Response(response.body, response);
				newResponse.headers.set('X-Token-Refresh-Needed', 'true');
				newResponse.headers.set('X-Token-Remaining-Days', request.authDetails.remainingDays.toFixed(2));

				logger.info('Token 即将过期，建议客户端刷新', {
					remainingDays: request.authDetails.remainingDays.toFixed(2),
				});

				return newResponse;
			}

			return response;
		}

		// OTP生成路由（支持高级参数）
		// 处理 /otp（显示使用说明）
		if (pathname === '/otp') {
			return await handleGenerateOTP('', request);
		}

		// 处理 /otp/{secret}（生成OTP）
		if (pathname.startsWith('/otp/')) {
			const secret = pathname.substring(5); // 去掉 '/otp/'
			return await handleGenerateOTP(secret, request);
		}

		// 404处理
		return createErrorResponse('页面未找到', '请求的页面不存在', 404, request);
	} catch (error) {
		logger.error(
			'请求处理失败',
			{
				method,
				pathname,
				errorMessage: error.message,
			},
			error,
		);
		return createErrorResponse('服务器错误', '请求处理失败，请稍后重试', 500, request);
	}
}

/**
 * 处理API请求
 * @param {string} pathname - 请求路径
 * @param {string} method - HTTP方法
 * @param {Request} request - HTTP请求对象
 * @param {Object} env - 环境变量对象
 * @returns {Response} HTTP响应
 */
async function handleApiRequest(pathname, method, request, env) {
	// ================= 恢复：管理员修改密码 API =================
	if (pathname === '/api/settings/password' && method === 'POST') {
		return await handleChangePassword(request, env);
	}

	// ================= 恢复：管理员 2FA 管理 API =================
	if (pathname.startsWith('/api/admin/2fa')) {
		if (pathname === '/api/admin/2fa/status' && method === 'GET') return handleGet2FAStatus(request, env);
		if (pathname === '/api/admin/2fa/setup' && method === 'POST') return handleSetup2FA(request, env);
		if (pathname === '/api/admin/2fa/verify' && method === 'POST') return handleVerifyAndEnable2FA(request, env);
		if (pathname === '/api/admin/2fa/disable' && method === 'POST') return handleDisable2FA(request, env);
		return createErrorResponse('方法不允许', `不支持的HTTP方法或路径`, 405, request);
	}

	// 密钥管理API
	if (pathname === '/api/secrets') {
		switch (method) {
			case 'GET':
				return handleGetSecrets(env);
			case 'POST':
				return handleAddSecret(request, env);
			default:
				return createErrorResponse('方法不允许', `不支持的HTTP方法: ${method}`, 405, request);
		}
	}

	// 批量导入API（必须在 /api/secrets/{id} 之前匹配）
	if (pathname === '/api/secrets/batch') {
		if (method === 'POST') {
			return handleBatchAddSecrets(request, env);
		}
		return createErrorResponse('方法不允许', `不支持的HTTP方法: ${method}`, 405, request);
	}

	// 单个密钥操作API
	if (pathname.startsWith('/api/secrets/')) {
		const secretId = pathname.substring('/api/secrets/'.length);
		if (!secretId) {
			return createErrorResponse('无效路径', '缺少密钥ID', 400, request);
		}

		switch (method) {
			case 'PUT':
				return handleUpdateSecret(request, env);
			case 'DELETE':
				return handleDeleteSecret(request, env);
			default:
				return createErrorResponse('方法不允许', `不支持的HTTP方法: ${method}`, 405, request);
		}
	}

	// 备份管理API
	if (pathname === '/api/backup') {
		switch (method) {
			case 'POST':
				return handleBackupSecrets(request, env);
			case 'GET':
				return handleGetBackups(request, env);
			default:
				return createErrorResponse('方法不允许', `不支持的HTTP方法: ${method}`, 405, request);
		}
	}

	// 恢复备份API
	if (pathname === '/api/backup/restore') {
		if (method === 'POST') {
			return handleRestoreBackup(request, env);
		}
		return createErrorResponse('方法不允许', `不支持的HTTP方法: ${method}`, 405, request);
	}

	// 导出备份API
	if (pathname.startsWith('/api/backup/export/')) {
		if (method === 'GET') {
			const backupKey = pathname.replace('/api/backup/export/', '');
			return handleExportBackup(request, env, backupKey);
		}
		return createErrorResponse('方法不允许', `不支持的HTTP方法: ${method}`, 405, request);
	}

	// Favicon 代理 API（不需要认证，公开访问）
	if (pathname.startsWith('/api/favicon/')) {
		if (method === 'GET') {
			const domain = pathname.replace('/api/favicon/', '');
			return handleFaviconProxy(request, env, domain);
		}
		return createErrorResponse('方法不允许', `不支持的HTTP方法: ${method}`, 405, request);
	}

	// 未知API路径
	return createErrorResponse('API未找到', '请求的API端点不存在', 404, request);
}

/**
 * 处理CORS预检请求
 * @param {Request} request - HTTP请求对象
 * @returns {Response|null} CORS响应或 null
 */
export function handleCORS(request) {
	return createPreflightResponse(request);
}
