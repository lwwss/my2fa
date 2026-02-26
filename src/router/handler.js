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
	handleGet2FAStatus,
	handleSetup2FA,
	handleVerifyAndEnable2FA,
	handleDisable2FA,
} from '../utils/auth.js';
import { createPreflightResponse } from '../utils/security.js';
import { getLogger } from '../utils/logger.js';

/**
 * 处理HTTP请求的主要函数
 */
export async function handleRequest(request, env) {
	const url = new URL(request.url);
	const method = request.method;
	const pathname = url.pathname;
	const logger = getLogger(env);

	try {
		// 🔧 首次设置路由（不需要认证）
		if (pathname === '/setup') {
			const setupRequired = await checkIfSetupRequired(env);
			if (!setupRequired) {
				return Response.redirect(new URL('/', request.url).toString(), 302);
			}
			return await createSetupPage();
		}

		// 🔧 首次设置 API（不需要认证）
		if (pathname === '/api/setup' && method === 'POST') {
			return await handleFirstTimeSetup(request, env);
		}

		const setupRequired = await checkIfSetupRequired(env);
		if (setupRequired && pathname === '/') {
			return Response.redirect(new URL('/setup', request.url).toString(), 302);
		}

		// 🔐 检查是否需要身份验证
		let authDetails = null;
		if (requiresAuth(pathname)) {
			authDetails = await verifyAuthWithDetails(request, env);

			if (!authDetails || !authDetails.valid) {
				if (!env.SECRETS_KV) {
					return createErrorResponse('服务未配置', '服务器未配置 KV 存储。请联系管理员配置 SECRETS_KV。', 503, request);
				}

				const storedPasswordHash = await env.SECRETS_KV.get('user_password');
				if (!storedPasswordHash) {
					return createErrorResponse('未设置密码', '请访问 /setup 进行首次设置。', 503, request);
				}

				return createUnauthorizedResponse(null, request);
			}

			request.authDetails = authDetails;
		}

		// 静态路由处理
		if (pathname === '/' || pathname === '') {
			return await createMainPage();
		}

		if (pathname === '/manifest.json') {
			return createManifest(request);
		}

		if (pathname === '/sw.js') {
			return createServiceWorker(env);
		}

		if (pathname === '/icon-192.png' || pathname === '/icon-512.png') {
			const size = pathname.includes('512') ? 512 : 192;
			return createDefaultIcon(size);
		}

		// 懒加载模块路由
		if (pathname.startsWith('/modules/')) {
			const moduleName = pathname.substring(9).replace('.js', '');
			const allowedModules = ['import', 'export', 'backup', 'qrcode', 'tools', 'googleMigration'];

			if (!allowedModules.includes(moduleName)) {
				return createErrorResponse('模块未找到', `不存在的模块: ${moduleName}`, 404, request);
			}

			try {
				const moduleCode = getModuleCode(moduleName);
				return new Response(moduleCode, {
					headers: {
						'Content-Type': 'application/javascript; charset=utf-8',
						'Cache-Control': 'public, max-age=3600',
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

			// 🔄 自动续期
			if (request.authDetails && request.authDetails.needsRefresh) {
				const newResponse = new Response(response.body, response);
				newResponse.headers.set('X-Token-Refresh-Needed', 'true');
				newResponse.headers.set('X-Token-Remaining-Days', request.authDetails.remainingDays.toFixed(2));
				return newResponse;
			}

			return response;
		}

		// OTP生成路由
		if (pathname === '/otp') {
			return await handleGenerateOTP('', request);
		}

		if (pathname.startsWith('/otp/')) {
			const secret = pathname.substring(5);
			return await handleGenerateOTP(secret, request);
		}

		return createErrorResponse('页面未找到', '请求的页面不存在', 404, request);
	} catch (error) {
		logger.error('请求处理失败', { method, pathname, errorMessage: error.message }, error);
		return createErrorResponse('服务器错误', '请求处理失败，请稍后重试', 500, request);
	}
}

/**
 * 处理API请求
 */
async function handleApiRequest(pathname, method, request, env) {
	// 管理员 2FA 管理 API
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
			case 'GET': return handleGetSecrets(env);
			case 'POST': return handleAddSecret(request, env);
			default: return createErrorResponse('方法不允许', `不支持的HTTP方法: ${method}`, 405, request);
		}
	}

	if (pathname === '/api/secrets/batch') {
		if (method === 'POST') return handleBatchAddSecrets(request, env);
		return createErrorResponse('方法不允许', `不支持的HTTP方法: ${method}`, 405, request);
	}

	if (pathname.startsWith('/api/secrets/')) {
		const secretId = pathname.substring('/api/secrets/'.length);
		if (!secretId) return createErrorResponse('无效路径', '缺少密钥ID', 400, request);

		switch (method) {
			case 'PUT': return handleUpdateSecret(request, env);
			case 'DELETE': return handleDeleteSecret(request, env);
			default: return createErrorResponse('方法不允许', `不支持的HTTP方法: ${method}`, 405, request);
		}
	}

	// 备份管理API
	if (pathname === '/api/backup') {
		switch (method) {
			case 'POST': return handleBackupSecrets(request, env);
			case 'GET': return handleGetBackups(request, env);
			default: return createErrorResponse('方法不允许', `不支持的HTTP方法: ${method}`, 405, request);
		}
	}

	if (pathname === '/api/backup/restore') {
		if (method === 'POST') return handleRestoreBackup(request, env);
		return createErrorResponse('方法不允许', `不支持的HTTP方法: ${method}`, 405, request);
	}

	if (pathname.startsWith('/api/backup/export/')) {
		if (method === 'GET') {
			const backupKey = pathname.replace('/api/backup/export/', '');
			return handleExportBackup(request, env, backupKey);
		}
		return createErrorResponse('方法不允许', `不支持的HTTP方法: ${method}`, 405, request);
	}

	if (pathname.startsWith('/api/favicon/')) {
		if (method === 'GET') {
			const domain = pathname.replace('/api/favicon/', '');
			return handleFaviconProxy(request, env, domain);
		}
		return createErrorResponse('方法不允许', `不支持的HTTP方法: ${method}`, 405, request);
	}

	return createErrorResponse('API未找到', '请求的API端点不存在', 404, request);
}

export function handleCORS(request) {
	return createPreflightResponse(request);
}
