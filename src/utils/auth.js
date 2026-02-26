/**
 * 身份验证工具模块
 * 提供 JWT Token 认证功能，支持自动过期，及管理员 2FA 验证
 */

import { createErrorResponse } from './response.js';
import { checkRateLimit, createRateLimitResponse, getClientIdentifier, RATE_LIMIT_PRESETS } from './rateLimit.js';
import { getSecurityHeaders } from './security.js';
import { getLogger } from './logger.js';
import {
	ValidationError,
	AuthenticationError,
	AuthorizationError,
	ConflictError,
	ConfigurationError,
	ErrorFactory,
	errorToResponse,
	logError,
} from './errors.js';
import { generateOTP, generateOTPAuthURL } from '../otp/generator.js';

// JWT 配置
const JWT_EXPIRY_DAYS = 30; // JWT 有效期：30天
const JWT_ALGORITHM = 'HS256';
const JWT_AUTO_REFRESH_THRESHOLD_DAYS = 7; // 剩余时间少于7天时自动续期

// Cookie 配置
const COOKIE_NAME = 'auth_token';
const COOKIE_MAX_AGE = JWT_EXPIRY_DAYS * 24 * 60 * 60; // 30天（秒）

// KV 存储键
const KV_USER_PASSWORD_KEY = 'user_password';
const KV_SETUP_COMPLETED_KEY = 'setup_completed';
const KV_ADMIN_2FA_ENABLED = 'admin_2fa_enabled';
const KV_ADMIN_2FA_SECRET = 'admin_2fa_secret';

// 密码配置
const PASSWORD_MIN_LENGTH = 8;
const PBKDF2_ITERATIONS = 100000; // PBKDF2 迭代次数

/**
 * 验证密码强度
 * @param {string} password - 密码
 * @returns {Object} { valid: boolean, message: string }
 */
function validatePasswordStrength(password) {
	if (!password || password.length < PASSWORD_MIN_LENGTH) {
		return {
			valid: false,
			message: `密码长度至少为 ${PASSWORD_MIN_LENGTH} 位`,
		};
	}

	const hasUpperCase = /[A-Z]/.test(password);
	const hasLowerCase = /[a-z]/.test(password);
	const hasNumber = /[0-9]/.test(password);
	const hasSymbol = /[^A-Za-z0-9]/.test(password);

	if (!hasUpperCase) {
		return { valid: false, message: '密码必须包含至少一个大写字母' };
	}
	if (!hasLowerCase) {
		return { valid: false, message: '密码必须包含至少一个小写字母' };
	}
	if (!hasNumber) {
		return { valid: false, message: '密码必须包含至少一个数字' };
	}
	if (!hasSymbol) {
		return { valid: false, message: '密码必须包含至少一个特殊字符' };
	}

	return { valid: true, message: '密码强度符合要求' };
}

/**
 * 使用 PBKDF2 加密密码
 * @param {string} password - 明文密码
 * @returns {Promise<string>} 加密后的密码
 */
async function hashPassword(password) {
	const validation = validatePasswordStrength(password);
	if (!validation.valid) {
		throw ErrorFactory.passwordWeak(validation.message, { password: '***' });
	}

	const salt = crypto.getRandomValues(new Uint8Array(16));
	const encoder = new TextEncoder();
	const passwordBuffer = encoder.encode(password);

	const keyMaterial = await crypto.subtle.importKey('raw', passwordBuffer, { name: 'PBKDF2' }, false, ['deriveBits']);
	const hashBuffer = await crypto.subtle.deriveBits(
		{
			name: 'PBKDF2',
			salt: salt,
			iterations: PBKDF2_ITERATIONS,
			hash: 'SHA-256',
		},
		keyMaterial,
		256,
	);

	const saltB64 = btoa(String.fromCharCode(...salt));
	const hashB64 = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));

	return `${saltB64}$${hashB64}`;
}

/**
 * 验证密码
 */
async function verifyPassword(password, storedHash, env = null) {
	try {
		const [saltB64, hashB64] = storedHash.split('$');
		if (!saltB64 || !hashB64) {
			return false;
		}

		const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
		const encoder = new TextEncoder();
		const passwordBuffer = encoder.encode(password);

		const keyMaterial = await crypto.subtle.importKey('raw', passwordBuffer, { name: 'PBKDF2' }, false, ['deriveBits']);
		const hashBuffer = await crypto.subtle.deriveBits(
			{
				name: 'PBKDF2',
				salt: salt,
				iterations: PBKDF2_ITERATIONS,
				hash: 'SHA-256',
			},
			keyMaterial,
			256,
		);

		const calculatedHashB64 = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
		return calculatedHashB64 === hashB64;
	} catch (error) {
		if (env) {
			const logger = getLogger(env);
			logger.error('密码验证失败', { errorMessage: error.message }, error);
		}
		return false;
	}
}

/**
 * 生成 JWT Token
 */
async function generateJWT(payload, secret, expiryDays = JWT_EXPIRY_DAYS) {
	const header = {
		alg: JWT_ALGORITHM,
		typ: 'JWT',
	};

	const now = Math.floor(Date.now() / 1000);
	const jwtPayload = {
		...payload,
		iat: now,
		exp: now + expiryDays * 24 * 60 * 60,
	};

	const base64UrlEncode = (str) => {
		return btoa(String.fromCharCode(...new Uint8Array(typeof str === 'string' ? new TextEncoder().encode(str) : str)))
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=/g, '');
	};

	const headerB64 = base64UrlEncode(JSON.stringify(header));
	const payloadB64 = base64UrlEncode(JSON.stringify(jwtPayload));
	const data = `${headerB64}.${payloadB64}`;

	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

	const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));

	const signatureB64 = base64UrlEncode(signature);
	return `${data}.${signatureB64}`;
}

/**
 * 验证并解析 JWT Token
 */
async function verifyJWT(token, secret, env = null) {
	const logger = env ? getLogger(env) : null;

	try {
		const parts = token.split('.');
		if (parts.length !== 3) {
			return null;
		}

		const [headerB64, payloadB64, signatureB64] = parts;
		const data = `${headerB64}.${payloadB64}`;

		const base64UrlDecode = (str) => {
			str = str.replace(/-/g, '+').replace(/_/g, '/');
			const pad = str.length % 4;
			if (pad) {
				str += '='.repeat(4 - pad);
			}
			const binary = atob(str);
			return new Uint8Array([...binary].map((c) => c.charCodeAt(0)));
		};

		const encoder = new TextEncoder();
		const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);

		const signatureBytes = base64UrlDecode(signatureB64);
		const isValid = await crypto.subtle.verify('HMAC', key, signatureBytes, encoder.encode(data));

		if (!isValid) {
			if (logger) logger.warn('JWT 签名验证失败');
			return null;
		}

		const payloadBytes = base64UrlDecode(payloadB64);
		const payloadJson = new TextDecoder().decode(payloadBytes);
		const payload = JSON.parse(payloadJson);

		const now = Math.floor(Date.now() / 1000);
		if (payload.exp && payload.exp < now) {
			if (logger) logger.warn('JWT 已过期');
			return null;
		}

		return payload;
	} catch (error) {
		if (logger) logger.error('JWT 验证失败', { errorMessage: error.message }, error);
		return null;
	}
}

/**
 * 创建 Set-Cookie header 值
 */
function createSetCookieHeader(token, maxAge = COOKIE_MAX_AGE) {
	const cookieAttributes = [
		`${COOKIE_NAME}=${token}`,
		`Max-Age=${maxAge}`,
		'Path=/',
		'HttpOnly',
		'SameSite=Strict',
		'Secure',
	];

	return cookieAttributes.join('; ');
}

/**
 * 从请求中获取 Cookie 中的 token
 */
function getTokenFromCookie(request) {
	const cookieHeader = request.headers.get('Cookie');
	if (!cookieHeader) {
		return null;
	}

	const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
		const [name, value] = cookie.trim().split('=');
		acc[name] = value;
		return acc;
	}, {});

	return cookies[COOKIE_NAME] || null;
}

export async function verifyAuth(request, env) {
	const logger = getLogger(env);

	if (env.SECRETS_KV) {
		const storedPasswordHash = await env.SECRETS_KV.get(KV_USER_PASSWORD_KEY);

		if (!storedPasswordHash) {
			logger.info('未设置用户密码，需要首次设置');
			return false;
		}

		let token = getTokenFromCookie(request);
		if (!token) {
			const authHeader = request.headers.get('Authorization');
			if (authHeader) {
				token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : authHeader;
			}
		}

		if (!token) return false;

		if (token.includes('.')) {
			const payload = await verifyJWT(token, storedPasswordHash, env);
			if (payload) return true;
		}

		return false;
	}

	logger.error('未配置 KV 存储，拒绝访问');
	return false;
}

export async function verifyAuthWithDetails(request, env) {
	const logger = getLogger(env);

	if (!env.SECRETS_KV) {
		logger.error('未配置 KV 存储，拒绝访问');
		return null;
	}

	const storedPasswordHash = await env.SECRETS_KV.get(KV_USER_PASSWORD_KEY);

	if (!storedPasswordHash) {
		return null;
	}

	let token = getTokenFromCookie(request);
	if (!token) {
		const authHeader = request.headers.get('Authorization');
		if (authHeader) {
			token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : authHeader;
		}
	}

	if (!token) return null;

	if (token.includes('.')) {
		const payload = await verifyJWT(token, storedPasswordHash, env);
		if (payload && payload.exp) {
			const now = Math.floor(Date.now() / 1000);
			const remainingSeconds = payload.exp - now;
			const remainingDays = remainingSeconds / (24 * 60 * 60);
			const needsRefresh = remainingDays < JWT_AUTO_REFRESH_THRESHOLD_DAYS;

			return {
				valid: true,
				payload,
				remainingDays,
				needsRefresh,
				token,
			};
		}
	}

	return null;
}

export function createUnauthorizedResponse(message = '未授权访问', request = null) {
	return createErrorResponse('身份验证失败', message || '请提供有效的访问令牌。', 401, request);
}

export async function checkIfSetupRequired(env) {
	if (env.SECRETS_KV) {
		const storedPasswordHash = await env.SECRETS_KV.get(KV_USER_PASSWORD_KEY);
		return !storedPasswordHash;
	}
	return true;
}

export async function handleFirstTimeSetup(request, env) {
	const logger = getLogger(env);

	try {
		const clientIP = getClientIdentifier(request, 'ip');
		const rateLimitInfo = await checkRateLimit(clientIP, env, RATE_LIMIT_PRESETS.login);

		if (!rateLimitInfo.allowed) {
			return createRateLimitResponse(rateLimitInfo, request);
		}

		const { password, confirmPassword } = await request.json();

		if (!password || !confirmPassword) {
			throw new ValidationError('请提供密码和确认密码', { missing: !password ? 'password' : 'confirmPassword' });
		}

		if (password !== confirmPassword) {
			throw new ValidationError('两次输入的密码不一致', { issue: 'password_mismatch' });
		}

		const existingHash = await env.SECRETS_KV.get(KV_USER_PASSWORD_KEY);
		if (existingHash) {
			throw new ConflictError('密码已设置，无法重复设置。', { operation: 'first_time_setup' });
		}

		const validation = validatePasswordStrength(password);
		if (!validation.valid) {
			throw ErrorFactory.passwordWeak(validation.message, { operation: 'first_time_setup' });
		}

		const passwordHash = await hashPassword(password);

		await env.SECRETS_KV.put(KV_USER_PASSWORD_KEY, passwordHash);
		await env.SECRETS_KV.put(KV_SETUP_COMPLETED_KEY, new Date().toISOString());

		const jwtToken = await generateJWT({ auth: true, setupAt: new Date().toISOString() }, passwordHash, JWT_EXPIRY_DAYS);
		const expiryDate = new Date(Date.now() + JWT_EXPIRY_DAYS * 24 * 60 * 60 * 1000);
		const securityHeaders = getSecurityHeaders(request);

		return new Response(
			JSON.stringify({
				success: true,
				message: '密码设置成功，已自动登录',
				expiresAt: expiryDate.toISOString(),
				expiresIn: `${JWT_EXPIRY_DAYS}天`,
			}),
			{
				status: 200,
				headers: {
					...securityHeaders,
					'Content-Type': 'application/json',
					'Set-Cookie': createSetCookieHeader(jwtToken),
					'X-RateLimit-Limit': rateLimitInfo.limit.toString(),
					'X-RateLimit-Remaining': rateLimitInfo.remaining.toString(),
					'X-RateLimit-Reset': rateLimitInfo.resetAt.toString(),
				},
			},
		);
	} catch (error) {
		if (error instanceof ValidationError || error instanceof ConflictError || error instanceof AuthenticationError) {
			logError(error, logger, { operation: 'first_time_setup' });
			return errorToResponse(error, request);
		}
		logger.error('首次设置失败', { errorMessage: error.message }, error);
		return createErrorResponse('设置失败', '处理设置请求时发生错误', 500, request);
	}
}

/**
 * 验证登录请求并返回 JWT（增加 2FA 检查）
 */
export async function handleLogin(request, env) {
	const logger = getLogger(env);

	try {
		const clientIP = getClientIdentifier(request, 'ip');
		const rateLimitInfo = await checkRateLimit(clientIP, env, RATE_LIMIT_PRESETS.login);

		if (!rateLimitInfo.allowed) {
			return createRateLimitResponse(rateLimitInfo, request);
		}

		const { credential, token } = await request.json();

		if (!credential) {
			throw new ValidationError('请提供密码', { missing: 'credential' });
		}

		if (!env.SECRETS_KV) {
			throw new ConfigurationError('服务器未配置 KV 存储，请联系管理员', { missingConfig: 'SECRETS_KV' });
		}

		const storedPasswordHash = await env.SECRETS_KV.get(KV_USER_PASSWORD_KEY);

		if (!storedPasswordHash) {
			throw new AuthorizationError('请先完成首次设置', { operation: 'login', setupRequired: true });
		}

		const isValid = await verifyPassword(credential, storedPasswordHash, env);

		if (!isValid) {
			throw ErrorFactory.passwordIncorrect({ operation: 'login' });
		}

		// 检查 2FA 是否开启
		const is2faEnabled = await env.SECRETS_KV.get(KV_ADMIN_2FA_ENABLED) === 'true';
		const securityHeaders = getSecurityHeaders(request);

		if (is2faEnabled) {
			if (!token) {
				// 未提供 2FA 验证码，返回要求输入
				return new Response(
					JSON.stringify({
						success: false,
						requires2FA: true,
						message: '已开启安全验证，请输入 2FA 验证码',
					}),
					{
						status: 401,
						headers: {
							...securityHeaders,
							'Content-Type': 'application/json',
						},
					},
				);
			}

			const adminSecret = await env.SECRETS_KV.get(KV_ADMIN_2FA_SECRET);
			if (!adminSecret) {
				throw new ConfigurationError('系统 2FA 配置异常，请联系管理员', { missingConfig: 'adminSecret' });
			}

			// 验证 2FA Token，允许前后一个时间窗口的容差
			const currentTime = Math.floor(Date.now() / 1000);
			let isValid2FA = false;
			for (let i = -1; i <= 1; i++) {
				const expectedOtp = await generateOTP(adminSecret, currentTime + (i * 30));
				if (expectedOtp === token) {
					isValid2FA = true;
					break;
				}
			}

			if (!isValid2FA) {
				return new Response(
					JSON.stringify({
						success: false,
						requires2FA: true,
						message: '2FA 验证码错误',
					}),
					{
						status: 401,
						headers: {
							...securityHeaders,
							'Content-Type': 'application/json',
						},
					},
				);
			}
		}

		const jwtToken = await generateJWT(
			{ auth: true, loginAt: new Date().toISOString() },
			storedPasswordHash,
			JWT_EXPIRY_DAYS,
		);

		const expiryDate = new Date(Date.now() + JWT_EXPIRY_DAYS * 24 * 60 * 60 * 1000);

		return new Response(
			JSON.stringify({
				success: true,
				message: '登录成功',
				token: jwtToken,
				expiresAt: expiryDate.toISOString(),
				expiresIn: `${JWT_EXPIRY_DAYS}天`,
			}),
			{
				status: 200,
				headers: {
					...securityHeaders,
					'Content-Type': 'application/json',
					'Set-Cookie': createSetCookieHeader(jwtToken),
					'X-RateLimit-Limit': rateLimitInfo.limit.toString(),
					'X-RateLimit-Remaining': rateLimitInfo.remaining.toString(),
					'X-RateLimit-Reset': rateLimitInfo.resetAt.toString(),
				},
			},
		);
	} catch (error) {
		if (
			error instanceof ValidationError ||
			error instanceof AuthenticationError ||
			error instanceof AuthorizationError ||
			error instanceof ConfigurationError
		) {
			logError(error, logger, { operation: 'login' });
			return errorToResponse(error, request);
		}
		logger.error('登录处理失败', { errorMessage: error.message }, error);
		return createErrorResponse('登录失败', '处理登录请求时发生错误', 500, request);
	}
}

export async function handleRefreshToken(request, env) {
	const logger = getLogger(env);

	try {
		let token = getTokenFromCookie(request);

		if (!token) {
			const authHeader = request.headers.get('Authorization');
			if (!authHeader) {
				throw ErrorFactory.jwtMissing({ operation: 'refresh_token' });
			}
			token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : authHeader;
		}

		if (!env.SECRETS_KV) {
			throw new ConfigurationError('服务器未配置 KV 存储', { missingConfig: 'SECRETS_KV' });
		}

		const storedPasswordHash = await env.SECRETS_KV.get(KV_USER_PASSWORD_KEY);
		if (!storedPasswordHash) {
			throw new AuthorizationError('请先完成首次设置', { operation: 'refresh_token', setupRequired: true });
		}

		const payload = await verifyJWT(token, storedPasswordHash, env);
		if (!payload) {
			throw ErrorFactory.jwtInvalid({ operation: 'refresh_token' });
		}

		const newToken = await generateJWT(
			{ auth: true, loginAt: payload.loginAt || new Date().toISOString(), refreshedAt: new Date().toISOString() },
			storedPasswordHash,
			JWT_EXPIRY_DAYS,
		);

		const expiryDate = new Date(Date.now() + JWT_EXPIRY_DAYS * 24 * 60 * 60 * 1000);
		const securityHeaders = getSecurityHeaders(request);

		return new Response(
			JSON.stringify({
				success: true,
				message: '令牌刷新成功',
				token: newToken,
				expiresAt: expiryDate.toISOString(),
				expiresIn: `${JWT_EXPIRY_DAYS}天`,
			}),
			{
				status: 200,
				headers: {
					...securityHeaders,
					'Content-Type': 'application/json',
					'Set-Cookie': createSetCookieHeader(newToken),
				},
			},
		);
	} catch (error) {
		if (
			error instanceof ValidationError ||
			error instanceof AuthenticationError ||
			error instanceof AuthorizationError ||
			error instanceof ConfigurationError
		) {
			logError(error, logger, { operation: 'refresh_token' });
			return errorToResponse(error, request);
		}
		logger.error('刷新令牌失败', { errorMessage: error.message }, error);
		return createErrorResponse('刷新失败', '刷新令牌时发生错误', 500, request);
	}
}

export function requiresAuth(pathname) {
	const publicPaths = [
		'/',
		'/api/login',
		'/api/refresh-token',
		'/api/setup',
		'/setup',
		'/manifest.json',
		'/sw.js',
		'/icon-192.png',
		'/icon-512.png',
		'/favicon.ico',
		'/otp',
	];

	if (publicPaths.includes(pathname)) return false;
	if (pathname.startsWith('/otp/')) return false;
	if (pathname.startsWith('/api/favicon/')) return false;
	return true;
}

// ================= 管理员 2FA 管理 API =================

export async function handleGet2FAStatus(request, env) {
	const isEnabled = await env.SECRETS_KV.get(KV_ADMIN_2FA_ENABLED) === 'true';
	return new Response(JSON.stringify({ success: true, enabled: isEnabled }), {
		status: 200,
		headers: { 'Content-Type': 'application/json' },
	});
}

export async function handleSetup2FA(request, env) {
	// 生成随机 Base32 Secret
	const buffer = crypto.getRandomValues(new Uint8Array(20));
	const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	let secret = '';
	for (let i = 0; i < buffer.length; i++) {
		secret += base32chars[buffer[i] % 32];
	}

	const uri = generateOTPAuthURL('My2FA Admin', 'Admin', secret);
	
	// 保存临时 secret，有效期 10 分钟
	await env.SECRETS_KV.put('temp_admin_2fa_secret', secret, { expirationTtl: 600 });

	return new Response(JSON.stringify({ success: true, secret, uri }), {
		status: 200,
		headers: { 'Content-Type': 'application/json' },
	});
}

export async function handleVerifyAndEnable2FA(request, env) {
	const { token } = await request.json();
	const secret = await env.SECRETS_KV.get('temp_admin_2fa_secret');
	
	if (!secret) return createErrorResponse('配置超时', '验证超时，请重新获取二维码', 400, request);

	const currentTime = Math.floor(Date.now() / 1000);
	let isValid = false;
	for (let i = -1; i <= 1; i++) {
		const expectedOtp = await generateOTP(secret, currentTime + (i * 30));
		if (expectedOtp === token) {
			isValid = true;
			break;
		}
	}

	if (isValid) {
		await env.SECRETS_KV.put(KV_ADMIN_2FA_SECRET, secret);
		await env.SECRETS_KV.put(KV_ADMIN_2FA_ENABLED, 'true');
		await env.SECRETS_KV.delete('temp_admin_2fa_secret');
		return new Response(JSON.stringify({ success: true, message: '2FA 已成功开启' }), {
			status: 200,
			headers: { 'Content-Type': 'application/json' },
		});
	}
	
	return createErrorResponse('验证失败', '验证码错误', 400, request);
}

export async function handleDisable2FA(request, env) {
	const { password } = await request.json();
	
	const storedPasswordHash = await env.SECRETS_KV.get(KV_USER_PASSWORD_KEY);
	const isValid = await verifyPassword(password, storedPasswordHash, env);
	
	if (!isValid) {
		return createErrorResponse('验证失败', '管理员密码错误', 401, request);
	}
	
	await env.SECRETS_KV.put(KV_ADMIN_2FA_ENABLED, 'false');
	await env.SECRETS_KV.delete(KV_ADMIN_2FA_SECRET);
	
	return new Response(JSON.stringify({ success: true, message: '2FA 已成功关闭' }), {
		status: 200,
		headers: { 'Content-Type': 'application/json' },
	});
}
