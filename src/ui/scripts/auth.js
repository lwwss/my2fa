/**
 * 认证模块
 * 包含认证相关函数
 */

/**
 * 获取认证相关代码
 * @returns {string} 认证 JavaScript 代码
 */
export function getAuthCode() {
	return `    // ========== 认证相关函数 ==========
    
    function getAuthToken() { return null; }
    function saveAuthToken(token, expiresAt = null) {}
    function clearAuthToken() {}
    function isTokenExpiringSoon() { return false; }
    function isTokenExpired() { return false; }
    function startTokenExpiryCheck() {}

    async function refreshAuthToken() {
      try {
        console.log('🔄 正在刷新 Token...');
        const response = await fetch('/api/refresh-token', {
          method: 'POST',
          credentials: 'include'
        });

        if (response.ok) {
          const data = await response.json();
          if (data.success) {
            console.log('✅ Token 刷新成功');
            return true;
          }
        }
        console.warn('⚠️ Token 刷新失败');
        return false;
      } catch (error) {
        console.error('Token 刷新错误:', error);
        return false;
      }
    }

    function showLoginModal() {
      const modal = document.getElementById('loginModal');
      const tokenInput = document.getElementById('loginToken');
      const errorDiv = document.getElementById('loginError');
      const otpInput = document.getElementById('loginOtp');

      if (!modal) return;

      modal.style.display = 'flex';
      modal.style.visibility = 'visible';
      modal.style.opacity = '1';
      modal.style.position = 'fixed';
      modal.style.top = '0';
      modal.style.left = '0';
      modal.style.width = '100vw';
      modal.style.height = '100vh';
      modal.style.zIndex = '999999';
      modal.style.background = 'rgba(0, 0, 0, 0.9)';
      modal.style.alignItems = 'center';
      modal.style.justifyContent = 'center';

      const modalContent = modal.querySelector('.modal-content');
      if (modalContent) {
        modalContent.style.opacity = '1';
        modalContent.style.transform = 'scale(1)';
        modalContent.style.visibility = 'visible';
      }

      errorDiv.style.display = 'none';
      tokenInput.value = '';
      
      // 隐藏 2FA 输入框
      if (otpInput) {
          otpInput.style.display = 'none';
          otpInput.value = '';
      }

      setTimeout(() => tokenInput.focus(), 100);

      tokenInput.onkeypress = function(e) {
        if (e.key === 'Enter') handleLoginSubmit();
      };
    }

    function hideLoginModal() {
      document.getElementById('loginModal').style.display = 'none';
    }

    async function handleLoginSubmit() {
      const tokenInput = document.getElementById('loginToken');
      const errorDiv = document.getElementById('loginError');
      const otpInput = document.getElementById('loginOtp');
      
      const credential = tokenInput.value.trim();
      const token = otpInput && otpInput.style.display !== 'none' ? otpInput.value.trim() : null;

      if (!credential) {
        errorDiv.textContent = '请输入密码';
        errorDiv.style.display = 'block';
        return;
      }

      if (otpInput && otpInput.style.display !== 'none' && !token) {
        errorDiv.textContent = '请输入 2FA 验证码';
        errorDiv.style.display = 'block';
        return;
      }

      try {
        const response = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ credential, token })
        });

        const data = await response.json();

        // 处理需要 2FA 验证的状态
        if (response.status === 401 && data.requires2FA) {
            errorDiv.textContent = data.message || '已开启安全验证，需要输入 2FA 验证码';
            errorDiv.style.display = 'block';
            errorDiv.style.color = '#ff9800'; // 提示色
            
            // 动态创建并显示 2FA 输入框
            if (otpInput) {
                otpInput.style.display = 'block';
                otpInput.focus();
            } else {
                const newOtpInput = document.createElement('input');
                newOtpInput.type = 'text';
                newOtpInput.id = 'loginOtp';
                newOtpInput.className = tokenInput.className;
                newOtpInput.placeholder = '输入 6 位 2FA 验证码';
                newOtpInput.style.marginTop = '10px';
                newOtpInput.onkeypress = function(e) {
                  if (e.key === 'Enter') handleLoginSubmit();
                };
                tokenInput.parentNode.insertBefore(newOtpInput, tokenInput.nextSibling);
                newOtpInput.focus();
            }
            return;
        }

        if (response.ok && data.success) {
          hideLoginModal();
          if (data.expiresIn) {
            showCenterToast('✅', '登录成功，有效期 ' + data.expiresIn);
          } else {
            showCenterToast('✅', '登录成功');
          }
          loadSecrets();
        } else {
          errorDiv.textContent = data.message || '密码或验证码错误，请重试';
          errorDiv.style.display = 'block';
          errorDiv.style.color = ''; // 恢复错误色
          
          if (otpInput && otpInput.style.display !== 'none') {
              otpInput.value = '';
              otpInput.focus();
          } else {
              tokenInput.value = '';
              tokenInput.focus();
          }
        }
      } catch (error) {
        console.error('登录失败:', error);
        errorDiv.textContent = '登录失败：' + error.message;
        errorDiv.style.display = 'block';
      }
    }

    function checkAuth() { return true; }

    function handleUnauthorized() {
      clearAuthToken();
      try {
        localStorage.removeItem('2fa-secrets-cache');
      } catch (e) {}

      showCenterToast('⚠️', '登录已过期，请重新登录');
      setTimeout(() => { showLoginModal(); }, 1500);
    }

    async function authenticatedFetch(url, options = {}) {
      options.credentials = 'include';
      const response = await fetch(url, options);
      
      if (response.headers.get('X-Token-Refresh-Needed') === 'true') {
        const remainingDays = response.headers.get('X-Token-Remaining-Days');
        console.log('⏰ Token 即将过期（剩余 ' + remainingDays + ' 天），正在自动刷新...');
        
        refreshAuthToken().then(success => {
          if (success) console.log('✅ Token 自动续期成功');
        }).catch(error => console.error('❌ Token 自动续期错误:', error));
      }
      return response;
    }
    
    // ========== 2FA 全局管理接口（供前端界面调试调用） ==========
    window.Admin2FA = {
        async getStatus() {
            const res = await fetch('/api/admin/2fa/status', { credentials: 'include' });
            return await res.json();
        },
        async setup() {
            const res = await fetch('/api/admin/2fa/setup', { method: 'POST', credentials: 'include' });
            return await res.json(); // 返回 { success, secret, uri }
        },
        async verifyAndEnable(token) {
            const res = await fetch('/api/admin/2fa/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ token })
            });
            return await res.json();
        },
        async disable(password) {
            const res = await fetch('/api/admin/2fa/disable', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ password })
            });
            return await res.json();
        }
    };
`;
}
