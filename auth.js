// 全局變數
let currentUser = null;
let pendingUser = null; // 等待驗證的用戶
let authToken = null;
// 動作鎖（避免重複觸發/誤觸）
let isLoggingIn = false;
let isRegistering = false;
let isVerifying = false;
let isResending = false;

// API 配置
const API_BASE_URL = '/api';

// 頁面載入時初始化
document.addEventListener('DOMContentLoaded', function() {
    initializeAuth();
    setupFormHandlers();
    // 若 OAuth 回跳夾帶 token，寫入後清除 URL
    const url = new URL(window.location.href);
    const t = url.searchParams.get('token');
    if (t) {
        try {
            localStorage.setItem('authToken', t);
            url.searchParams.delete('token');
            window.history.replaceState({}, document.title, url.pathname + url.search);
            // 拉取個人資料並更新 UI
            (async ()=>{
                authToken = t;
                const resp = await fetch(`${API_BASE_URL}/user`, { headers: { Authorization: `Bearer ${authToken}` } });
                if (resp.ok) {
                    const data = await resp.json();
                    currentUser = data.user || {};
                    if (currentUser.handle) currentUser.handle = String(currentUser.handle).toLowerCase();
                    updateUIForLoggedInUser();
                    showAlert(`歡迎回來，${currentUser.username}！`, 'success');
                    // 若為 OAuth 首登且尚未設定 handle，彈出補資料
                    if (!currentUser.handle) {
                        openOAuthCompleteModal();
                    }
                }
            })();
        } catch (_) {}
    }
    // 捲動顯示動畫
    const io = new IntersectionObserver(entries => {
        entries.forEach(e => {
            if (e.isIntersecting) {
                e.target.classList.add('in');
                io.unobserve(e.target);
            }
        });
    }, { threshold: 0.15 });
    document.querySelectorAll('.reveal').forEach(el => io.observe(el));

    // 若在 /chat 頁面（含 hash #/chat），動態掛載 chat 介面
    if (location.pathname.replace(/\/$/, '') === '/chat' || location.hash === '#/chat') {
        (async ()=>{ await ensureCurrentUser(); mountChatUI(); })();
    }

    // 更強視差：根據 data-speed 微動（僅首屏元素）
    const parallaxEls = document.querySelectorAll('.parallax');
    window.addEventListener('scroll', () => {
        const y = window.scrollY || 0;
        parallaxEls.forEach(el => {
            const speed = parseFloat(el.getAttribute('data-speed') || '0.3');
            // 只在視窗內且首屏時才明顯偏移
            const translate = `translate3d(0, ${y * speed * 0.25}px, 0)`;
            el.style.transform = `translateZ(0) ${translate}`;
        });
    }, { passive: true });

    // 若已登入且沒有 handle（OAuth 首登），在初始化後也檢查一次以避免競態
    setTimeout(()=>{
        if (currentUser && !currentUser.handle) {
            openOAuthCompleteModal();
        }
    }, 400);
});

// 初始化認證狀態
async function initializeAuth() {
    // 檢查是否有保存的登入令牌
    authToken = localStorage.getItem('authToken');
    if (authToken) {
        try {
            // 驗證令牌並獲取用戶資訊
            const response = await fetch(`${API_BASE_URL}/user`, {
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const data = await response.json();
                currentUser = data.user || {};
                if (currentUser.handle) currentUser.handle = String(currentUser.handle).toLowerCase();
                updateUIForLoggedInUser();
            } else {
                // 令牌無效，清除本地存儲
                localStorage.removeItem('authToken');
                authToken = null;
            }
        } catch (error) {
            console.error('驗證令牌失敗:', error);
            localStorage.removeItem('authToken');
            authToken = null;
        }
    }
}

// 確保 currentUser 已載入（避免 /chat 初始化競態）
async function ensureCurrentUser(){
    if (currentUser && currentUser.id) return true;
    const t = localStorage.getItem('authToken');
    if (!t) return false;
    try{
        authToken = t;
        const resp = await fetch(`${API_BASE_URL}/user`, { headers:{ Authorization:`Bearer ${authToken}` } });
        if (resp.ok){
            const data = await resp.json();
            currentUser = data.user || {};
            if (currentUser.handle) currentUser.handle = String(currentUser.handle).toLowerCase();
            return true;
        }
    }catch(_){ }
    return false;
}

// 設置表單處理器
function setupFormHandlers() {
    // 登入表單
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    
    // 註冊表單
    document.getElementById('registerForm').addEventListener('submit', handleRegister);

    // 登入/註冊/登出 按鈕
    const loginBtn = document.getElementById('loginBtn');
    if (loginBtn) loginBtn.addEventListener('click', showLogin);

    const registerBtn = document.getElementById('registerBtn');
    if (registerBtn) registerBtn.addEventListener('click', showRegister);

    const googleOAuthLink = document.getElementById('googleOAuthLink');
    if (googleOAuthLink) googleOAuthLink.addEventListener('click', (e)=>{ e.preventDefault(); startGoogleOAuth(); });
    const discordOAuthLink = document.getElementById('discordOAuthLink');
    if (discordOAuthLink) discordOAuthLink.addEventListener('click', (e)=>{ e.preventDefault(); startDiscordOAuth(); });

    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) logoutBtn.addEventListener('click', logout);

    // 首頁 CTA：若未登入則打開登入；若未完成 ID 設定則提示並打開完成設定視窗
    const chatBtn = document.getElementById('chatCtaButton');
    if (chatBtn) {
        chatBtn.addEventListener('click', (e)=>{
            if (!currentUser) {
                e.preventDefault();
                showLogin();
                return;
            }
            if (!currentUser.handle) {
                e.preventDefault();
                showAlert('尚未設定 ID，請點擊右上角頭像或完成設定視窗來設定');
                openOAuthCompleteModal();
            }
        });
    }

    // 註冊：檢查自訂 ID 可用性
    const checkHandleBtn = document.getElementById('checkHandleBtn');
    if (checkHandleBtn) {
        checkHandleBtn.addEventListener('click', async () => {
            const input = document.getElementById('registerHandle');
            const hint = document.getElementById('handleHint');
            const val = (input.value || '').trim().toLowerCase();
            if (!val || !/^[a-z0-9_-]+$/.test(val)) {
                hint.textContent = '格式錯誤：只能英文小寫、數字、-、_';
                hint.style.color = '#ef4444';
                return;
            }
            try {
                const resp = await fetch(`${API_BASE_URL}/handle-available?handle=${encodeURIComponent(val)}`);
                const d = await resp.json();
                if (d.available) {
                    hint.textContent = '可使用';
                    hint.style.color = '#10b981';
                } else {
                    hint.textContent = d.reason === 'INVALID' ? '格式無效' : '已被使用';
                    hint.style.color = '#ef4444';
                }
            } catch (_) {
                hint.textContent = '檢查失敗，稍後再試';
                hint.style.color = '#ef4444';
            }
        });
    }

    // OAuth 補資料：檢查 handle 可用性
    const oauthCheckBtn = document.getElementById('oauthCheckHandleBtn');
    if (oauthCheckBtn) {
        oauthCheckBtn.addEventListener('click', async () => {
            const input = document.getElementById('oauthHandle');
            const hint = document.getElementById('oauthHandleHint');
            const val = (input.value || '').trim().toLowerCase();
            if (!val || !/^[a-z0-9_-]+$/.test(val)) {
                hint.textContent = '格式錯誤：只能英文小寫、數字、-、_';
                hint.style.color = '#ef4444';
                return;
            }
            try {
                const resp = await fetch(`${API_BASE_URL}/handle-available?handle=${encodeURIComponent(val)}`);
                const d = await resp.json();
                if (d.available) {
                    hint.textContent = '可使用';
                    hint.style.color = '#10b981';
                } else {
                    hint.textContent = d.reason === 'INVALID' ? '格式無效' : '已被使用';
                    hint.style.color = '#ef4444';
                }
            } catch (_) {
                hint.textContent = '檢查失敗，稍後再試';
                hint.style.color = '#ef4444';
            }
        });
    }

    // OAuth 補資料：頭像預覽
    const oauthAvatarInput = document.getElementById('oauthAvatarInput');
    if (oauthAvatarInput) oauthAvatarInput.addEventListener('change', (e)=>{
        if (e.target.files && e.target.files[0]) {
            const reader = new FileReader();
            reader.onload = (ev)=>{ document.getElementById('oauthAvatarPreview').src = ev.target.result; };
            reader.readAsDataURL(e.target.files[0]);
        }
    });

    // OAuth 補資料：提交
    const oauthForm = document.getElementById('oauthCompleteForm');
    if (oauthForm) {
        oauthForm.addEventListener('submit', async (e)=>{
            e.preventDefault();
            const handle = (document.getElementById('oauthHandle').value || '').trim().toLowerCase();
            const username = document.getElementById('oauthUsername').value.trim();
            if (!handle || !/^[a-z0-9_-]+$/.test(handle)) { showAlert('ID 格式錯誤：只能英文小寫、數字、-、_'); return; }
            if (!username) { showAlert('暱稱不可為空'); return; }
            const avatar = document.getElementById('oauthAvatarPreview').src || '';
            try {
                const resp = await fetch(`${API_BASE_URL}/user/complete-oauth`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
                    body: JSON.stringify({ handle, username, avatar })
                });
                const d = await resp.json().catch(()=>({}));
                if (!resp.ok) {
                    if (d.error === 'HANDLE_TAKEN') { showAlert('此 ID 已被使用'); return; }
                    if (d.error === 'INVALID_HANDLE') { showAlert('ID 格式錯誤：只能英文小寫、數字、-、_'); return; }
                    throw new Error(d.message || '設定失敗');
                }
                currentUser = d.user || currentUser;
                if (currentUser.handle) currentUser.handle = String(currentUser.handle).toLowerCase();
                updateUIForLoggedInUser();
                closeModal('oauthCompleteModal');
                showAlert('已完成基本設定','success');
            } catch (err) {
                console.error('complete oauth error:', err);
                showAlert(err.message || '設定失敗');
            }
        });
    }

    // 關閉彈窗按鈕（右上角X）
    document.querySelectorAll('.close').forEach(closeEl => {
        closeEl.addEventListener('click', () => {
            const modalId = closeEl.getAttribute('data-modal-id');
            if (modalId) closeModal(modalId);
        });
    });

    // 複製使用者 ID
    const copyBtn = document.getElementById('copyUserIdBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', async ()=>{
            try {
                const idInput = document.getElementById('profileUserId');
                if (idInput && idInput.value) {
                    await navigator.clipboard.writeText(idInput.value);
                    showAlert('已複製 ID');
                }
            } catch (_) {
                showAlert('複製失敗，請手動選取');
            }
        });
    }

    // 切換登入/註冊連結
    const switchToRegisterLink = document.getElementById('switchToRegisterLink');
    if (switchToRegisterLink) switchToRegisterLink.addEventListener('click', (e) => { e.preventDefault(); switchToRegister(); });

    const switchToLoginLink = document.getElementById('switchToLoginLink');
    if (switchToLoginLink) switchToLoginLink.addEventListener('click', (e) => { e.preventDefault(); switchToLogin(); });

    // 頭像上傳預覽
    const avatarInput = document.getElementById('avatarInput');
    if (avatarInput) avatarInput.addEventListener('change', (e) => previewAvatar(e.target));

    // 驗證與重發
    const verifyBtn = document.getElementById('verifyBtn');
    if (verifyBtn) verifyBtn.addEventListener('click', verifyCode);

    const resendBtn = document.getElementById('resendBtn');
    if (resendBtn) resendBtn.addEventListener('click', (e) => { e.preventDefault(); resendCode(); });

    // 點擊彈窗外部關閉
    window.addEventListener('click', function(event) {
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            if (event.target === modal) {
                if (currentUser && !currentUser.handle && modal.id === 'oauthCompleteModal') {
                    // 阻止點外圍關閉
                    showAlert('請先完成基本設定（ID/暱稱/頭像）','error');
                } else {
                    closeModal(modal.id);
                }
            }
        });
    });
}
// 開始 Google 登入流程（彈出 Google OAuth 頁面取得 ID Token）
function startGoogleOAuth() {
    const envMeta = document.querySelector('meta[name="google-client-id"]');
    const clientId = window.GOOGLE_CLIENT_ID || (envMeta && envMeta.content) || '';
    const redirectUri = `${location.origin}/api/auth/google/callback`;
    if (!clientId) { showAlert('缺少 GOOGLE_CLIENT_ID'); return; }
    const scope = encodeURIComponent('openid email profile');
    const state = encodeURIComponent(Math.random().toString(36).slice(2));
    const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${scope}&include_granted_scopes=true&state=${state}&prompt=select_account`;
    window.location.href = url;
}

function startDiscordOAuth() {
    const clientId = (window.DISCORD_CLIENT_ID || '');
    const redirectUri = `${location.origin}/api/auth/discord/callback`;
    if (!clientId) { showAlert('缺少 DISCORD_CLIENT_ID'); return; }
    const scope = encodeURIComponent('identify email guilds.join');
    const state = encodeURIComponent(Math.random().toString(36).slice(2));
    const url = `https://discord.com/api/oauth2/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${scope}&prompt=consent`;
    window.location.href = url;
}

function loadScript(src) {
    return new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = src;
        s.async = true;
        s.onload = resolve;
        s.onerror = reject;
        document.head.appendChild(s);
    });
}

function getGoogleClientId() {
    // 從全域或 <meta name="google-client-id" content="..."> 讀取
    const meta = document.querySelector('meta[name="google-client-id"]');
    return window.GOOGLE_CLIENT_ID || (meta && meta.content) || '';
}

// 其餘 GIS One-Tap 相關已移除，改用 OAuth 授權碼流程

// 顯示登入彈窗
function showLogin() {
    // 若尚未完成 OAuth 基本設定，阻止顯示登入/註冊彈窗
    if (currentUser && !currentUser.handle) {
        openOAuthCompleteModal();
        showAlert('請先完成基本設定（ID/暱稱/頭像）','error');
        return;
    }
    closeAllModals();
    document.body.classList.add('modal-open');
    document.getElementById('loginModal').classList.add('show');
    document.getElementById('loginEmail').focus();
}

// 顯示註冊彈窗
function showRegister() {
    if (currentUser && !currentUser.handle) {
        openOAuthCompleteModal();
        showAlert('請先完成基本設定（ID/暱稱/頭像）','error');
        return;
    }
    closeAllModals();
    document.body.classList.add('modal-open');
    document.getElementById('registerModal').classList.add('show');
    document.getElementById('registerUsername').focus();
}

// 關閉彈窗
function closeModal(modalId) {
    // 若尚未完成基本設定，不允許關閉 oauthCompleteModal
    if (currentUser && !currentUser.handle && modalId === 'oauthCompleteModal') {
        showAlert('請先完成基本設定（ID/暱稱/頭像）','error');
        return;
    }
    document.getElementById(modalId).classList.remove('show');
    const anyOpen = Array.from(document.querySelectorAll('.modal')).some(m => m.classList.contains('show'));
    if (!anyOpen) document.body.classList.remove('modal-open');
}

// 關閉所有彈窗
function closeAllModals() {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        modal.classList.remove('show');
    });
    document.body.classList.remove('modal-open');
}

// 切換到註冊
function switchToRegister() {
    closeModal('loginModal');
    showRegister();
}

// 切換到登入
function switchToLogin() {
    closeModal('registerModal');
    showLogin();
}

// 頭像預覽
function previewAvatar(input) {
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
            document.getElementById('avatarPreview').src = e.target.result;
        };
        reader.readAsDataURL(input.files[0]);
    }
}

// 產生內嵌SVG頭像，避免外部請求
function generateAvatarDataUrl(initial) {
    const safe = (initial || 'U').toUpperCase().slice(0, 1);
    const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100'>
  <defs>
    <linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>
      <stop offset='0%' stop-color='#667eea'/>
      <stop offset='100%' stop-color='#764ba2'/>
    </linearGradient>
  </defs>
  <rect width='100' height='100' fill='url(#g)' rx='16'/>
  <text x='50' y='58' font-family='Arial, sans-serif' font-size='44' fill='white' text-anchor='middle' dominant-baseline='middle'>${safe}</text>
  <!-- padding tweak -->
  <rect width='100' height='100' fill='transparent'/>
  <text x='50' y='52' font-family='Arial, sans-serif' font-size='44' fill='white' text-anchor='middle'>${safe}</text>
</svg>`;
    return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

// 處理註冊
async function handleRegister(event) {
    event.preventDefault();
    if (isRegistering) return; // 節流
    
    const username = document.getElementById('registerUsername').value.trim();
    const email = document.getElementById('registerEmail').value.trim();
    const password = document.getElementById('registerPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const handleInput = document.getElementById('registerHandle');
    const customHandle = handleInput ? (handleInput.value || '').trim().toLowerCase() : '';
    const avatarFile = document.getElementById('avatarInput') ? document.getElementById('avatarInput').files[0] : null;
    
    // 表單驗證
    if (!validateRegisterForm(username, email, password, confirmPassword)) {
        return;
    }

    // 前端先驗證 handle 格式
    if (customHandle && !/^[a-z0-9_-]+$/.test(customHandle)) {
        showAlert('ID 格式錯誤：只能英文小寫、數字、-、_');
        return;
    }
    
    try {
        // 處理頭像
        let avatarDataUrl = generateAvatarDataUrl(username.charAt(0));
        if (avatarFile) {
            avatarDataUrl = await fileToBase64(avatarFile);
        }
        
        // 動作鎖與禁用註冊按鈕
        isRegistering = true;
        const submitBtn = document.querySelector('#registerForm button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.textContent = '註冊中...';

        // 發送註冊請求到後端
        const response = await fetch(`${API_BASE_URL}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                email,
                password,
                avatar: avatarDataUrl,
                handle: customHandle
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || '註冊失敗');
        }

        // 註冊成功，保存待驗證用戶資訊
        pendingUser = {
            username,
            email
        };

        // 若後端已回傳 user.handle（理論上只有成功建立才會有），亦同步暫存
        if (data && data.user && data.user.handle) {
            pendingUser.handle = String(data.user.handle).toLowerCase();
        }

        // 顯示驗證彈窗
        closeModal('registerModal');
        showVerificationModal(email);
        
        // 顯示成功訊息
        if (data.emailError) {
            showAlert('註冊成功！但驗證郵件發送失敗，請稍後重新發送', 'success');
        } else {
            showAlert('註冊成功！請檢查您的郵箱並輸入驗證碼', 'success');
        }

    } catch (error) {
        console.error('註冊錯誤:', error);
        showAlert(error.message || '註冊失敗，請稍後再試');
    } finally {
        // 恢復註冊按鈕與動作鎖
        const submitBtn = document.querySelector('#registerForm button[type="submit"]');
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = '註冊';
        }
        isRegistering = false;
    }
}

// 驗證註冊表單
function validateRegisterForm(username, email, password, confirmPassword) {
    if (!username || username.length < 2) {
        showAlert('使用者名稱至少需要2個字元');
        return false;
    }
    
    if (!isValidEmail(email)) {
        showAlert('請輸入有效的電子郵件地址');
        return false;
    }
    
    if (password.length < 6) {
        showAlert('密碼至少需要6個字元');
        return false;
    }
    
    if (password !== confirmPassword) {
        showAlert('密碼與確認密碼不符');
        return false;
    }
    
    return true;
}

// 註：email存在檢查現在由後端處理

// 驗證email格式
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// 文件轉base64
function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => resolve(reader.result);
        reader.onerror = error => reject(error);
    });
}

// 註：驗證碼發送現在由後端處理，會發送真實郵件

// 顯示驗證彈窗
function showVerificationModal(email) {
    document.getElementById('verificationEmail').textContent = email;
    document.getElementById('verificationModal').classList.add('show');
    document.getElementById('verificationCode').focus();
}

// 驗證驗證碼
async function verifyCode() {
    if (isVerifying) return; // 節流
    const inputCode = document.getElementById('verificationCode').value.trim();
    
    if (!inputCode) {
        showAlert('請輸入驗證碼');
        return;
    }
    
    if (!pendingUser || !pendingUser.email) {
        showAlert('驗證會話已過期，請重新註冊');
        closeModal('verificationModal');
        return;
    }
    
    try {
        // 動作鎖與禁用驗證按鈕
        isVerifying = true;
        const verifyBtn = document.querySelector('#verificationModal button');
        verifyBtn.disabled = true;
        verifyBtn.textContent = '驗證中...';

        // 發送驗證請求到後端
        const response = await fetch(`${API_BASE_URL}/verify-email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: pendingUser.email,
                code: inputCode
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || '驗證失敗');
        }

        // 驗證成功
        closeModal('verificationModal');
        showAlert('電子郵件驗證成功！請登入您的帳號', 'success');
        
        // 清理待驗證用戶資料
        const email = pendingUser.email;
        pendingUser = null;
        
        // 顯示登入彈窗並預填email
        setTimeout(() => {
            showLogin();
            document.getElementById('loginEmail').value = email;
        }, 1500);

    } catch (error) {
        console.error('驗證錯誤:', error);
        showAlert(error.message || '驗證失敗，請稍後再試');
    } finally {
        // 恢復驗證按鈕與動作鎖
        const verifyBtn = document.querySelector('#verificationModal button');
        verifyBtn.disabled = false;
        verifyBtn.textContent = '驗證';
        isVerifying = false;
    }
}

// 重新發送驗證碼
async function resendCode() {
    if (isResending) return; // 節流
    if (!pendingUser || !pendingUser.email) {
        showAlert('驗證會話已過期，請重新註冊');
        return;
    }

    try {
        // 動作鎖與禁用重發按鈕
        isResending = true;
        const resendBtn = document.getElementById('resendBtn') || document.querySelector('.btn-link');
        resendBtn.disabled = true;
        resendBtn.textContent = '發送中...';

        const response = await fetch(`${API_BASE_URL}/resend-verification`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: pendingUser.email
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || '重發驗證碼失敗');
        }

        showAlert('驗證碼已重新發送到您的郵箱', 'success');

    } catch (error) {
        console.error('重發驗證碼錯誤:', error);
        showAlert(error.message || '重發驗證碼失敗，請稍後再試');
    } finally {
        // 恢復重發按鈕與動作鎖
        const resendBtn = document.getElementById('resendBtn') || document.querySelector('.btn-link');
        resendBtn.disabled = false;
        resendBtn.textContent = '重新發送驗證碼';
        isResending = false;
    }
}

// 註：用戶數據現在由後端數據庫管理

// 處理登入
async function handleLogin(event) {
    event.preventDefault();
    if (isLoggingIn) return; // 節流，避免重複觸發
    
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    
    if (!email || !password) {
        showAlert('請填寫所有欄位');
        return;
    }
    
    try {
        // 設定動作鎖與禁用登入按鈕
        isLoggingIn = true;
        const submitBtn = document.querySelector('#loginForm button[type="submit"]');
        const originalText = submitBtn.textContent;
        submitBtn.disabled = true;
        submitBtn.textContent = '登入中...';

        // 發送登入請求到後端
        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email,
                password
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || '登入失敗');
        }

        // 登入成功
        authToken = data.token;
        currentUser = data.user || {};
        if (currentUser.handle) currentUser.handle = String(currentUser.handle).toLowerCase();
        
        // 保存令牌到本地存儲
        localStorage.setItem('authToken', authToken);
        
        closeModal('loginModal');
        updateUIForLoggedInUser();
        
        showAlert(`歡迎回來，${currentUser.username}！`, 'success');

    } catch (error) {
        console.error('登入錯誤:', error);
        showAlert(error.message || '登入失敗，請稍後再試');
    } finally {
        // 恢復登入按鈕與動作鎖
        const submitBtn = document.querySelector('#loginForm button[type="submit"]');
        submitBtn.disabled = false;
        submitBtn.textContent = '登入';
        isLoggingIn = false;
    }
}

// 更新UI為已登入狀態
function updateUIForLoggedInUser() {
    // 隱藏登入/註冊按鈕
    document.getElementById('authButtons').style.display = 'none';
    
    // 顯示用戶資訊
    const userInfo = document.getElementById('userInfo');
    const userAvatar = document.getElementById('userAvatar');
    const userName = document.getElementById('userName');
    
    userAvatar.src = currentUser.avatar;
    userName.textContent = currentUser.username;
    userInfo.style.display = 'flex';

    // 點擊頭像開啟編輯視窗
    userAvatar.onclick = openProfileModal;
    
    // 更新歡迎訊息與 CTA（不覆蓋整區，避免後續區塊被清空）
    const welcomeTitle = document.getElementById('welcomeTitle');
    if (welcomeTitle) welcomeTitle.textContent = `歡迎回來，${currentUser.username}！`;
    const welcomeSub = document.querySelector('.welcome-sub');
    if (welcomeSub) welcomeSub.textContent = '準備好開始聊天了嗎？';
}

// ============ Chat ============
let chatState = { currentPeer: null, friends: [], requests: [], lastMsgIdByPeer: {}, renderedIdSetByPeer: {}, autoScroll: true };
let isSendingMessage = false; // 防重入，避免重複送出

// 共用：送出目前輸入框的訊息（提供多處綁定呼叫）
async function sendCurrentChatMessage(){
    const input = document.getElementById('chatInput');
    const btn = document.getElementById('chatSendBtn');
    if (!input || !btn) return; // UI 尚未掛載
    const text = (input.value || '').trim();
    if (!chatState.currentPeer) { showAlert('請先在左側選擇好友'); return; }
    if (!text) return;
    if (isSendingMessage) return; // 防雙觸發（Enter + Click、或多重綁定）
    isSendingMessage = true;
    if (!authToken) {
        const t = localStorage.getItem('authToken');
        if (t) authToken = t;
    }
    if (!authToken) { showAlert('登入已過期，請重新登入'); showLogin(); return; }
    const prevDisabled = input.disabled;
    input.disabled = true; btn.disabled = true;
    try{
        const clientId = `${currentUser.id}-${chatState.currentPeer.id}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
        const resp = await fetch(`${API_BASE_URL}/messages`, {
            method:'POST',
            headers:{ 'Content-Type':'application/json', Authorization:`Bearer ${authToken}` },
            body: JSON.stringify({ toUserId: chatState.currentPeer.id, content: text, clientId })
        });
        if (resp.ok){
            input.value='';
            // 使用伺服器回傳 id，避免之後增量拉取重複顯示
            let r = null;
            try { r = await resp.json(); } catch(_) {}
            const serverId = r && r.id ? r.id : null;
            const createdAt = r && r.createdAt ? r.createdAt : Date.now();
            appendMessages([{ id: serverId, sender_id: currentUser.id, receiver_id: chatState.currentPeer.id, content: text, created_at: createdAt, seen_at: null }]);
        }
        else {
            let detail = '';
            try { detail = (await resp.json()).message || ''; } catch(_) { try { detail = await resp.text(); } catch(_) {} }
            if (resp.status === 401 || resp.status === 403) { showAlert('登入已過期或權限不足，請重新登入'); showLogin(); }
            else { showAlert(detail || '傳送失敗，請稍後再試'); }
        }
    }catch(_){ showAlert('網路異常，請稍後再試'); }
    finally{
        // 若已選擇會話則允許輸入
        if (chatState.currentPeer) input.disabled = false; else input.disabled = prevDisabled;
        btn.disabled = false;
        isSendingMessage = false;
    }
}

function mountChatUI() {
    const tpl = document.getElementById('chatTemplate');
    if (!tpl) return;
    // 隱藏首頁框架，保留彈窗節點
    const header = document.querySelector('.header');
    const main = document.querySelector('.main-content');
    if (header) header.style.display = 'none';
    if (main) main.style.display = 'none';
    // 挂載聊天根節點
    let root = document.getElementById('chatRoot');
    if (!root){
        root = document.createElement('div');
        root.id = 'chatRoot';
        document.body.appendChild(root);
    }
    root.innerHTML = '';
    root.appendChild(tpl.content.cloneNode(true));
    // 側邊軌道切換
    document.querySelectorAll('.rail-item').forEach(btn=>{
        btn.addEventListener('click', ()=>{
            document.querySelectorAll('.rail-item').forEach(i=>i.classList.remove('is-active'));
            btn.classList.add('is-active');
            const key = btn.getAttribute('data-rail');
            switchRail(key);
        });
    });
    // 導航欄底部：通知與頭像
    const railNotif = document.getElementById('railNotifBtn');
    const railAvatarImg = document.getElementById('railAvatarImg');
    if (railAvatarImg) {
        const init = (currentUser && currentUser.username ? currentUser.username[0] : 'U');
        railAvatarImg.src = (currentUser && currentUser.avatar) ? currentUser.avatar : generateAvatarDataUrl(init);
    }
    const railAvatarBtn = document.getElementById('railAvatarBtn');
    const railMenu = document.getElementById('railAvatarMenu');
    const openMenu = ()=>{ railMenu.style.display = 'block'; };
    const closeMenu = ()=>{ railMenu.style.display = 'none'; };
    if (railAvatarBtn) railAvatarBtn.addEventListener('click', (e)=>{
        e.stopPropagation();
        if (railMenu.style.display === 'block') closeMenu(); else openMenu();
    });
    document.getElementById('railMenuSettings').addEventListener('click', ()=>{
        closeMenu();
        if (!currentUser) { showLogin(); return; }
        if (!currentUser.handle) { openOAuthCompleteModal(); return; }
        openProfileModal();
    });
    document.getElementById('railMenuAddFriend').addEventListener('click', ()=>{
        closeMenu();
        if (!currentUser) { showLogin(); return; }
        if (!currentUser.handle) { openOAuthCompleteModal(); return; }
        document.getElementById('addFriendModal').classList.add('show');
        document.body.classList.add('modal-open');
    });
    document.addEventListener('click', (e)=>{
        if (!railMenu.contains(e.target) && e.target !== railAvatarBtn) closeMenu();
    });
    if (railNotif) railNotif.addEventListener('click', async ()=>{
        if (!currentUser) { showLogin(); return; }
        if (!currentUser.handle) { openOAuthCompleteModal(); return; }
        await refreshNotifications();
        document.getElementById('notificationsModal').classList.add('show');
        document.body.classList.add('modal-open');
    });
    // 移除舊 FAB 相關程式（改用 railMenu）
    const notifBtn = document.getElementById('railNotifBtn');
    if (notifBtn) notifBtn.addEventListener('click', async ()=>{
        if (!currentUser) { showLogin(); return; }
        if (!currentUser.handle) { openOAuthCompleteModal(); return; }
        await refreshNotifications();
        document.getElementById('notificationsModal').classList.add('show');
        document.body.classList.add('modal-open');
    });
    // 列表與訊息
    bindAddFriendForm();
    loadFriends();
    wireChatSend();
    // 自動捲動狀態：使用者若往上捲動，暫停自動置底
    const msgBox = document.getElementById('chatMessages');
    chatState.autoScroll = true;
    if (msgBox) {
        msgBox.addEventListener('scroll', ()=>{
            chatState.autoScroll = isNearBottom(msgBox, 48);
        });
    }
    // 週期刷新通知徽標（提高即時性）
    refreshNotifications();
    if (window._notifTimer) clearInterval(window._notifTimer);
    window._notifTimer = setInterval(refreshNotifications, 3000);
    // 若未登入或未完成設定，引導
    if (!currentUser) { showLogin(); }
    else if (!currentUser.handle) { openOAuthCompleteModal(); }
}

function bindAddFriendForm(){
    const form = document.getElementById('addFriendForm');
    if (!form) return;
    form.addEventListener('submit', async (e)=>{
        e.preventDefault();
        const handle = (document.getElementById('addFriendHandle').value||'').trim().toLowerCase();
        if (!handle || !/^[a-z0-9_-]+$/.test(handle)) { showAlert('ID 格式錯誤'); return; }
        try{
            const resp = await fetch(`${API_BASE_URL}/friends/request`, { method:'POST', headers:{ 'Content-Type':'application/json', Authorization:`Bearer ${authToken}` }, body: JSON.stringify({ handle }) });
            const d = await resp.json().catch(()=>({}));
            if (!resp.ok) {
                if (resp.status === 404) { showAlert('使用者不存在，請再次檢查 ID 是否正確'); return; }
                if (d.error === 'ALREADY_PENDING') { showAlert('已送出邀請，等待對方回覆'); return; }
                if (d.error === 'ALREADY_FRIENDS') { showAlert('你們已是好友'); return; }
                if (d.error === 'CANNOT_ADD_SELF') { showAlert('不能加自己為好友'); return; }
                throw new Error('發送失敗');
            }
            closeModal('addFriendModal');
            showAlert('已發送好友邀請','success');
        }catch(err){ showAlert(err.message||'發送失敗'); }
    });
}

async function refreshNotifications(){
    try{
        const resp = await fetch(`${API_BASE_URL}/friends/requests`, { headers:{ Authorization:`Bearer ${authToken}` } });
        const d = await resp.json();
        if (resp.ok){
            chatState.requests = d.requests||[];
            renderNotifications();
            const sticky = document.getElementById('railNotifBtn');
            if (sticky){ sticky.classList.toggle('is-active', chatState.requests.length>0); }
        }
    }catch(_){ }
}

function renderNotifications(){
    const body = document.getElementById('notificationsBody');
    body.innerHTML = '';
    if (!chatState.requests.length){ body.textContent = '沒有新通知'; return; }
    chatState.requests.forEach(r=>{
        const row = document.createElement('div');
        row.style.display='flex'; row.style.alignItems='center'; row.style.gap='8px'; row.style.marginBottom='10px';
        row.innerHTML = `<img src="${r.from.avatar||''}" style="width:36px;height:36px;border-radius:50%"/><div style="flex:1"><div style="font-weight:700">${r.from.username}</div><div style="color:#6b7280">@${r.from.handle}</div></div>`;
        const accept = document.createElement('button'); accept.className='btn btn-primary'; accept.textContent='接受';
        const reject = document.createElement('button'); reject.className='btn btn-secondary'; reject.textContent='拒絕';
        accept.onclick = ()=> respondRequest(r.id,'accept');
        reject.onclick = ()=> respondRequest(r.id,'reject');
        row.appendChild(accept); row.appendChild(reject);
        body.appendChild(row);
    });
}

async function respondRequest(requestId, action){
    try{
        const resp = await fetch(`${API_BASE_URL}/friends/respond`, { method:'POST', headers:{ 'Content-Type':'application/json', Authorization:`Bearer ${authToken}` }, body: JSON.stringify({ requestId, action }) });
        if (resp.ok){ showAlert(action==='accept'?'已接受':'已拒絕','success'); await refreshNotifications(); await loadFriends(); }
        else{ showAlert('操作失敗'); }
    }catch(_){ showAlert('操作失敗'); }
}

async function loadFriends(){
    try{
        const resp = await fetch(`${API_BASE_URL}/friends`, { headers:{ Authorization:`Bearer ${authToken}` } });
        const d = await resp.json();
        if (resp.ok){ chatState.friends = d.friends||[]; renderFriendList(); }
    }catch(_){ }
}

function renderFriendList(){
    const box = document.getElementById('sidebarContent');
    box.innerHTML = `
      <div class="sidebar-card">
        <div class="sidebar-title">好友</div>
        <div class="sidebar-list" id="friendList"></div>
      </div>
    `;
    const list = document.getElementById('friendList');
    (chatState.friends||[]).forEach(f=>{
        const item = document.createElement('div');
        item.className='item';
        item.innerHTML = `<img class="avatar" src="${f.avatar||''}"/><div class="name">${f.username}</div>`;
        item.onclick = ()=> openConversation(f);
        list.appendChild(item);
    });
}

function switchRail(key){
    const listBox = document.getElementById('sidebarContent');
    const title = document.getElementById('chatTitle');
    const messages = document.getElementById('chatMessages');
    if (key === 'all'){
        title.textContent = '請從左邊選擇一位好友來對話';
        messages.innerHTML = '';
        renderFriendList();
        return;
    }
    if (key === 'home'){
        title.textContent = '';
        messages.innerHTML = '';
        listBox.innerHTML = `
          <div class="sidebar-card">
            <div class="sidebar-title">主頁</div>
            <div class="sidebar-sub">按下左側第一個按鈕，選擇好友開始聊天，或在通知中接受好友邀請。</div>
          </div>
        `;
        return;
    }
    if (key === 'friends'){
        title.textContent = '好友';
        messages.innerHTML = '';
        renderFriendList();
        return;
    }
    if (key === 'groups'){
        title.textContent = '群組';
        messages.innerHTML = '';
        listBox.innerHTML = `
          <div class="sidebar-card">
            <div class="sidebar-title">群組</div>
            <div class="sidebar-sub">即將推出</div>
          </div>
        `;
        return;
    }
    if (key === 'settings'){
        title.textContent = '偏好設定';
        messages.innerHTML = '';
        // 清空側欄內容
        listBox.innerHTML = '';
        // 第六個（設定）：給你快速切換主題的示範
        const box = document.createElement('div');
        box.style.padding='1rem';
        box.innerHTML = `
          <div style="display:flex; gap:.5rem;">
            <button id="themeLight" class="btn btn-secondary">淡色</button>
            <button id="themeDark" class="btn btn-secondary">深色</button>
          </div>
        `;
        messages.appendChild(box);
        document.getElementById('themeLight').onclick = ()=> document.body.classList.remove('theme-dark');
        document.getElementById('themeDark').onclick = ()=> document.body.classList.add('theme-dark');
        return;
    }
}

function openConversation(peer){
    chatState.currentPeer = peer;
    document.getElementById('chatTitle').textContent = peer.username;
    document.getElementById('chatMessages').innerHTML = '';
    chatState.autoScroll = true;
    fetchMessages();
    // 啟動增量輪詢，低延遲抓新訊息
    startMessagePolling();
    // 允許輸入並聚焦
    const input = document.getElementById('chatInput');
    if (input) { input.disabled = false; input.placeholder = '輸入訊息...'; input.focus(); }
}

async function fetchMessages(){
    if (!chatState.currentPeer) return;
    try{
        const resp = await fetch(`${API_BASE_URL}/messages?with=${encodeURIComponent(chatState.currentPeer.id)}`, { headers:{ Authorization:`Bearer ${authToken}` } });
        let d = {};
        try { d = await resp.json(); } catch(_) {}
        if (resp.ok){ renderMessages(d.messages||[]); }
        else {
            if (resp.status === 400) { showAlert(d.message || '參數無效'); }
            else if (resp.status === 401 || resp.status === 403) { showAlert('登入已過期或權限不足，請重新登入'); showLogin(); }
            else { showAlert(d.message || '載入訊息失敗'); }
        }
    }catch(err){ showAlert('網路異常，請稍後再試'); }
}

function renderMessages(list){
    const box = document.getElementById('chatMessages');
    const shouldStick = isNearBottom(box, 64);
    box.innerHTML = '';
    let maxId = chatState.lastMsgIdByPeer[chatState.currentPeer.id] || 0;
    // 重置已渲染集合，避免後續 append 去重失效
    chatState.renderedIdSetByPeer[chatState.currentPeer.id] = new Set();
    list.forEach(m=>{
        const mine = m.sender_id === currentUser.id;
        const row = document.createElement('div');
        row.className = `msg ${mine?'me':'peer'}`;
        if (m.id != null) row.dataset.msgId = String(m.id);
        row.dataset.fromMe = mine ? 'true' : 'false';
        row.dataset.seen = m.seen_at ? 'true' : 'false';
        row.innerHTML = mine
            ? `<div class="bubble">${escapeHtml(m.content)}</div><div class="time">${formatTime(m.created_at)}</div>`
            : `<img src="${chatState.currentPeer.avatar||''}" class="avatar" style="width:28px;height:28px;border-radius:50%"/><div><div class="bubble">${escapeHtml(m.content)}</div><div class="time">${formatTime(m.created_at)}</div></div>`;
        box.appendChild(row);
        if (m.id && m.id > maxId) maxId = m.id;
        if (m.id) chatState.renderedIdSetByPeer[chatState.currentPeer.id].add(m.id);
    });
    chatState.lastMsgIdByPeer[chatState.currentPeer.id] = maxId;
    if (shouldStick || chatState.autoScroll) {
    box.scrollTop = box.scrollHeight;
    }
    // 標記對方訊息為已讀（節流：避免頻繁打）
    scheduleMarkRead();
    renderReadReceipt();
}

function wireChatSend(){
    const input = document.getElementById('chatInput');
    const btn = document.getElementById('chatSendBtn');
    if (btn) {
        btn.replaceWith(btn.cloneNode(true));
    }
    const freshBtn = document.getElementById('chatSendBtn');
    if (freshBtn) freshBtn.addEventListener('click', sendCurrentChatMessage, { once: false });

    if (input) {
        input.replaceWith(input.cloneNode(true));
    }
    const freshInput = document.getElementById('chatInput');
    if (freshInput) freshInput.addEventListener('keydown', e=>{ if (e.isComposing || e.keyCode===229) return; if (e.key==='Enter' && !e.shiftKey) { e.preventDefault(); sendCurrentChatMessage(); } }, { once: false });
    // 初始未選好友前禁用
    if (freshInput) { freshInput.disabled = true; freshInput.placeholder = '請先從左邊選擇好友'; }
}

// ===== 低延遲增量輪詢與已讀節流 =====
let pollTimer = null;
let pollCounter = 0;
let backoffMs = 700;
let backoffFailCount = 0;
function startMessagePolling(){
    stopMessagePolling();
    pollTimer = setInterval(async ()=>{
        try{
            if (!chatState.currentPeer) return;
            pollCounter = (pollCounter + 1) % 5;
            if (pollCounter === 0) {
                await fetchMessages(); // 週期性全量刷新，更新已讀狀態
            } else {
                const lastId = chatState.lastMsgIdByPeer[chatState.currentPeer.id] || 0;
                const url = lastId ? `${API_BASE_URL}/messages?with=${encodeURIComponent(chatState.currentPeer.id)}&after=${lastId}` : `${API_BASE_URL}/messages?with=${encodeURIComponent(chatState.currentPeer.id)}`;
                const resp = await fetch(url, { headers:{ Authorization:`Bearer ${authToken}` } });
                if (resp.status === 429) { handlePollBackoff(); return; }
                if (!resp.ok) return;
                const d = await resp.json();
                const list = d.messages||[];
                if (list.length) appendMessages(list);
                else renderReadReceipt(); // 即使沒新訊息也刷新已讀指示
                resetPollBackoff();
            }
        }catch(_){ }
    }, backoffMs);
}
function stopMessagePolling(){ if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

function handlePollBackoff(){
    backoffFailCount = Math.min(backoffFailCount + 1, 6);
    backoffMs = Math.min(5000, 700 * Math.pow(1.6, backoffFailCount));
    restartPolling();
}
function resetPollBackoff(){
    if (backoffFailCount !== 0 || backoffMs !== 700){
        backoffFailCount = 0;
        backoffMs = 700;
        restartPolling();
    }
}
function restartPolling(){
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    startMessagePolling();
}

function appendMessages(list){
    const box = document.getElementById('chatMessages');
    const wasStick = chatState.autoScroll;
    let maxId = chatState.lastMsgIdByPeer[chatState.currentPeer.id] || 0;
    const rendered = chatState.renderedIdSetByPeer[chatState.currentPeer.id] || (chatState.renderedIdSetByPeer[chatState.currentPeer.id] = new Set());
    list.forEach(m=>{
        // 去重：若有 id 且已渲染過則跳過
        if (m.id && rendered.has(m.id)) return;
        const mine = m.sender_id === currentUser.id;
        const row = document.createElement('div');
        row.className = `msg ${mine?'me':'peer'}`;
        if (m.id != null) row.dataset.msgId = String(m.id);
        row.dataset.fromMe = mine ? 'true' : 'false';
        row.dataset.seen = m.seen_at ? 'true' : 'false';
        row.innerHTML = mine
            ? `<div class="bubble">${escapeHtml(m.content)}</div><div class="time">${formatTime(m.created_at)}</div>`
            : `<img src="${chatState.currentPeer.avatar||''}" class="avatar" style="width:28px;height:28px;border-radius:50%"/><div><div class="bubble">${escapeHtml(m.content)}</div><div class="time">${formatTime(m.created_at)}</div></div>`;
        box.appendChild(row);
        if (m.id && m.id > maxId) maxId = m.id;
        if (m.id) rendered.add(m.id);
    });
    chatState.lastMsgIdByPeer[chatState.currentPeer.id] = maxId;
    // 只有在使用者靠近底部或是我方訊息時才自動置底
    const containsMine = list.some(m => m.sender_id === currentUser.id);
    if (wasStick || containsMine) {
        box.scrollTop = box.scrollHeight;
    }
    scheduleMarkRead();
    renderReadReceipt();
}

function renderReadReceipt(){
    const box = document.getElementById('chatMessages');
    if (!box) return;
    const existing = document.getElementById('readReceiptMarker');
    if (existing) existing.remove();
    const msgs = Array.from(box.querySelectorAll('.msg'));
    if (!msgs.length) return;
    // 找到「最後一則『我方訊息』且已讀」的訊息節點
    const lastSeenMine = [...msgs].reverse().find(el => (el.dataset.fromMe === 'true') && (el.dataset.seen === 'true'));
    if (!lastSeenMine) return;
    const receipt = document.createElement('div');
    receipt.id = 'readReceiptMarker';
    receipt.style.display='flex';
    receipt.style.alignItems='center';
    receipt.style.justifyContent='flex-end';
    receipt.style.marginTop = '2px';
    receipt.innerHTML = `<img src="${chatState.currentPeer.avatar||''}" style="width:16px;height:16px;border-radius:50%;" title="已讀"/>`;
    lastSeenMine.insertAdjacentElement('afterend', receipt);
}

let _markReadTimer = null;
function scheduleMarkRead(){
    if (_markReadTimer) return;
    _markReadTimer = setTimeout(async ()=>{
        _markReadTimer = null;
        if (!chatState.currentPeer) return;
        try{
            await fetch(`${API_BASE_URL}/messages/read`, { method:'POST', headers:{ 'Content-Type':'application/json', Authorization:`Bearer ${authToken}` }, body: JSON.stringify({ withUserId: chatState.currentPeer.id }) });
        }catch(_){ }
    }, 800);
}

// 取消全域 click 委派以避免重複觸發，改由 wireChatSend 精準綁定

let lastEnterTs = 0;
document.addEventListener('keydown', function(e){
    const input = document.getElementById('chatInput');
    if (!input) return;
    if (document.activeElement === input && e.key === 'Enter' && !e.shiftKey && !(e.isComposing || e.keyCode===229)){
        const now = Date.now();
        if (now - lastEnterTs < 300) { return; } // 去抖：300ms 內忽略重複 Enter
        lastEnterTs = now;
        e.preventDefault();
        sendCurrentChatMessage();
    }
});

function formatTime(ts){ try{ return new Date(ts).toLocaleString(); }catch(_){ return ''; } }
function escapeHtml(s){ return s.replace(/[&<>"']/g, (c)=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;' }[c])); }
function isNearBottom(el, threshold=48){
    if (!el) return true;
    const distance = el.scrollHeight - el.scrollTop - el.clientHeight;
    return distance <= threshold;
}

function openOAuthCompleteModal() {
    // 預填現有 username 與 avatar
    const preview = document.getElementById('oauthAvatarPreview');
    const nameInput = document.getElementById('oauthUsername');
    const handleInput = document.getElementById('oauthHandle');
    const hint = document.getElementById('oauthHandleHint');
    preview.src = currentUser.avatar || '';
    nameInput.value = currentUser.username || '';
    // 清空 handle，提示必填
    if (handleInput) handleInput.value = '';
    if (hint) { hint.textContent = '請先設定你的專屬 ID 才能繼續使用'; hint.style.color = '#ef4444'; }
    document.getElementById('oauthCompleteModal').classList.add('show');
    document.body.classList.add('modal-open');
}

function openProfileModal() {
    const preview = document.getElementById('profileAvatarPreview');
    const nameInput = document.getElementById('profileUsername');
    const idInput = document.getElementById('profileUserId');
    // 若尚未設定 ID，導向完成設定視窗
    if (currentUser && !currentUser.handle) {
        openOAuthCompleteModal();
        showAlert('尚未設定 ID，請先完成設定');
        return;
    }
    preview.src = currentUser.avatar || '';
    nameInput.value = currentUser.username || '';
    if (idInput) {
        const h = (currentUser.handle || '').toLowerCase();
        idInput.value = h;
        const hint = document.getElementById('profileUserIdHint');
        if (!h) {
            if (hint) { hint.textContent = '尚未設定 ID，請點擊右上角頭像或完成設定視窗來設定'; hint.style.color = '#ef4444'; }
        } else if (hint) {
            hint.textContent = '';
        }
    }
    document.getElementById('profileModal').classList.add('show');
    document.body.classList.add('modal-open');
}

// 頭像預覽（編輯）
document.addEventListener('change', function(e){
    if (e.target && e.target.id === 'profileAvatarInput' && e.target.files && e.target.files[0]) {
        // 使用 Cropper 進行裁切
        const file = e.target.files[0];
        const reader = new FileReader();
        reader.onload = (ev)=>{
            openCropper(ev.target.result);
        };
        reader.readAsDataURL(file);
    }
});

// （已改由 hookProfileSave 處理 profileForm 提交與裁切）

// 開啟裁切器、壓縮輸出
let activeCropper = null;
function openCropper(dataUrl) {
    const img = document.getElementById('profileAvatarPreview');
    img.src = dataUrl;
    // 銷毀舊實例
    if (activeCropper) { activeCropper.destroy(); activeCropper = null; }
    // 等圖片載入後建立 cropper
    img.onload = () => {
        activeCropper = new window.Cropper(img, {
            viewMode: 1,
            aspectRatio: 1,
            background: false,
            autoCropArea: 1,
            movable: true,
            zoomable: true,
            scalable: false,
            dragMode: 'move'
        });
    };
}

// 在儲存前若有 cropper，取裁切結果並壓縮
async function getCroppedDataUrl() {
    if (!activeCropper) {
        return document.getElementById('profileAvatarPreview').src || '';
    }
    const canvas = activeCropper.getCroppedCanvas({ width: 256, height: 256 });
    // 輸出為 PNG（無損，不壓縮）
    const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
    return await new Promise(resolve => {
        const fr = new FileReader();
        fr.onload = () => resolve(fr.result);
        fr.readAsDataURL(blob);
    });
}

// 攔截 profile 儲存，改抓裁切後圖片
(function hookProfileSave(){
    const form = document.getElementById('profileForm');
    if (!form) return;
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const newName = document.getElementById('profileUsername').value.trim();
        if (!newName) { showAlert('暱稱不可為空'); return; }
        const newAvatar = await getCroppedDataUrl();
        try {
            const resp = await fetch(`${API_BASE_URL}/user/profile`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
                body: JSON.stringify({ username: newName, avatar: newAvatar })
            });
            if (!resp.ok) {
                const d = await resp.json().catch(()=>({message:'更新失敗'}));
                throw new Error(d.message || '更新失敗');
            }
            const updated = await resp.json();
            if (updated && updated.user) {
                currentUser.username = updated.user.username || newName;
                currentUser.avatar = updated.user.avatar || newAvatar;
                currentUser.handle = updated.user.handle || currentUser.handle;
            } else {
                // 後備：沿用本地值
                currentUser.username = newName;
                currentUser.avatar = newAvatar;
            }
            document.getElementById('userName').textContent = newName;
            document.getElementById('userAvatar').src = newAvatar;
            const idInput = document.getElementById('profileUserId');
            if (idInput && currentUser.handle) idInput.value = currentUser.handle;
            closeModal('profileModal');
            if (activeCropper) { activeCropper.destroy(); activeCropper = null; }
            showAlert('已更新個人資料','success');
        } catch (err) {
            console.error('更新個人資料錯誤:', err);
            showAlert(err.message || '更新失敗');
        }
    }, { once: true });
})();

// 登出
function logout() {
    // 清理所有認證相關數據
    currentUser = null;
    authToken = null;
    localStorage.removeItem('authToken');
    
    // 重置UI
    document.getElementById('authButtons').style.display = 'flex';
    document.getElementById('userInfo').style.display = 'none';
    
    // 重置歡迎訊息
    const welcomeSection = document.getElementById('welcomeSection');
    welcomeSection.innerHTML = `
        <h1>歡迎來到 FayCR連線室</h1>
        <p>請登入或註冊以開始使用</p>
    `;
    
    showAlert('已成功登出', 'success');
}

// 顯示提示訊息
function showAlert(message, type = 'error') {
    // 移除現有的提示
    const existingAlert = document.querySelector('.alert');
    if (existingAlert) {
        existingAlert.remove();
    }
    
    // 創建新提示
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.innerHTML = `
        <div class="alert-content">
            <i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'}"></i>
            <span>${message}</span>
            <button class="alert-close" onclick="this.parentElement.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;
    
    // 添加樣式
    alert.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 10000;
        background: ${type === 'success' ? '#10b981' : '#ef4444'};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 10px;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
        animation: slideInFromRight 0.3s ease;
        max-width: 400px;
        word-wrap: break-word;
    `;
    
    document.body.appendChild(alert);
    
    // 自動移除
    setTimeout(() => {
        if (alert.parentElement) {
            alert.style.animation = 'slideOutToRight 0.3s ease';
            setTimeout(() => alert.remove(), 300);
        }
    }, 5000);
}

// 添加動畫樣式
const alertStyles = document.createElement('style');
alertStyles.textContent = `
    .alert-content {
        display: flex;
        align-items: center;
        gap: 0.8rem;
    }
    
    .alert-close {
        background: none;
        border: none;
        color: white;
        cursor: pointer;
        padding: 0.2rem;
        border-radius: 3px;
        transition: background 0.2s;
    }
    
    .alert-close:hover {
        background: rgba(255, 255, 255, 0.2);
    }
    
    @keyframes slideInFromRight {
        from {
            opacity: 0;
            transform: translateX(100%);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
    
    @keyframes slideOutToRight {
        from {
            opacity: 1;
            transform: translateX(0);
        }
        to {
            opacity: 0;
            transform: translateX(100%);
        }
    }
`;
document.head.appendChild(alertStyles);

// 鍵盤快捷鍵
document.addEventListener('keydown', function(event) {
    // ESC 關閉彈窗
    if (event.key === 'Escape') {
        closeAllModals();
    }
    
    // Enter 在驗證碼輸入框中驗證
    if (event.key === 'Enter' && event.target.id === 'verificationCode') {
        verifyCode();
    }
});

// 表單實時驗證
document.addEventListener('input', function(event) {
    const input = event.target;
    
    // 密碼確認驗證
    if (input.id === 'confirmPassword' || input.id === 'registerPassword') {
        const password = document.getElementById('registerPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        const confirmInput = document.getElementById('confirmPassword');
        
        if (confirmPassword && password !== confirmPassword) {
            confirmInput.style.borderColor = '#ef4444';
        } else {
            confirmInput.style.borderColor = '';
        }
    }
    
    // 郵件格式驗證
    if (input.type === 'email') {
        if (input.value && !isValidEmail(input.value)) {
            input.style.borderColor = '#ef4444';
        } else {
            input.style.borderColor = '';
        }
    }
    
    // 驗證碼只允許數字
    if (input.id === 'verificationCode') {
        input.value = input.value.replace(/[^0-9]/g, '');
    }
});

// 防止表單默認提交
document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', function(event) {
        event.preventDefault();
    });
});

console.log('FayCRChat 認證系統已初始化');
