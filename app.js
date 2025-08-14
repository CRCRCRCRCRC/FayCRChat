const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');
const fetch = global.fetch || require('node-fetch');

// 引入自定義模塊
const Database = require('./database');
const EmailService = require('./emailService');

// 載入配置
let config;
try {
    config = require('./config');
} catch (err) {
    console.error('❌ 找不到 config.js 文件！');
    console.log('請建立 config.js 並填入您的配置');
    process.exit(1);
}

const app = express();
// 簡易 SSE Hub（單實例最佳努力）
const sseClients = global.__sseClients || new Map();
global.__sseClients = sseClients;
function getSseSet(userId){
    const id = Number(userId);
    if (!sseClients.has(id)) sseClients.set(id, new Set());
    return sseClients.get(id);
}
function broadcastToUser(userId, eventName, payload){
    const set = getSseSet(userId);
    const data = `event: ${eventName}\n` + `data: ${JSON.stringify(payload)}\n\n`;
    for (const res of [...set]){
        try { res.write(data); } catch(_) { try{ set.delete(res); }catch(_){} }
    }
}
// 在 Vercel/Proxy 環境下，必須信任代理，否則 rate-limit 會報 X-Forwarded-For 錯誤
app.set('trust proxy', 1);

// 初始化數據庫和郵件服務
const database = new Database(config.database.filename);
const emailService = new EmailService(config.email);

// Google OAuth 客戶端（授權碼流程）
const googleOAuthClient = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    `${process.env.PUBLIC_BASE_URL || ''}/api/auth/google/callback`
);

// 安全中間件
app.use(helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https:"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "https:", "data:"],
        },
    },
}));

// 速率限制（調整為分類限流）
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    skip: (req, _res) => req.path.startsWith('/api/messages'),
    message: {
        error: 'RATE_LIMIT_EXCEEDED',
        message: '請求過於頻繁，請稍後再試'
    }
});

const messagesLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 180, // 約每秒 3 次
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'CHAT_RATE_LIMIT', message: '訊息請求過於頻繁，請稍後再試' }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: {
        error: 'AUTH_RATE_LIMIT_EXCEEDED',
        message: '認證請求過於頻繁，請稍後再試'
    }
});

// 對一般 API 啟用一般限流；聊天訊息相關改用專屬限流
app.use(generalLimiter);

// CORS 配置（允許動態來源）
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// 中間件
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 本地開發時提供靜態檔案（Vercel 函式中不會使用到檔案系統）
// 注意：Vercel Serverless 環境為唯讀，請勿在 /var/task 下寫入檔案

// 不在 Serverless 中做磁碟上傳；頭像以 base64 存入資料庫

// JWT 中間件
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'NO_TOKEN', message: '需要訪問令牌' });
    }
    jwt.verify(token, config.server.jwtSecret, (err, user) => {
        if (err) return res.status(403).json({ error: 'INVALID_TOKEN', message: '無效的訪問令牌' });
        req.user = user;
        next();
    });
};

// API 路由
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'FayCRChat 後端服務運行中', timestamp: new Date().toISOString() });
});

// 提供前端需要的公開環境變數（不包含敏感值）
app.get('/api/env', (req, res) => {
    res.json({
        googleClientId: process.env.GOOGLE_CLIENT_ID || '',
        discordClientId: process.env.DISCORD_CLIENT_ID || ''
    });
});

app.get('/api/test-email', async (req, res) => {
    try {
        const result = await emailService.testConnection();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'EMAIL_TEST_FAILED', message: error.message });
    }
});

app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { username, email, password, avatar, handle } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'MISSING_FIELDS', message: '請填寫所有必填欄位' });
        }
        if (username.length < 2) return res.status(400).json({ error: 'INVALID_USERNAME', message: '使用者名稱至少需要2個字元' });
        if (password.length < 6) return res.status(400).json({ error: 'INVALID_PASSWORD', message: '密碼至少需要6個字元' });
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) return res.status(400).json({ error: 'INVALID_EMAIL', message: '請輸入有效的電子郵件地址' });

        const user = await database.createUser({ username, email, password, avatarData: avatar, handle });

        try {
            await emailService.sendVerificationEmail(email, username, user.verificationCode);
            res.status(201).json({ success: true, message: '註冊成功！驗證郵件已發送', user: { id: user.id, username, email, handle: user.handle } });
        } catch (emailError) {
            console.error('發送驗證郵件失敗:', emailError);
            res.status(201).json({ success: true, message: '註冊成功！但驗證郵件發送失敗，請稍後重新發送', user: { id: user.id, username, email, handle: user.handle }, emailError: true });
        }
    } catch (error) {
        if (error.message === 'INVALID_HANDLE') return res.status(400).json({ error: 'INVALID_HANDLE', message: 'ID 僅能包含英文小寫、數字、-、_' });
        if (error.message === 'HANDLE_TAKEN') return res.status(409).json({ error: 'HANDLE_TAKEN', message: '此 ID 已被使用' });
        if (error.message === 'EMAIL_EXISTS') return res.status(409).json({ error: 'EMAIL_EXISTS', message: '此電子郵件已被註冊' });
        res.status(500).json({ error: 'REGISTRATION_FAILED', message: '註冊失敗，請稍後再試' });
    }
});

app.post('/api/verify-email', authLimiter, async (req, res) => {
    try {
        const { email, code } = req.body;
        if (!email || !code) return res.status(400).json({ error: 'MISSING_FIELDS', message: '請提供電子郵件和驗證碼' });

        const result = await database.verifyUser(email, code);
        try {
            const user = await database.getUserById(result.userId);
            await emailService.sendWelcomeEmail(email, user.username);
        } catch (_) {}
        res.json({ success: true, message: '電子郵件驗證成功！' });
    } catch (error) {
        if (error.message === 'USER_NOT_FOUND') return res.status(404).json({ error: 'USER_NOT_FOUND', message: '找不到用戶' });
        if (error.message === 'INVALID_CODE') return res.status(400).json({ error: 'INVALID_CODE', message: '驗證碼錯誤' });
        if (error.message === 'CODE_EXPIRED') return res.status(400).json({ error: 'CODE_EXPIRED', message: '驗證碼已過期，請重新發送' });
        res.status(500).json({ error: 'VERIFICATION_FAILED', message: '驗證失敗，請稍後再試' });
    }
});

app.post('/api/resend-verification', authLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'MISSING_EMAIL', message: '請提供電子郵件地址' });

        const result = await database.resendVerificationCode(email);
        let username = '用戶';
        try {
            await new Promise((resolve, reject) => {
                database.db.get('SELECT username FROM users WHERE email = ?', [email], (err, row) => {
                    if (err) return reject(err);
                    if (row && row.username) username = row.username;
                    resolve();
                });
            });
        } catch (_) {}
        await emailService.sendVerificationEmail(email, username, result.verificationCode);
        res.json({ success: true, message: '驗證碼已重新發送' });
    } catch (error) {
        if (error.message === 'USER_NOT_FOUND_OR_VERIFIED') return res.status(404).json({ error: 'USER_NOT_FOUND_OR_VERIFIED', message: '找不到用戶或用戶已驗證' });
        res.status(500).json({ error: 'RESEND_FAILED', message: '重發驗證碼失敗，請稍後再試' });
    }
});

app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'MISSING_FIELDS', message: '請填寫電子郵件和密碼' });

        const user = await database.authenticateUser(email, password);
        const token = jwt.sign({ userId: user.id, email: user.email, username: user.username }, config.server.jwtSecret, { expiresIn: '7d' });
        res.json({ success: true, message: '登入成功', token, user: { id: user.id, username: user.username, email: user.email, avatar: user.avatar, handle: user.handle } });
    } catch (error) {
        if (error.message === 'USER_NOT_FOUND' || error.message === 'INVALID_PASSWORD') {
            return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: '電子郵件或密碼錯誤' });
        }
        if (error.message === 'EMAIL_NOT_VERIFIED') return res.status(403).json({ error: 'EMAIL_NOT_VERIFIED', message: '請先驗證您的電子郵件' });
        res.status(500).json({ error: 'LOGIN_FAILED', message: '登入失敗，請稍後再試' });
    }
});

// Step 1: 前端導向 Google 授權頁（前端已組好URL）

// Step 2: 授權碼 callback（交換 token 並登入/註冊）
app.get('/api/auth/google/callback', async (req, res) => {
    try {
        const code = req.query.code;
        if (!code) return res.status(400).send('Missing code');

        const r = await googleOAuthClient.getToken({ code });
        const idToken = r.tokens.id_token;
        if (!idToken) return res.status(500).send('No id_token');

        const ticket = await googleOAuthClient.verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID });
        const payload = ticket.getPayload();
        const email = payload.email;
        const username = payload.name || email.split('@')[0];
        const avatar = payload.picture || null;

        // 嘗試查詢/建立使用者
        const sql = require('@neondatabase/serverless').neon(process.env.DATABASE_URL);
        let rows = await sql`select id, username, email, avatar_data, is_verified, user_handle from users where email = ${email}`;
        let userRow = rows[0];
        if (!userRow) {
            // OAuth 首次建立：直接驗證為 true，且 user_handle 暫不設定（NULL）
            const rndPass = Math.random().toString(36) + Date.now().toString(36);
            const passwordHash = await bcrypt.hash(rndPass, 12);
            const ins = await sql`
                insert into users (username, email, password_hash, avatar_data, is_verified, verification_code, verification_expires, user_handle)
                values (${username}, ${email}, ${passwordHash}, ${avatar || null}, true, null, null, null)
                returning id, username, email, avatar_data, is_verified, user_handle
            `;
            userRow = ins[0];
        }
        // 覆蓋頭像
        if (avatar && userRow && userRow.avatar_data !== avatar) {
            await sql`update users set avatar_data = ${avatar} where email = ${email}`;
            userRow.avatar_data = avatar;
        }

        const token = jwt.sign({ userId: userRow.id, email: userRow.email, username: userRow.username }, config.server.jwtSecret, { expiresIn: '7d' });
        // 改用 302 導回首頁，將 token 放在查詢參數，避免 inline script 觸發 CSP
        return res.redirect(`/?token=${encodeURIComponent(token)}`);
    } catch (e) {
        console.error('Google OAuth callback error:', e);
        return res.status(500).send('Google OAuth Failed');
    }
});

// Discord OAuth callback：交換 token、拿使用者資料，並嘗試加入指定伺服器
app.get('/api/auth/discord/callback', async (req, res) => {
    try {
        const code = req.query.code;
        if (!code) return res.status(400).send('Missing code');

        const redirectUri = `${process.env.PUBLIC_BASE_URL || ''}/api/auth/discord/callback`;
        // 交換 token
        const tokenResp = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: process.env.DISCORD_CLIENT_ID,
                client_secret: process.env.DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code,
                redirect_uri: redirectUri
            })
        });
        if (!tokenResp.ok) {
            const txt = await tokenResp.text();
            return res.status(500).send('Discord token exchange failed: ' + txt);
        }
        const tokenData = await tokenResp.json();
        const accessToken = tokenData.access_token;

        // 取得使用者資料
        const userResp = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${accessToken}` }
        });
        if (!userResp.ok) {
            const txt = await userResp.text();
            return res.status(500).send('Discord user fetch failed: ' + txt);
        }
        const u = await userResp.json();
        const email = u.email || `${u.id}@discord.local`; // 若未授權 email，使用臨時郵件
        const username = u.global_name || u.username || 'DiscordUser';
        const avatar = u.avatar ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png?size=128` : null;

        // 查詢/建立本地使用者
        const sql = require('@neondatabase/serverless').neon(process.env.DATABASE_URL);
        let rows = await sql`select id, username, email, avatar_data, is_verified, user_handle from users where email = ${email}`;
        let userRow = rows[0];
        if (!userRow) {
            const rndPass = Math.random().toString(36) + Date.now().toString(36);
            const passwordHash = await bcrypt.hash(rndPass, 12);
            const ins = await sql`
                insert into users (username, email, password_hash, avatar_data, is_verified, verification_code, verification_expires, user_handle)
                values (${username}, ${email}, ${passwordHash}, ${avatar || null}, true, null, null, null)
                returning id, username, email, avatar_data, is_verified, user_handle
            `;
            userRow = ins[0];
        }
        if (avatar && userRow && userRow.avatar_data !== avatar) {
            await sql`update users set avatar_data = ${avatar} where email = ${email}`;
            userRow.avatar_data = avatar;
        }

        // 嘗試讓使用者加入指定伺服器（需 Bot Token 並且 bot 在該伺服器，且有 guilds.join scope）
        // 注意：Discord 已不再允許純 OAuth user token 直接加 guild，需透過 Bot 的 OAuth2 與 Add Guild Member API
        // 這裡提供示範：若提供 DISCORD_GUILD_ID 與 DISCORD_BOT_TOKEN，則嘗試加入
        if (process.env.DISCORD_GUILD_ID && process.env.DISCORD_BOT_TOKEN) {
            try {
                const joinResp = await fetch(`https://discord.com/api/guilds/${process.env.DISCORD_GUILD_ID}/members/${u.id}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bot ${process.env.DISCORD_BOT_TOKEN}`
                    },
                    body: JSON.stringify({
                        access_token: accessToken
                    })
                });
                // 201/204 表成功；若失敗可忽略不阻斷登入
            } catch (_) {}
        }

        const token = jwt.sign({ userId: userRow.id, email: userRow.email, username: userRow.username }, config.server.jwtSecret, { expiresIn: '7d' });
        return res.redirect(`/?token=${encodeURIComponent(token)}`);
    } catch (e) {
        console.error('Discord OAuth callback error:', e);
        return res.status(500).send('Discord OAuth Failed');
    }
});

app.get('/api/user', authenticateToken, async (req, res) => {
    try {
        const user = await database.getUserById(req.user.userId);
        res.json({ success: true, user: { id: user.id, username: user.username, email: user.email, avatar: user.avatar, isVerified: user.isVerified, handle: user.handle } });
    } catch (error) {
        res.status(500).json({ error: 'GET_USER_FAILED', message: '獲取用戶資訊失敗' });
    }
});

// 發送好友請求
app.post('/api/friends/request', authenticateToken, async (req, res) => {
    try {
        const { handle } = req.body;
        if (!handle) return res.status(400).json({ error: 'MISSING_HANDLE' });
        const r = await database.createFriendRequest(req.user.userId, handle);
        res.json({ success: true, requestId: r.requestId, targetUserId: r.targetUserId });
    } catch (e) {
        if (e.message === 'USER_NOT_FOUND') return res.status(404).json({ error: 'USER_NOT_FOUND', message: '使用者不存在' });
        if (e.message === 'CANNOT_ADD_SELF') return res.status(400).json({ error: 'CANNOT_ADD_SELF', message: '不能加自己為好友' });
        if (e.message === 'ALREADY_PENDING') return res.status(409).json({ error: 'ALREADY_PENDING', message: '已送出邀請，等待對方回覆' });
        if (e.message === 'ALREADY_FRIENDS') return res.status(409).json({ error: 'ALREADY_FRIENDS', message: '已經是好友' });
        console.error('friend request error', e);
        res.status(500).json({ error: 'REQUEST_FAILED' });
    }
});

// 取得待處理的好友邀請
app.get('/api/friends/requests', authenticateToken, async (req, res) => {
    try {
        const list = await database.getIncomingFriendRequests(req.user.userId);
        res.json({ success: true, requests: list });
    } catch (e) {
        res.status(500).json({ error: 'FETCH_FAILED' });
    }
});

// 回覆好友邀請（接受/拒絕）
app.post('/api/friends/respond', authenticateToken, async (req, res) => {
    try {
        const { requestId, action } = req.body; // action: accept|reject
        if (!requestId || !['accept', 'reject'].includes(action)) return res.status(400).json({ error: 'BAD_REQUEST' });
        const r = await database.respondFriendRequest(req.user.userId, requestId, action);
        res.json({ success: true, status: r.status });
    } catch (e) {
        if (e.message === 'REQUEST_NOT_FOUND') return res.status(404).json({ error: 'REQUEST_NOT_FOUND' });
        if (e.message === 'FORBIDDEN') return res.status(403).json({ error: 'FORBIDDEN' });
        if (e.message === 'ALREADY_HANDLED') return res.status(409).json({ error: 'ALREADY_HANDLED' });
        res.status(500).json({ error: 'RESPOND_FAILED' });
    }
});

// 好友列表
app.get('/api/friends', authenticateToken, async (req, res) => {
    try {
        const friends = await database.getFriends(req.user.userId);
        res.json({ success: true, friends });
    } catch (e) {
        res.status(500).json({ error: 'FETCH_FAILED' });
    }
});

// ===== Groups =====
// 建立群組：name + memberIds（包含 owner 會自動加入）
app.post('/api/groups', authenticateToken, async (req, res) => {
    try {
        const { name, memberIds, avatar } = req.body;
        if (!name || (typeof name !== 'string')) return res.status(400).json({ error: 'INVALID_NAME', message: '群組名稱不可為空' });
        const ids = Array.isArray(memberIds) ? memberIds : [];
        const g = await database.createGroup(req.user.userId, name, ids, avatar || null);
        res.json({ success: true, group: { id: g.id, name, avatar: avatar || null } });
    } catch (e) {
        if (e.message === 'INVALID_NAME') return res.status(400).json({ error: 'INVALID_NAME', message: '群組名稱不可為空' });
        console.error('create group error:', e);
        res.status(500).json({ error: 'CREATE_GROUP_FAILED' });
    }
});

// 取使用者所在群組
app.get('/api/groups', authenticateToken, async (req, res) => {
    try { const list = await database.getUserGroups(req.user.userId); res.json({ success:true, groups: list }); }
    catch(e){ res.status(500).json({ error:'FETCH_GROUPS_FAILED' }); }
});

// 群組訊息
app.get('/api/group-messages', authenticateToken, messagesLimiter, async (req, res) => {
    try {
        const gid = req.query.groupId ? parseInt(req.query.groupId, 10) : null;
        const beforeId = req.query.before ? parseInt(req.query.before, 10) : null;
        const afterId = req.query.after ? parseInt(req.query.after, 10) : null;
        if (!Number.isFinite(gid)) return res.status(400).json({ error:'BAD_REQUEST', message:'缺少或無效的 groupId' });
        const list = await database.getGroupMessages(req.user.userId, gid, 50, beforeId, afterId);
        res.json({ success:true, messages: list });
    } catch(e){
        if (e.message === 'NOT_GROUP_MEMBER') return res.status(403).json({ error:'FORBIDDEN' });
        res.status(500).json({ error:'FETCH_FAILED', message: e.message || '取得訊息失敗' });
    }
});

app.post('/api/group-messages', authenticateToken, messagesLimiter, async (req, res) => {
    try {
        const { groupId, content, clientId, image, imageMime } = req.body;
        const gid = Number(groupId);
        const text = typeof content === 'string' ? content : '';
        const hasImage = !!(image && String(image).length);
        if (!Number.isFinite(gid) || (!text.trim() && !hasImage)) return res.status(400).json({ error:'BAD_REQUEST', message:'群組或內容/圖片無效' });
        const r = await database.sendGroupMessage(req.user.userId, gid, text, clientId || null, hasImage ? image : null, hasImage ? (imageMime || 'image/png') : null);
        res.json({ success:true, id:r.id, createdAt: r.createdAt });
        // SSE 廣播給群組所有成員
        try {
            const memberIds = await database.getGroupMemberIds(gid);
            const payload = { id: r.id, group_id: gid, sender_id: req.user.userId, content: text, created_at: r.createdAt, image_data: hasImage ? image : null, image_mime: hasImage ? (imageMime || 'image/png') : null };
            memberIds.filter(uid => uid !== req.user.userId).forEach(uid => broadcastToUser(uid, 'new_message', payload));
        } catch(_) {}
    } catch(e){
        if (e.message === 'NOT_GROUP_MEMBER') return res.status(403).json({ error:'FORBIDDEN' });
        res.status(500).json({ error:'SEND_FAILED', message: e.message || '發送失敗' });
    }
});

// 取得與某人對話訊息
app.get('/api/messages', authenticateToken, messagesLimiter, async (req, res) => {
    try {
        const withUserId = parseInt(req.query.with, 10);
        const beforeId = req.query.before ? parseInt(req.query.before, 10) : null;
        const afterId = req.query.after ? parseInt(req.query.after, 10) : null;
        if (!Number.isFinite(withUserId)) {
            return res.status(400).json({ error: 'BAD_REQUEST', message: '缺少或無效的對話對象' });
        }
        const list = await database.getMessages(req.user.userId, withUserId, 50, beforeId, afterId);
        res.json({ success: true, messages: list });
    } catch (e) {
        console.error('GET /api/messages error:', e);
        res.status(500).json({ error: 'FETCH_FAILED', message: e.message || '取得訊息失敗' });
    }
});

// 傳送訊息
app.post('/api/messages', authenticateToken, messagesLimiter, async (req, res) => {
    try {
        const { toUserId, content, clientId, image, imageMime } = req.body;
        const receiverId = Number(toUserId);
        const text = typeof content === 'string' ? content : '';
        const hasImage = !!(image && String(image).length);
        if (!Number.isFinite(receiverId) || (!text.trim() && !hasImage)) {
            return res.status(400).json({ error: 'BAD_REQUEST', message: '收件人或內容/圖片無效' });
        }
        const r = await database.sendMessage(req.user.userId, receiverId, text, clientId || null, hasImage ? image : null, hasImage ? (imageMime || 'image/png') : null);
        // 回傳標準化欄位（含 id），供前端去重
        res.json({ success: true, id: r.id, createdAt: r.createdAt });
        // SSE 推播給接收者
        try { broadcastToUser(receiverId, 'new_message', { id: r.id, sender_id: req.user.userId, receiver_id: receiverId, content: text, created_at: r.createdAt, image_data: hasImage ? image : null, image_mime: hasImage ? (imageMime || 'image/png') : null }); } catch(_) {}
    } catch (e) {
        console.error('POST /api/messages error:', e);
        res.status(500).json({ error: 'SEND_FAILED', message: e.message || '發送失敗' });
    }
});

// 已讀回報
app.post('/api/messages/read', authenticateToken, messagesLimiter, async (req, res) => {
    try {
        const { withUserId } = req.body;
        const peerId = Number(withUserId);
        if (!Number.isFinite(peerId)) return res.status(400).json({ error: 'BAD_REQUEST', message: 'withUserId 無效' });
        await database.markMessagesRead(req.user.userId, peerId);
        res.json({ success: true });
        // SSE 通知對方：你的訊息已被我讀取
        try { broadcastToUser(peerId, 'read_update', { byUserId: req.user.userId, withUserId: peerId }); } catch(_) {}
    } catch (e) {
        console.error('POST /api/messages/read error:', e);
        res.status(500).json({ error: 'READ_FAILED', message: e.message || '已讀標記失敗' });
    }
});

// SSE 連線（使用 token 查詢參數驗證）
app.get('/api/stream', async (req, res) => {
    try {
        const token = req.query.token;
        if (!token) return res.status(401).end();
        let user;
        try { user = jwt.verify(token, config.server.jwtSecret); } catch(_) { return res.status(403).end(); }
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        // 立即發送一次，讓連線就緒
        res.write(':ok\n\n');
        const set = getSseSet(user.userId);
        set.add(res);
        const keep = setInterval(()=>{ try{ res.write(':ka\n\n'); }catch(_){ } }, 20000);
        req.on('close', () => { clearInterval(keep); try{ set.delete(res); }catch(_){} });
    } catch (_) {
        try { res.status(500).end(); } catch(_){ }
    }
});
// 管理端：清空所有使用者（需啟用與權杖）
app.post('/api/admin/purge-users', async (req, res) => {
    try {
        if (process.env.ADMIN_PURGE_ENABLED !== 'true') {
            return res.status(403).json({ error: 'DISABLED', message: '此操作未啟用' });
        }
        const adminToken = req.headers['x-admin-token'];
        if (!adminToken || adminToken !== process.env.ADMIN_PURGE_TOKEN) {
            return res.status(403).json({ error: 'FORBIDDEN', message: '缺少或無效的管理權杖' });
        }
        const sql = require('@neondatabase/serverless').neon(process.env.DATABASE_URL);
        await sql`truncate table users restart identity`;
        return res.json({ success: true });
    } catch (e) {
        console.error('Purge users error:', e);
        return res.status(500).json({ error: 'PURGE_FAILED', message: '清除失敗' });
    }
});

// 可用性檢查：ID 是否可用
app.get('/api/handle-available', async (req, res) => {
    try {
        const handle = req.query.handle || '';
        const result = await database.isHandleAvailable(handle);
        res.json(result);
    } catch (e) {
        res.status(500).json({ available: false });
    }
});

// 更新個人資料（名稱、頭像，同步更新唯一 ID）
app.post('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const { username, avatar } = req.body;
        if (!username) return res.status(400).json({ error: 'INVALID_USERNAME', message: '暱稱不可為空' });
        const updated = await database.updateUserProfile(req.user.userId, { username, avatarData: avatar });
        res.json({ success: true, user: { id: updated.id, username: updated.username, email: updated.email, avatar: updated.avatar, isVerified: updated.isVerified, handle: updated.handle } });
    } catch (e) {
        console.error('更新個人資料錯誤:', e);
        res.status(500).json({ error: 'PROFILE_UPDATE_FAILED', message: '更新失敗' });
    }
});

// OAuth 首登後補資料：設定 handle 與（可選）暱稱、頭像
app.post('/api/user/complete-oauth', authenticateToken, async (req, res) => {
    try {
        const { handle, username, avatar } = req.body;
        if (!handle || !/^[a-z0-9_-]+$/.test(String(handle).toLowerCase())) {
            return res.status(400).json({ error: 'INVALID_HANDLE', message: 'ID 僅能包含英文小寫、數字、-、_' });
        }
        // 檢查占用
        const sql = require('@neondatabase/serverless').neon(process.env.DATABASE_URL);
        const normalized = String(handle).toLowerCase();
        const taken = await sql`select id from users where user_handle = ${normalized} and id <> ${req.user.userId} limit 1`;
        if (taken.length) return res.status(409).json({ error: 'HANDLE_TAKEN', message: '此 ID 已被使用' });

        // 更新：只設定 user_handle（若提供 username/avatar 也一併更新）
        await sql`
            update users
            set user_handle = ${normalized},
                username = ${username || null},
                avatar_data = ${avatar || null},
                updated_at = now()
            where id = ${req.user.userId}
        `;
        const u = await database.getUserById(req.user.userId);
        res.json({ success: true, user: { id: u.id, username: u.username, email: u.email, avatar: u.avatar, isVerified: u.isVerified, handle: u.handle } });
    } catch (e) {
        console.error('complete-oauth error:', e);
        res.status(500).json({ error: 'COMPLETE_OAUTH_FAILED', message: '設定失敗' });
    }
});

// 取消 /uploads 靜態服務（Serverless 無檔案系統）

// 錯誤處理中間件
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'FILE_TOO_LARGE', message: '文件大小不能超過5MB' });
    }
    res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: '服務器內部錯誤' });
});

module.exports = app;


