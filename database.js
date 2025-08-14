const { neon } = require('@neondatabase/serverless');
const bcrypt = require('bcryptjs');

const sql = neon(process.env.DATABASE_URL);

async function ensureTables() {
    await sql`
        create table if not exists users (
            id serial primary key,
            username text not null,
            email text unique not null,
            password_hash text not null,
            avatar_data text,
            is_verified boolean default false,
            verification_code text,
            verification_expires bigint,
            created_at timestamptz default now(),
            updated_at timestamptz default now()
        )
    `;
    // 新增以暱稱派生的唯一 ID 欄位（若不存在）
    await sql`alter table users add column if not exists user_handle text unique`;
    // 好友請求表
    await sql`
        create table if not exists friend_requests (
            id serial primary key,
            requester_id int not null references users(id) on delete cascade,
            target_user_id int not null references users(id) on delete cascade,
            status text not null default 'pending',
            created_at timestamptz default now(),
            responded_at timestamptz
        )
    `;
    // 訊息表（雙人）
    await sql`
        create table if not exists messages (
            id serial primary key,
            sender_id int not null references users(id) on delete cascade,
            receiver_id int not null references users(id) on delete cascade,
            content text not null,
            created_at timestamptz default now(),
            seen_at timestamptz
        )
    `;
    // 用於客戶端冪等：避免重複插入同一則訊息
    await sql`alter table messages add column if not exists client_id text unique`;
    // 圖片訊息（Base64 Data URL 或純 base64），與 MIME
    await sql`alter table messages add column if not exists image_data text`;
    await sql`alter table messages add column if not exists image_mime text`;

    // ===== Groups =====
    await sql`
        create table if not exists groups (
            id serial primary key,
            name text not null,
            owner_id int not null references users(id) on delete cascade,
            created_at timestamptz default now(),
            avatar_data text
        )
    `;
    await sql`alter table groups add column if not exists avatar_data text`;
    await sql`
        create table if not exists group_members (
            id serial primary key,
            group_id int not null references groups(id) on delete cascade,
            user_id int not null references users(id) on delete cascade,
            added_at timestamptz default now(),
            unique (group_id, user_id)
        )
    `;
    await sql`
        create table if not exists group_messages (
            id serial primary key,
            group_id int not null references groups(id) on delete cascade,
            sender_id int not null references users(id) on delete cascade,
            content text not null,
            created_at timestamptz default now(),
            image_data text,
            image_mime text,
            client_id text unique
        )
    `;
}

// 由暱稱產生基底 handle：只保留英文字母（a-z），轉小寫；空則回退 'user'
function createBaseHandle(username) {
    if (!username) return 'user';
    const ascii = username
        .toString()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, ''); // 去除變音符
    const lettersOnly = ascii.toLowerCase().replace(/[^a-z]/g, '');
    return lettersOnly || 'user';
}

function normalizeHandleInput(handle) {
    if (!handle) return '';
    return handle.toString().trim().toLowerCase();
}

function isValidHandlePattern(handle) {
    return /^[a-z0-9_-]+$/.test(handle);
}

// 生成不重複的 handle：base、base-2、base-3 ...
function numberToLetters(n) {
    // 1 -> a, 2 -> b, ..., 26 -> z, 27 -> aa, ...
    let s = '';
    while (n > 0) {
        n -= 1;
        s = String.fromCharCode(97 + (n % 26)) + s;
        n = Math.floor(n / 26);
    }
    return s;
}

async function generateUniqueHandle(base, excludeUserId = null) {
    let candidate = base && base.length ? base : 'user';
    // 先測試 base 本身
    let rows = excludeUserId == null
        ? await sql`select id from users where user_handle = ${candidate} limit 1`
        : await sql`select id from users where user_handle = ${candidate} and id <> ${excludeUserId} limit 1`;
    if (!rows.length) return candidate;

    // 依序嘗試 base + a, base + b, ... base + z, base + aa, ...
    for (let i = 1; i <= 5000; i++) {
        const suffix = numberToLetters(i);
        candidate = `${base}${suffix}`;
        rows = excludeUserId == null
            ? await sql`select id from users where user_handle = ${candidate} limit 1`
            : await sql`select id from users where user_handle = ${candidate} and id <> ${excludeUserId} limit 1`;
        if (!rows.length) return candidate;
    }
    // 極端 fallback：附加隨機 6 碼字母
    const random = Array.from({length:6},()=>String.fromCharCode(97+Math.floor(Math.random()*26))).join('');
    return `${base}${random}`;
}

class Database {
    constructor() {
        // best-effort 初始化
        this._init = ensureTables().catch(() => {});
    }

    async createUser({ username, email, password, avatarData, handle }) {
        await this._init;

        const exists = await sql`select id from users where email = ${email}`;
        if (exists.length) throw new Error('EMAIL_EXISTS');

        const passwordHash = await bcrypt.hash(password, 12);
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const verificationExpires = Date.now() + 15 * 60 * 1000;
        let finalHandle;
        if (handle && handle.length) {
            const normalized = normalizeHandleInput(handle);
            if (!isValidHandlePattern(normalized)) throw new Error('INVALID_HANDLE');
            // 檢查是否已被使用
            const taken = await sql`select id from users where user_handle = ${normalized} limit 1`;
            if (taken.length) throw new Error('HANDLE_TAKEN');
            finalHandle = normalized;
        } else {
            const base = createBaseHandle(username);
            finalHandle = await generateUniqueHandle(base);
        }

        const rows = await sql`
            insert into users (username, email, password_hash, avatar_data, verification_code, verification_expires, user_handle)
            values (${username}, ${email}, ${passwordHash}, ${avatarData || null}, ${verificationCode}, ${verificationExpires}, ${finalHandle})
            returning id, user_handle
        `;
        const id = rows[0].id;
        const userHandle = rows[0].user_handle;
        return { id, username, email, verificationCode, verificationExpires, handle: userHandle };
    }

    async verifyUser(email, code) {
        await this._init;
        const rows = await sql`select id, verification_code, verification_expires from users where email = ${email}`;
        if (!rows.length) throw new Error('USER_NOT_FOUND');
        const u = rows[0];
        if (u.verification_code !== code) throw new Error('INVALID_CODE');
        if (Date.now() > Number(u.verification_expires)) throw new Error('CODE_EXPIRED');

        await sql`update users set is_verified = true, verification_code = null, verification_expires = null, updated_at = now() where id = ${u.id}`;
        return { success: true, userId: u.id };
    }

    async authenticateUser(email, password) {
        await this._init;
        const rows = await sql`select id, username, email, password_hash, avatar_data, is_verified, user_handle from users where email = ${email}`;
        if (!rows.length) throw new Error('USER_NOT_FOUND');
        const u = rows[0];
        if (!u.is_verified) throw new Error('EMAIL_NOT_VERIFIED');
        const ok = await bcrypt.compare(password, u.password_hash);
        if (!ok) throw new Error('INVALID_PASSWORD');
        // 若為 null 代表尚未完成首次設定（OAuth 首登）；保留 null 以讓前端彈出補資料
        let handle = u.user_handle;
        if (handle != null) {
            const normalized = normalizeHandleInput(handle);
            if (!isValidHandlePattern(normalized)) {
                // 舊資料不合規 → 轉合法且唯一
                const base = createBaseHandle(u.username);
                handle = await generateUniqueHandle(base, u.id);
                await sql`update users set user_handle = ${handle} where id = ${u.id}`;
            } else if (normalized !== handle) {
                // 大小寫或空白差異，嘗試標準化
                const taken = await sql`select id from users where user_handle = ${normalized} and id <> ${u.id} limit 1`;
                if (!taken.length) {
                    handle = normalized;
                    await sql`update users set user_handle = ${handle} where id = ${u.id}`;
                }
            }
        }
        return { id: u.id, username: u.username, email: u.email, avatar: u.avatar_data, handle };
    }

    async resendVerificationCode(email) {
        await this._init;
        const rows = await sql`select id, is_verified from users where email = ${email}`;
        if (!rows.length || rows[0].is_verified) throw new Error('USER_NOT_FOUND_OR_VERIFIED');
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const verificationExpires = Date.now() + 15 * 60 * 1000;
        await sql`update users set verification_code = ${verificationCode}, verification_expires = ${verificationExpires}, updated_at = now() where email = ${email}`;
        return { verificationCode, verificationExpires };
    }

    async getUserById(id) {
        await this._init;
        const rows = await sql`select id, username, email, avatar_data, is_verified, user_handle from users where id = ${id}`;
        if (!rows.length) throw new Error('USER_NOT_FOUND');
        const u = rows[0];
        // handle 為 null：保留，前端會引導首次設定
        let handle = u.user_handle;
        if (handle != null) {
            const normalized = normalizeHandleInput(handle);
            if (!isValidHandlePattern(normalized)) {
                const base = createBaseHandle(u.username);
                handle = await generateUniqueHandle(base, u.id);
                await sql`update users set user_handle = ${handle} where id = ${u.id}`;
            } else if (normalized !== handle) {
                const taken = await sql`select id from users where user_handle = ${normalized} and id <> ${u.id} limit 1`;
                if (!taken.length) {
                    handle = normalized;
                    await sql`update users set user_handle = ${handle} where id = ${u.id}`;
                }
            }
        }
        return { id: u.id, username: u.username, email: u.email, avatar: u.avatar_data, isVerified: u.is_verified, handle };
    }

    // 更新使用者暱稱與頭像；不再自動調整 handle（使用者於註冊時自訂）
    async updateUserProfile(userId, { username, avatarData }) {
        await this._init;
        const rows = await sql`
            update users
            set username = ${username},
                avatar_data = ${avatarData || null},
                updated_at = now()
            where id = ${userId}
            returning id, username, email, avatar_data, is_verified, user_handle
        `;
        const u = rows[0];
        return { id: u.id, username: u.username, email: u.email, avatar: u.avatar_data, isVerified: u.is_verified, handle: u.user_handle };
    }

    async isHandleAvailable(handle) {
        await this._init;
        const normalized = normalizeHandleInput(handle);
        if (!normalized || !isValidHandlePattern(normalized)) return { available: false, reason: 'INVALID' };
        const rows = await sql`select id from users where user_handle = ${normalized} limit 1`;
        return { available: rows.length === 0 };
    }

    async close() {}

    // ====== Friends ======
    async findUserByHandle(handle) {
        await this._init;
        const normalized = normalizeHandleInput(handle);
        const rows = await sql`select id, username, email, avatar_data, user_handle from users where user_handle = ${normalized}`;
        return rows[0] || null;
    }

    async createFriendRequest(requesterId, targetHandle) {
        await this._init;
        const target = await this.findUserByHandle(targetHandle);
        if (!target) throw new Error('USER_NOT_FOUND');
        if (target.id === requesterId) throw new Error('CANNOT_ADD_SELF');
        // 已存在的待處理或已是好友
        const existing = await sql`
            select id, status from friend_requests
            where (requester_id = ${requesterId} and target_user_id = ${target.id})
               or (requester_id = ${target.id} and target_user_id = ${requesterId})
            order by id desc limit 1`;
        if (existing.length) {
            const st = existing[0].status;
            if (st === 'pending') throw new Error('ALREADY_PENDING');
            if (st === 'accepted') throw new Error('ALREADY_FRIENDS');
        }
        const rows = await sql`
            insert into friend_requests (requester_id, target_user_id, status)
            values (${requesterId}, ${target.id}, 'pending')
            returning id
        `;
        return { requestId: rows[0].id, targetUserId: target.id };
    }

    async getIncomingFriendRequests(userId) {
        await this._init;
        const rows = await sql`
            select fr.id, fr.requester_id as from_id, u.username as from_username, u.avatar_data as from_avatar, u.user_handle as from_handle, fr.created_at
            from friend_requests fr
            join users u on u.id = fr.requester_id
            where fr.target_user_id = ${userId} and fr.status = 'pending'
            order by fr.created_at desc`;
        return rows.map(r => ({ id: r.id, from: { id: r.from_id, username: r.from_username, avatar: r.from_avatar, handle: r.from_handle }, createdAt: r.created_at }));
    }

    async respondFriendRequest(userId, requestId, action) {
        await this._init;
        const rows = await sql`select id, requester_id, target_user_id, status from friend_requests where id = ${requestId}`;
        if (!rows.length) throw new Error('REQUEST_NOT_FOUND');
        const r = rows[0];
        if (r.target_user_id !== userId) throw new Error('FORBIDDEN');
        if (r.status !== 'pending') throw new Error('ALREADY_HANDLED');
        const status = action === 'accept' ? 'accepted' : 'rejected';
        await sql`update friend_requests set status = ${status}, responded_at = now() where id = ${requestId}`;
        return { status };
    }

    async getFriends(userId) {
        await this._init;
        const rows = await sql`
            select u.id, u.username, u.avatar_data, u.user_handle
            from friend_requests fr
            join users u on u.id = case when fr.requester_id = ${userId} then fr.target_user_id else fr.requester_id end
            where (fr.requester_id = ${userId} or fr.target_user_id = ${userId})
              and fr.status = 'accepted'
            order by u.username asc`;
        return rows.map(r => ({ id: r.id, username: r.username, avatar: r.avatar_data, handle: r.user_handle }));
    }

    // ====== Messaging ======
    async sendMessage(senderId, toUserId, content, clientId = null, imageData = null, imageMime = null) {
        await this._init;
        const receiverId = Number(toUserId);
        const text = (content || '').toString();
        const hasImage = !!(imageData && String(imageData).length);
        if (!Number.isFinite(receiverId) || (!text.trim() && !hasImage)) {
            throw new Error('INVALID_INPUT');
        }
        let rows;
        if (clientId) {
            rows = await sql`
                insert into messages (sender_id, receiver_id, content, client_id, image_data, image_mime)
                values (${senderId}, ${receiverId}, ${text}, ${clientId}, ${hasImage ? imageData : null}, ${hasImage ? imageMime : null})
                on conflict (client_id) do nothing
                returning id, created_at`;
            if (!rows.length) {
                // 已存在相同 client_id，查詢其 id
                rows = await sql`select id, created_at from messages where client_id = ${clientId} limit 1`;
            }
        } else {
            rows = await sql`insert into messages (sender_id, receiver_id, content, image_data, image_mime) values (${senderId}, ${receiverId}, ${text}, ${hasImage ? imageData : null}, ${hasImage ? imageMime : null}) returning id, created_at`;
        }
        return { id: rows[0].id, createdAt: rows[0].created_at };
    }

    // ====== Groups ======
    async createGroup(ownerId, name, memberIds = [], avatarData = null) {
        await this._init;
        const groupName = (name || '').toString().trim();
        if (!groupName) throw new Error('INVALID_NAME');
        // 建立群組
        const gRows = await sql`insert into groups (name, owner_id, avatar_data) values (${groupName}, ${ownerId}, ${avatarData || null}) returning id`;
        const groupId = gRows[0].id;
        // 成員去重，確保包含建立者
        const uniqueIds = new Set([Number(ownerId), ...memberIds.map(n => Number(n)).filter(Number.isFinite)]);
        for (const uid of uniqueIds) {
            await sql`insert into group_members (group_id, user_id) values (${groupId}, ${uid}) on conflict (group_id, user_id) do nothing`;
        }
        return { id: groupId };
    }

    async getUserGroups(userId) {
        await this._init;
        const rows = await sql`
            select g.id, g.name, g.avatar_data
            from group_members gm
            join groups g on g.id = gm.group_id
            where gm.user_id = ${userId}
            order by g.created_at desc
        `;
        return rows.map(r => ({ id: r.id, name: r.name, avatar: r.avatar_data }));
    }

    async getGroupMemberIds(groupId) {
        await this._init;
        const rows = await sql`select user_id from group_members where group_id = ${groupId}`;
        return rows.map(r => r.user_id);
    }

    async assertGroupMember(userId, groupId) {
        const rows = await sql`select 1 from group_members where user_id = ${userId} and group_id = ${groupId} limit 1`;
        if (!rows.length) throw new Error('NOT_GROUP_MEMBER');
    }

    async sendGroupMessage(senderId, groupId, content, clientId = null, imageData = null, imageMime = null) {
        await this._init;
        const gid = Number(groupId);
        const text = (content || '').toString();
        const hasImage = !!(imageData && String(imageData).length);
        if (!Number.isFinite(gid) || (!text.trim() && !hasImage)) throw new Error('INVALID_INPUT');
        await this.assertGroupMember(senderId, gid);
        let rows;
        if (clientId) {
            rows = await sql`
                insert into group_messages (group_id, sender_id, content, client_id, image_data, image_mime)
                values (${gid}, ${senderId}, ${text}, ${clientId}, ${hasImage ? imageData : null}, ${hasImage ? imageMime : null})
                on conflict (client_id) do nothing
                returning id, created_at
            `;
            if (!rows.length) rows = await sql`select id, created_at from group_messages where client_id = ${clientId} limit 1`;
        } else {
            rows = await sql`insert into group_messages (group_id, sender_id, content, image_data, image_mime) values (${gid}, ${senderId}, ${text}, ${hasImage ? imageData : null}, ${hasImage ? imageMime : null}) returning id, created_at`;
        }
        return { id: rows[0].id, createdAt: rows[0].created_at };
    }

    async getGroupMessages(userId, groupId, limit = 50, beforeId = null, afterId = null) {
        await this._init;
        const gid = Number(groupId);
        if (!Number.isFinite(gid)) throw new Error('BAD_GROUP');
        await this.assertGroupMember(userId, gid);
        const safeLimit = Math.max(1, Math.min(200, Number(limit) || 50));
        let rows;
        if (afterId != null) {
            rows = await sql`
                select gm.id, gm.group_id, gm.sender_id, gm.content, gm.created_at, gm.image_data, gm.image_mime,
                       u.username as sender_name, u.avatar_data as sender_avatar
                from group_messages gm
                join users u on u.id = gm.sender_id
                where gm.group_id = ${gid} and gm.id > ${afterId}
                order by gm.id asc
                limit ${safeLimit}
            `;
            return rows;
        } else if (beforeId != null) {
            rows = await sql`
                select gm.id, gm.group_id, gm.sender_id, gm.content, gm.created_at, gm.image_data, gm.image_mime,
                       u.username as sender_name, u.avatar_data as sender_avatar
                from group_messages gm
                join users u on u.id = gm.sender_id
                where gm.group_id = ${gid} and gm.id < ${beforeId}
                order by gm.id desc
                limit ${safeLimit}
            `;
            return rows.reverse();
        } else {
            rows = await sql`
                select gm.id, gm.group_id, gm.sender_id, gm.content, gm.created_at, gm.image_data, gm.image_mime,
                       u.username as sender_name, u.avatar_data as sender_avatar
                from group_messages gm
                join users u on u.id = gm.sender_id
                where gm.group_id = ${gid}
                order by gm.id desc
                limit ${safeLimit}
            `;
            return rows.reverse();
        }
    }
    async getMessages(userId, withUserId, limit = 50, beforeId = null, afterId = null) {
        await this._init;
        const safeLimit = Math.max(1, Math.min(200, Number(limit) || 50));
        let rows;
        if (afterId != null) {
            rows = await sql`
                select m.id, m.sender_id, m.receiver_id, m.content, m.created_at, m.seen_at, m.image_data, m.image_mime
                from messages m
                where ((m.sender_id = ${userId} and m.receiver_id = ${withUserId})
                   or  (m.sender_id = ${withUserId} and m.receiver_id = ${userId}))
                  and m.id > ${afterId}
                order by m.id asc
                limit ${safeLimit}`;
            return rows; // already asc for incremental append
        } else if (beforeId != null) {
            rows = await sql`
                select m.id, m.sender_id, m.receiver_id, m.content, m.created_at, m.seen_at, m.image_data, m.image_mime
                from messages m
                where ((m.sender_id = ${userId} and m.receiver_id = ${withUserId})
                   or  (m.sender_id = ${withUserId} and m.receiver_id = ${userId}))
                  and m.id < ${beforeId}
                order by m.id desc
                limit ${safeLimit}`;
            return rows.reverse();
        } else {
            rows = await sql`
                select m.id, m.sender_id, m.receiver_id, m.content, m.created_at, m.seen_at, m.image_data, m.image_mime
                from messages m
                where (m.sender_id = ${userId} and m.receiver_id = ${withUserId})
                   or  (m.sender_id = ${withUserId} and m.receiver_id = ${userId})
                order by m.id desc
                limit ${safeLimit}`;
            return rows.reverse();
        }
    }

    async markMessagesRead(userId, withUserId) {
        await this._init;
        await sql`update messages set seen_at = now() where sender_id = ${withUserId} and receiver_id = ${userId} and seen_at is null`;
        return { success: true };
    }
}

module.exports = Database;
