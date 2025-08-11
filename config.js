// FayCR連線室後端配置文件
// 請根據您的實際環境修改以下配置

module.exports = {
    // 郵件服務配置（改由環境變數控制，Vercel 上設定）
    email: {
        host: process.env.EMAIL_HOST || 'smtp.gmail.com',
        port: Number(process.env.EMAIL_PORT || 587),
        secure: String(process.env.EMAIL_SECURE || 'false') === 'true',
        auth: {
            user: process.env.EMAIL_USER || '',
            pass: process.env.EMAIL_PASS || ''
        },
        from: {
            email: process.env.EMAIL_FROM || process.env.EMAIL_USER || '',
            name: process.env.EMAIL_FROM_NAME || 'FayCRChat'
        }
    },
    
    // 服務器配置
    server: {
        port: Number(process.env.PORT || 8080),
        jwtSecret: process.env.JWT_SECRET || 'please_set_JWT_SECRET_in_env',
        corsOrigin: process.env.CORS_ORIGIN || ''
    },
    
    // 數據庫配置（Vercel KV 使用，不需要路徑）
    database: {
        filename: ''
    }
};

// 部署到 Vercel 時，請在專案的 Environment Variables 中設定：
// EMAIL_HOST, EMAIL_PORT, EMAIL_SECURE, EMAIL_USER, EMAIL_PASS, EMAIL_FROM, EMAIL_FROM_NAME, JWT_SECRET, CORS_ORIGIN
