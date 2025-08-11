// 郵件服務配置範例文件
// 請複製此文件為 config.js 並填入您的真實配置

module.exports = {
    // 郵件服務配置 (Gmail 範例)
    email: {
        host: 'smtp.gmail.com',
        port: 587,
        secure: false, // true for 465, false for other ports
        auth: {
            user: 'your-email@gmail.com', // 您的Gmail地址
            pass: 'your-app-password'     // Gmail應用程式密碼 (不是登入密碼)
        },
        from: {
            email: 'your-email@gmail.com',
            name: 'FayCR連線室'
        }
    },
    
    // 服務器配置
    server: {
        port: 3001,
        jwtSecret: 'your-super-secret-jwt-key-here-change-this',
        corsOrigin: 'http://localhost:8080'
    },
    
    // 數據庫配置
    database: {
        filename: './faycr_users.db'
    }
};

// Gmail 設置說明：
// 1. 開啟 Gmail 的 2 步驟驗證
// 2. 生成應用程式密碼：https://myaccount.google.com/apppasswords
// 3. 將應用程式密碼填入上面的 'pass' 欄位
