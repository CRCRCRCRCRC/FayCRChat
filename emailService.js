const nodemailer = require('nodemailer');

class EmailService {
    constructor(config) {
        this.config = config;
        this.transporter = null;
        this.initializeTransporter();
    }

    // 初始化郵件傳輸器
    async initializeTransporter() {
        try {
            this.transporter = nodemailer.createTransport({
                host: this.config.host,
                port: this.config.port,
                secure: this.config.secure || false,
                auth: {
                    user: this.config.auth.user,
                    pass: this.config.auth.pass
                },
                tls: {
                    rejectUnauthorized: false // 允許自簽名證書
                }
            });

            // 驗證郵件配置
            await this.transporter.verify();
            console.log('✅ 郵件服務已就緒');
        } catch (error) {
            console.error('❌ 郵件服務初始化失敗:', error.message);
            console.log('請檢查您的郵件配置設置');
        }
    }

    // 發送驗證碼郵件
    async sendVerificationEmail(to, username, verificationCode) {
        if (!this.transporter) {
            throw new Error('郵件服務未初始化');
        }

        const mailOptions = {
            from: {
                name: this.config.from.name,
                address: this.config.from.email
            },
            to: to,
            subject: '🔐 FayCRChat - 電子郵件驗證',
            html: this.generateVerificationEmailHTML(username, verificationCode),
            text: this.generateVerificationEmailText(username, verificationCode)
        };

        try {
            const info = await this.transporter.sendMail(mailOptions);
            console.log('✅ 驗證郵件已發送:', info.messageId);
            return {
                success: true,
                messageId: info.messageId,
                to: to
            };
        } catch (error) {
            console.error('❌ 發送驗證郵件失敗:', error);
            throw new Error('郵件發送失敗: ' + error.message);
        }
    }

    // 生成驗證郵件HTML內容
    generateVerificationEmailHTML(username, code) {
        return `
        <!DOCTYPE html>
        <html lang="zh-TW">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>FayCRChat - 電子郵件驗證</title>
            <style>
                body {
                    font-family: 'Arial', 'Microsoft JhengHei', sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                }
                .container {
                    background: white;
                    border-radius: 20px;
                    padding: 40px;
                    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                }
                .header {
                    text-align: center;
                    margin-bottom: 30px;
                }
                .logo {
                    font-size: 28px;
                    font-weight: bold;
                    background: linear-gradient(45deg, #667eea, #764ba2);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    background-clip: text;
                    margin-bottom: 10px;
                }
                .title {
                    color: #2d3748;
                    font-size: 24px;
                    margin: 20px 0;
                }
                .content {
                    text-align: center;
                    margin: 30px 0;
                }
                .verification-code {
                    font-size: 36px;
                    font-weight: bold;
                    color: #667eea;
                    background: #f7fafc;
                    padding: 20px;
                    border-radius: 15px;
                    margin: 20px 0;
                    letter-spacing: 8px;
                    border: 2px dashed #667eea;
                }
                .warning {
                    background: #fef2f2;
                    border: 1px solid #fecaca;
                    color: #dc2626;
                    padding: 15px;
                    border-radius: 10px;
                    margin: 20px 0;
                    font-size: 14px;
                }
                .footer {
                    text-align: center;
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #e2e8f0;
                    color: #64748b;
                    font-size: 14px;
                }
                .button {
                    display: inline-block;
                    background: linear-gradient(45deg, #667eea, #764ba2);
                    color: white;
                    padding: 15px 30px;
                    text-decoration: none;
                    border-radius: 10px;
                    font-weight: bold;
                    margin: 20px 0;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">🌐 FayCRChat</div>
                    <h1 class="title">電子郵件驗證</h1>
                </div>
                
                <div class="content">
                    <p>親愛的 <strong>${username}</strong>，</p>
                    <p>歡迎加入 FayCRChat！請使用以下驗證碼完成您的帳號註冊：</p>
                    
                    <div class="verification-code">${code}</div>
                    
                    <p>請在 <strong>15 分鐘內</strong> 輸入此驗證碼。</p>
                    
                    <div class="warning">
                        ⚠️ <strong>重要提醒：</strong><br>
                        • 此驗證碼將在15分鐘後失效<br>
                        • 請勿將驗證碼分享給他人<br>
                        • 如果您沒有註冊此帳號，請忽略此郵件
                    </div>
                </div>
                
                <div class="footer">
                    <p>這是一封自動發送的郵件，請勿直接回覆。</p>
                    <p>如有問題，請聯繫我們的客服團隊。</p>
                    <p>&copy; 2024 FayCRChat. 保留所有權利.</p>
                </div>
            </div>
        </body>
        </html>
        `;
    }

    // 生成驗證郵件純文字內容
    generateVerificationEmailText(username, code) {
        return `
FayCRChat - 電子郵件驗證

親愛的 ${username}，

歡迎加入 FayCRChat！請使用以下驗證碼完成您的帳號註冊：

驗證碼：${code}

請在 15 分鐘內輸入此驗證碼。

重要提醒：
- 此驗證碼將在15分鐘後失效
- 請勿將驗證碼分享給他人
- 如果您沒有註冊此帳號，請忽略此郵件

這是一封自動發送的郵件，請勿直接回覆。
如有問題，請聯繫我們的客服團隊。

© 2024 FayCRChat. 保留所有權利.
        `;
    }

    // 發送歡迎郵件
    async sendWelcomeEmail(to, username) {
        if (!this.transporter) {
            throw new Error('郵件服務未初始化');
        }

        const mailOptions = {
            from: {
                name: this.config.from.name,
                address: this.config.from.email
            },
            to: to,
            subject: '🎉 歡迎加入 FayCRChat！',
            html: this.generateWelcomeEmailHTML(username),
            text: `歡迎加入 FayCR連線室，${username}！您的帳號已成功註冊並驗證。`
        };

        try {
            const info = await this.transporter.sendMail(mailOptions);
            console.log('✅ 歡迎郵件已發送:', info.messageId);
            return {
                success: true,
                messageId: info.messageId
            };
        } catch (error) {
            console.error('❌ 發送歡迎郵件失敗:', error);
            // 歡迎郵件失敗不應該影響主要流程
            return { success: false, error: error.message };
        }
    }

    // 生成歡迎郵件HTML內容
    generateWelcomeEmailHTML(username) {
        return `
        <!DOCTYPE html>
        <html lang="zh-TW">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>歡迎加入 FayCRChat</title>
            <style>
                body {
                    font-family: 'Arial', 'Microsoft JhengHei', sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                }
                .container {
                    background: white;
                    border-radius: 20px;
                    padding: 40px;
                    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                    text-align: center;
                }
                .logo {
                    font-size: 32px;
                    font-weight: bold;
                    background: linear-gradient(45deg, #667eea, #764ba2);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    background-clip: text;
                    margin-bottom: 20px;
                }
                .celebration {
                    font-size: 48px;
                    margin: 20px 0;
                }
                .title {
                    color: #2d3748;
                    font-size: 28px;
                    margin: 20px 0;
                }
                .message {
                    color: #4a5568;
                    font-size: 18px;
                    margin: 20px 0;
                }
                .footer {
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #e2e8f0;
                    color: #64748b;
                    font-size: 14px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">🌐 FayCRChat</div>
                <div class="celebration">🎉</div>
                <h1 class="title">歡迎加入我們！</h1>
                <p class="message">
                    親愛的 <strong>${username}</strong>，<br>
                    恭喜您成功註冊 FayCRChat！<br>
                    您的帳號已經驗證完成，現在可以開始享受我們的服務了。
                </p>
                <div class="footer">
                    <p>感謝您選擇 FayCRChat</p>
                    <p>&copy; 2024 FayCRChat. 保留所有權利.</p>
                </div>
            </div>
        </body>
        </html>
        `;
    }

    // 測試郵件服務
    async testConnection() {
        try {
            if (!this.transporter) {
                throw new Error('郵件服務未初始化');
            }
            await this.transporter.verify();
            return { success: true, message: '郵件服務連接正常' };
        } catch (error) {
            return { success: false, message: error.message };
        }
    }
}

module.exports = EmailService;
