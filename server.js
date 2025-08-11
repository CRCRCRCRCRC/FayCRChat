const app = require('./app');
const config = require('./config');
const PORT = config.server.port || 8080;

const server = app.listen(PORT, () => {
    console.log(`🚀 本地服務已啟動：http://localhost:${PORT}`);
});

// 優雅關閉
process.on('SIGINT', () => server.close(() => process.exit(0)));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
