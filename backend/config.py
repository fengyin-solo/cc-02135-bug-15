"""应用配置"""
import os

PORT = int(os.getenv('PORT', 8636))
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', '/app/uploads')
DB_FILE = os.getenv('DB_FILE', '/app/data/app.db')

# Token 有效期：全系统唯一的令牌时长标准（5 分钟），登录与刷新共用
TOKEN_EXPIRE_SECONDS = int(os.getenv('TOKEN_EXPIRE_SECONDS', 300))

# 登录限流：同一账号在固定窗口内最多连续失败次数（第 6 次起直接锁定到窗口结束）
RATE_LIMIT_REQUESTS = int(os.getenv('RATE_LIMIT_REQUESTS', 5))
RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW', 60))

MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 52428800))  # 50MB

BLOCKED_EXTENSIONS = {'exe', 'sh', 'bat', 'cmd', 'ps1', 'py', 'php', 'jsp', 'cgi', 'pl'}

SHARE_LINK_EXPIRE_HOURS = int(os.getenv('SHARE_LINK_EXPIRE_HOURS', 24))
SHARE_LINK_MAX_DOWNLOADS = int(os.getenv('SHARE_LINK_MAX_DOWNLOADS', 10))

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
