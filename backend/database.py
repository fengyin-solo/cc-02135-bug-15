"""数据库操作"""
import sqlite3
import hashlib
from config import DB_FILE


def get_db():
    """获取数据库连接"""
    conn = sqlite3.connect(DB_FILE, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """初始化数据库表"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            path TEXT NOT NULL,
            size INTEGER NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at REAL NOT NULL
        )
    ''')

    # 登录失败计数：按账号记录固定窗口，多进程/重试均以同一行为准
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_failures (
            username TEXT PRIMARY KEY,
            window_started_at REAL NOT NULL,
            fail_count INTEGER NOT NULL DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS share_links (
            id TEXT PRIMARY KEY,
            file_id TEXT NOT NULL,
            created_by TEXT NOT NULL,
            expires_at REAL,
            max_downloads INTEGER,
            download_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
        )
    ''')

    default_users = [
        ('admin', hashlib.sha256('admin123'.encode()).hexdigest()),
        ('user', hashlib.sha256('user123'.encode()).hexdigest()),
        ('test', hashlib.sha256('test123'.encode()).hexdigest())
    ]
    for username, password_hash in default_users:
        cursor.execute(
            'INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)',
            (username, password_hash)
        )

    conn.commit()
    conn.close()
