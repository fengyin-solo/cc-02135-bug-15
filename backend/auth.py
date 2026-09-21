"""认证相关功能

统一规则（登录校验、令牌存储、频率计数、页面恢复共用同一套标准）：
- 限流：按账号统计“连续登录失败”次数，固定窗口从首次失败起算，窗口结束即清零；
  成功登录立即清零；网络重试命中同一条失败记录，不重复计时、不延长窗口。
- 令牌：以 tokens 表行为唯一标准，expires_at > now 才有效；过期即删除。
- 刷新：原子轮换——同一事务内插入新令牌并删除旧令牌，旧令牌刷新后立即失效；
  并发刷新最多一方成功。
- 退出：服务端删除令牌，所有入口以同一标准重新判定。
"""
import math
import uuid
import time
import hashlib
from functools import wraps
from flask import request, jsonify
from database import get_db
from config import TOKEN_EXPIRE_SECONDS, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW


# ---------------------------------------------------------------------------
# 登录限流：连续失败计数（持久化，多 worker / 重试看到的是同一份计数与窗口）
# ---------------------------------------------------------------------------

# 兼容旧代码/测试中的内存存储引用；真实计数以 login_failures 表为准
rate_limit_store = {}


def _login_key(username):
    """限流标识：规范化后的账号名"""
    return username.strip().lower()


def _login_failures(conn, key, now):
    """读取当前窗口内的失败计数与窗口起点；过期窗口视为未开始（不落库）"""
    cursor = conn.cursor()
    cursor.execute(
        'SELECT window_started_at, fail_count FROM login_failures WHERE username = ?',
        (key,)
    )
    row = cursor.fetchone()
    if not row:
        return 0.0, 0

    window_started_at, fail_count = row['window_started_at'], row['fail_count']
    if now - window_started_at >= RATE_LIMIT_WINDOW:
        # 窗口已结束：边界时点（恰好满窗口）即放行，由后续登录重新开始计数
        return 0.0, 0
    return window_started_at, fail_count


def login_lock_status(username):
    """返回账号当前限流状态：(fail_count, retry_after_seconds)

    retry_after > 0 表示窗口内失败次数已达上限，必须等待该秒数。
    全系统剩余等待时间统一由窗口起点 + 窗口长度推算，不随请求次数变化。
    """
    now = time.time()
    conn = get_db()
    window_started_at, fail_count = _login_failures(conn, _login_key(username), now)
    conn.close()

    if window_started_at and fail_count >= RATE_LIMIT_REQUESTS:
        retry_after = math.ceil(window_started_at + RATE_LIMIT_WINDOW - now)
        return fail_count, max(retry_after, 1)
    return fail_count, 0


def record_login_failure(username):
    """记录一次登录失败，返回 (fail_count, retry_after_seconds)

    固定窗口：窗口起点是首次失败的时间，后续失败不再重置起点，
    因而重试不会重复计时、不会延长等待。
    """
    key = _login_key(username)
    now = time.time()
    conn = get_db()
    # 立即拿写锁：多个 worker / 并发重试串行提交，计数不会丢失或重复开窗口
    conn.isolation_level = None
    try:
        conn.execute('BEGIN IMMEDIATE')
        window_started_at, fail_count = _login_failures(conn, key, now)

        if fail_count == 0:
            # 新窗口从这一次失败起算
            window_started_at, fail_count = now, 1
        else:
            fail_count += 1

        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO login_failures (username, window_started_at, fail_count)
            VALUES (?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                window_started_at = excluded.window_started_at,
                fail_count = excluded.fail_count
        ''', (key, window_started_at, fail_count))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    if fail_count >= RATE_LIMIT_REQUESTS:
        retry_after = math.ceil(window_started_at + RATE_LIMIT_WINDOW - now)
        return fail_count, max(retry_after, 1)
    return fail_count, 0


def reset_login_failures(username):
    """成功登录后清零该账号的失败计数"""
    conn = get_db()
    conn.cursor().execute(
        'DELETE FROM login_failures WHERE username = ?',
        (_login_key(username),)
    )
    conn.commit()
    conn.close()


def clear_login_failures():
    """清空全部失败计数（测试隔离用）"""
    conn = get_db()
    conn.cursor().execute('DELETE FROM login_failures')
    conn.commit()
    conn.close()


def rate_limit(f):
    """速率限制装饰器（保留兼容；登录限流改由 login_lock_status 处理）"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------------------------
# 令牌存储与校验：以 tokens 表行 + expires_at 为唯一标准
# ---------------------------------------------------------------------------

def generate_token(username):
    """生成并存储 token"""
    token = str(uuid.uuid4())
    expires_at = time.time() + TOKEN_EXPIRE_SECONDS

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT OR REPLACE INTO tokens (token, username, expires_at) VALUES (?, ?, ?)',
        (token, username, expires_at)
    )
    conn.commit()
    conn.close()
    return token


def _get_token_session(conn, token):
    """读取令牌会话。统一的有效判定：行存在且 expires_at > now；过期即删除"""
    now = time.time()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT username, expires_at FROM tokens WHERE token = ?',
        (token,)
    )
    row = cursor.fetchone()

    if row and row['expires_at'] > now:
        return row

    if row:
        # 过期令牌立即清除，避免边界时点被继续放行
        cursor.execute('DELETE FROM tokens WHERE token = ?', (token,))
        conn.commit()
    return None


def verify_token(token):
    """验证 token 是否有效"""
    if not token:
        return False
    conn = get_db()
    row = _get_token_session(conn, token)
    conn.close()
    return row is not None


def rotate_token(token):
    """刷新令牌：原子轮换为新令牌，旧令牌立即失效。

    并发刷新在同一事务内竞争：读到旧令牌、删除旧令牌、写入新令牌。
    后到的请求在删除旧令牌后无法再查到它，返回 None（401），
    因此不会出现旧令牌与新令牌同时可用。
    """
    if not token:
        return None

    conn = get_db()
    conn.isolation_level = None
    try:
        # 单连接立即事务，配合 busy timeout 保证并发刷新串行提交
        conn.execute('BEGIN IMMEDIATE')
        cursor = conn.cursor()
        cursor.execute(
            'SELECT username, expires_at FROM tokens WHERE token = ?',
            (token,)
        )
        row = cursor.fetchone()

        if not row or row['expires_at'] <= time.time():
            # 无效或已过期：删除残留行，不发放新令牌
            cursor.execute('DELETE FROM tokens WHERE token = ?', (token,))
            conn.commit()
            return None

        new_token = str(uuid.uuid4())
        new_expires = time.time() + TOKEN_EXPIRE_SECONDS
        cursor.execute('DELETE FROM tokens WHERE token = ?', (token,))
        cursor.execute(
            'INSERT INTO tokens (token, username, expires_at) VALUES (?, ?, ?)',
            (new_token, row['username'], new_expires)
        )
        conn.commit()
        return {'token': new_token, 'expires_at': new_expires}
    except Exception:
        conn.rollback()
        return None
    finally:
        conn.close()


# 兼容旧命名
def refresh_token(token):
    return rotate_token(token)


def revoke_token(token):
    """退出登录：删除令牌。无效/不存在同样视为已退出（幂等）"""
    if not token:
        return
    conn = get_db()
    conn.cursor().execute('DELETE FROM tokens WHERE token = ?', (token,))
    conn.commit()
    conn.close()


def get_username_from_token(token):
    """从有效 token 获取用户名，无效返回 None"""
    if not token:
        return None
    conn = get_db()
    row = _get_token_session(conn, token)
    username = row['username'] if row else None
    conn.close()
    return username


def extract_token():
    """从请求中提取 token（Authorization: Bearer 优先，查询参数兼容）"""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:].strip()
        if token:
            return token
    return request.args.get('token')


def login_required(f):
    """登录认证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = extract_token()
        if not token or not verify_token(token):
            return jsonify({'error': '未授权或token已过期'}), 401

        return f(*args, **kwargs)
    return decorated_function


def authenticate_user(username, password):
    """验证用户凭据"""
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id FROM users WHERE username = ? AND password_hash = ?',
        (username, password_hash)
    )
    user = cursor.fetchone()
    conn.close()
    return user is not None
