"""认证与会话管理。

本模块是全应用唯一的限流判定与令牌判定标准来源：

- 登录限流：只对“凭据校验失败”的登录请求计数（滑动窗口），成功登录清零，
  参数错误 / 被限流 / 网络层失败一律不计数，因此网络重试不会重复计时，
  连续输错后输入正确密码不会被误限。判定与剩余等待时间在同一把锁内计算，
  所有页面看到的剩余秒数完全一致。
- 令牌存储：一个用户同一时刻只保留一个有效令牌；刷新采用原子轮换
  （旧令牌立即作废，只放行一个并发刷新）；所有入口共用同一条边界规则
  ``expires_at > now``，恰好到期即失效。
"""
import math
import time
import uuid
import hashlib
import threading
from functools import wraps

from flask import request, jsonify, g

from database import get_db
from config import TOKEN_EXPIRE_SECONDS, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW


# ---------------------------------------------------------------------------
# 登录失败计数（滑动窗口）
# ---------------------------------------------------------------------------

_rate_lock = threading.Lock()
# identifier（客户端标识）-> 历次凭据校验失败的时间戳列表
_login_failures = {}


def _prune_failures(timestamps, now):
    """丢弃已经滑出窗口的失败记录。

    边界规则统一为：失败时刻距现在“恰好”达到整个窗口时长（>=）即失效，
    与令牌的严格大于判定保持同一种边界口径。
    """
    return [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]


def login_rate_status(identifier):
    """返回当前限流状态 ``(is_limited, retry_after_seconds)``。

    只读判定，不写入任何记录：被限流的请求本身不占额度，重复提交 /
    网络重试不会延长等待时间。剩余时间与放行结论在同一把锁内基于同一份
    数据计算，保证各个页面拿到的等待秒数一致。
    """
    now = time.time()
    with _rate_lock:
        timestamps = _prune_failures(_login_failures.get(identifier, []), now)
        _login_failures[identifier] = timestamps

        if len(timestamps) >= RATE_LIMIT_REQUESTS:
            # 最早一次失败滑出窗口之时即为解锁时刻
            remaining = RATE_LIMIT_WINDOW - (now - timestamps[0])
            return True, max(1, int(math.ceil(remaining)))
        return False, 0


def record_login_failure(identifier):
    """记录一次“凭据校验失败”的登录尝试。"""
    now = time.time()
    with _rate_lock:
        timestamps = _prune_failures(_login_failures.get(identifier, []), now)
        timestamps.append(now)
        _login_failures[identifier] = timestamps


def reset_login_failures(identifier):
    """登录成功后清空失败计数，既往失败不带入新的会话。"""
    with _rate_lock:
        _login_failures.pop(identifier, None)


# ---------------------------------------------------------------------------
# 令牌存储：唯一的有效性标准
# ---------------------------------------------------------------------------

def _new_token():
    return uuid.uuid4().hex


def generate_token(username):
    """登录成功后签发令牌。

    同一用户只保留一个有效令牌：重新登录会让此前签发的令牌立即失效，
    避免旧令牌在到期前一直残留可用。
    """
    token = _new_token()
    now = time.time()
    expires_at = now + TOKEN_EXPIRE_SECONDS

    conn = get_db()
    try:
        conn.isolation_level = None  # 显式事务
        cursor = conn.cursor()
        cursor.execute('BEGIN IMMEDIATE')
        cursor.execute('DELETE FROM tokens WHERE username = ?', (username,))
        cursor.execute(
            'INSERT INTO tokens (token, username, expires_at) VALUES (?, ?, ?)',
            (token, username, expires_at)
        )
        conn.commit()
    finally:
        conn.close()
    return token


def _load_valid_session(cursor, token, now):
    """在给定游标上按唯一标准读取会话：行存在且 ``expires_at`` 严格大于 now。

    恰好到期（expires_at == now）或已过期的令牌就地删除。
    """
    cursor.execute(
        'SELECT username, expires_at FROM tokens WHERE token = ?',
        (token,)
    )
    row = cursor.fetchone()
    if row is None:
        return None
    if row['expires_at'] > now:
        return row
    cursor.execute('DELETE FROM tokens WHERE token = ?', (token,))
    return None


def get_token_session(token):
    """校验令牌并返回会话信息（username / expires_at），无效返回 None。

    这是全应用唯一的令牌有效性标准，登录态判定、下载鉴权、刷新、退出
    全部经由本函数（或同一 SQL 标准），边界时点不会一处放行、一处拒绝。
    """
    if not token:
        return None

    now = time.time()
    conn = get_db()
    try:
        cursor = conn.cursor()
        row = _load_valid_session(cursor, token, now)
        conn.commit()  # 提交可能发生的过期令牌清理
        if row is None:
            return None
        return {'username': row['username'], 'expires_at': row['expires_at']}
    finally:
        conn.close()


def verify_token(token):
    """令牌是否有效（与 get_token_session 同一标准）。"""
    return get_token_session(token) is not None


def get_username_from_token(token):
    """从有效令牌获取用户名，无效返回 None（与鉴权装饰器同一标准）。"""
    session = get_token_session(token)
    return session['username'] if session else None


def rotate_token(old_token):
    """原子刷新：把旧令牌轮换为新令牌，旧令牌立即作废。

    借助 ``BEGIN IMMEDIATE`` 写锁串行化并发刷新：同一旧令牌无论被并发
    刷新多少次，只有一个请求能完成轮换并拿到新令牌，其余请求在锁释放后
    查不到旧令牌而失败——旧令牌不会偶尔继续可用，也不会重复计时。
    边界时点同样使用严格大于，恰好到期的令牌不能刷新。
    """
    if not old_token:
        return None

    now = time.time()
    new_token = _new_token()
    new_expires_at = now + TOKEN_EXPIRE_SECONDS

    conn = get_db()
    try:
        conn.isolation_level = None
        cursor = conn.cursor()
        cursor.execute('BEGIN IMMEDIATE')
        cursor.execute(
            'SELECT username, expires_at FROM tokens WHERE token = ?',
            (old_token,)
        )
        row = cursor.fetchone()

        if row is None:
            conn.commit()
            return None
        if row['expires_at'] <= now:
            cursor.execute('DELETE FROM tokens WHERE token = ?', (old_token,))
            conn.commit()
            return None

        # 同一事务内以“令牌仍存在且未到期”为条件改名，锁保护下必然成立；
        # 条件保留是为了让边界/竞争情形确定性地失败而不是误放行。
        cursor.execute(
            'UPDATE tokens SET token = ?, expires_at = ? '
            'WHERE token = ? AND expires_at > ?',
            (new_token, new_expires_at, old_token, now)
        )
        if cursor.rowcount != 1:
            conn.rollback()
            return None

        conn.commit()
        return {
            'token': new_token,
            'username': row['username'],
            'expires_at': new_expires_at
        }
    finally:
        conn.close()


def revoke_token(token):
    """作废令牌（主动退出）。幂等，令牌不存在也视为已退出。"""
    if not token:
        return
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM tokens WHERE token = ?', (token,))
        conn.commit()
    finally:
        conn.close()


def get_request_token():
    """从请求中提取令牌：Authorization: Bearer 优先，查询参数仅为兼容。

    所有受保护入口共用同一提取方式与同一校验标准。
    """
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:].strip()
        if token:
            return token
    return request.args.get('token')


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


def login_required(f):
    """登录认证装饰器：所有受保护入口共用 get_token_session 的判定。"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_request_token()
        session = get_token_session(token)
        if session is None:
            return jsonify({'error': '未授权或token已过期'}), 401

        g.token = token
        g.username = session['username']
        return f(*args, **kwargs)
    return decorated_function
