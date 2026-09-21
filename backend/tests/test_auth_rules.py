"""登录限流与令牌刷新统一规则测试"""
import time
import threading

import pytest


LOGIN = {'username': 'admin', 'password': 'admin123'}
WRONG = {'username': 'admin', 'password': 'bad-password'}


def _fail(client, n):
    for _ in range(n):
        resp = client.post('/api/auth', json=WRONG)
    return resp


# ---------------------------------------------------------------------------
# 限流：连续失败计数，正确密码不误限
# ---------------------------------------------------------------------------

def test_correct_password_after_failures_not_limited(client):
    """连续输错 4 次后，正确密码仍可登录（正确密码不能被误限）"""
    resp = _fail(client, 4)
    assert resp.status_code == 401

    resp = client.post('/api/auth', json=LOGIN)
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True


def test_lockout_after_threshold(client):
    """达到失败上限后，第 6 次（含正确密码）在窗口内被限流"""
    fifth = _fail(client, 5)
    assert fifth.status_code == 401

    sixth = client.post('/api/auth', json=LOGIN)
    assert sixth.status_code == 429
    body = sixth.get_json()
    assert body['retry_after'] > 0
    assert sixth.headers['Retry-After'] == str(body['retry_after'])


def test_successful_login_resets_counter(client):
    """登录成功后失败计数清零，再次失败从第 1 次开始"""
    _fail(client, 4)
    client.post('/api/auth', json=LOGIN)

    # 若未清零，再来 2 次错误就会触发限流；清零后第 5 次错误仍应只是 401
    resp = _fail(client, 5)
    assert resp.status_code == 401


def test_retry_after_consistent_across_requests(client):
    """窗口内不同请求看到的剩余等待时间单调一致，不因重试而延长/重置"""
    _fail(client, 5)

    first = client.post('/api/auth', json=WRONG)
    assert first.status_code == 429
    wait1 = first.get_json()['retry_after']

    time.sleep(1.1)
    second = client.post('/api/auth', json=LOGIN)
    assert second.status_code == 429
    wait2 = second.get_json()['retry_after']

    # 重试不重复计时：第二次等待只会变短，不会变长或重新开始
    assert wait2 <= wait1
    assert wait2 >= wait1 - 2


def test_window_expiry_allows_login(client):
    """窗口结束后计数自动失效，正确密码立刻可登录"""
    from auth import get_db

    _fail(client, 5)
    assert client.post('/api/auth', json=LOGIN).status_code == 429

    # 将窗口起点拨到窗口之外（边界：恰好满窗口即放行）
    conn = get_db()
    conn.execute(
        'UPDATE login_failures SET window_started_at = ?',
        (time.time() - 60,)
    )
    conn.commit()
    conn.close()

    resp = client.post('/api/auth', json=LOGIN)
    assert resp.status_code == 200


def test_bad_request_not_counted(client):
    """格式错误（空字段）不消耗失败次数，不影响正常登录速度"""
    for _ in range(6):
        resp = client.post('/api/auth', json={'username': '', 'password': ''})
        assert resp.status_code == 400

    assert client.post('/api/auth', json=LOGIN).status_code == 200


def test_lockout_scoped_per_account(client):
    """一个账号被锁，不影响其他账号正常登录"""
    _fail(client, 5)
    assert client.post('/api/auth', json=WRONG).status_code == 429

    other = client.post('/api/auth', json={'username': 'user', 'password': 'user123'})
    assert other.status_code == 200


# ---------------------------------------------------------------------------
# 令牌刷新：原子轮换，并发只有一方成功，旧令牌立即失效
# ---------------------------------------------------------------------------

def test_refresh_rotates_token(client, auth_token):
    """刷新成功后返回新令牌，旧令牌立即失效"""
    resp = client.post(f'/api/refresh-token?token={auth_token}')
    assert resp.status_code == 200
    new_token = resp.get_json()['token']
    assert new_token
    assert new_token != auth_token

    # 旧令牌不能再访问受保护资源
    old_resp = client.get('/api/shares', headers={'Authorization': f'Bearer {auth_token}'})
    assert old_resp.status_code == 401

    # 旧令牌也不能再次刷新
    old_refresh = client.post('/api/refresh-token',
                              headers={'Authorization': f'Bearer {auth_token}'})
    assert old_refresh.status_code == 401

    # 新令牌可用
    new_resp = client.get('/api/shares', headers={'Authorization': f'Bearer {new_token}'})
    assert new_resp.status_code == 200


def test_concurrent_refresh_only_one_wins():
    """并发刷新同一令牌：最多一方拿到新令牌，旧令牌不再可用"""
    from app import app
    from database import init_db, get_db
    from auth import clear_login_failures

    clear_login_failures()
    init_db()

    with app.test_client() as login_client:
        token = login_client.post('/api/auth', json=LOGIN).get_json()['token']

    results = []
    barrier = threading.Barrier(5)

    def worker():
        with app.test_client() as c:
            barrier.wait()
            resp = c.post('/api/refresh-token',
                          headers={'Authorization': f'Bearer {token}'})
            results.append((resp.status_code,
                            resp.get_json().get('token') if resp.status_code == 200 else None))

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in results if r[0] == 200]
    assert len(successes) == 1

    # 旧令牌已删除，新令牌是库里唯一指向本次轮换结果的令牌
    conn = get_db()
    old_rows = conn.execute('SELECT token FROM tokens WHERE token = ?',
                            (token,)).fetchall()
    winner_rows = conn.execute('SELECT token FROM tokens WHERE token = ?',
                               (successes[0][1],)).fetchall()
    conn.close()
    assert len(old_rows) == 0
    assert len(winner_rows) == 1


def test_refresh_expired_token_rejected(client, db_conn):
    """过期令牌刷新被拒，并被清除"""
    resp = client.post('/api/auth', json=LOGIN)
    token = resp.get_json()['token']

    db_conn.execute('UPDATE tokens SET expires_at = ? WHERE token = ?',
                    (time.time() - 1, token))
    db_conn.commit()

    refresh = client.post('/api/refresh-token',
                          headers={'Authorization': f'Bearer {token}'})
    assert refresh.status_code == 401

    use = client.get('/api/shares', headers={'Authorization': f'Bearer {token}'})
    assert use.status_code == 401


def test_token_duration_unchanged(client, db_conn):
    """令牌有效期仍为配置的 300 秒（既有时长不变），刷新同样给完整时长"""
    from config import TOKEN_EXPIRE_SECONDS

    token = client.post('/api/auth', json=LOGIN).get_json()['token']
    row = db_conn.execute('SELECT expires_at FROM tokens WHERE token = ?',
                          (token,)).fetchone()
    assert 299 < (row['expires_at'] - time.time()) <= TOKEN_EXPIRE_SECONDS

    resp = client.post('/api/refresh-token',
                       headers={'Authorization': f'Bearer {token}'})
    new_token = resp.get_json()['token']
    row = db_conn.execute('SELECT expires_at FROM tokens WHERE token = ?',
                          (new_token,)).fetchone()
    assert 299 < (row['expires_at'] - time.time()) <= TOKEN_EXPIRE_SECONDS


# ---------------------------------------------------------------------------
# 退出登录：服务端吊销
# ---------------------------------------------------------------------------

def test_logout_revokes_token(client, auth_token):
    """主动退出后令牌立即失效，受保护入口返回 401"""
    before = client.get('/api/shares', headers={'Authorization': f'Bearer {auth_token}'})
    assert before.status_code == 200

    logout = client.post('/api/logout', headers={'Authorization': f'Bearer {auth_token}'})
    assert logout.status_code == 200

    after = client.get('/api/shares', headers={'Authorization': f'Bearer {auth_token}'})
    assert after.status_code == 401

    # 已退出的令牌刷新同样被拒
    refresh = client.post('/api/refresh-token',
                          headers={'Authorization': f'Bearer {auth_token}'})
    assert refresh.status_code == 401


def test_logout_idempotent(client):
    """缺少/无效令牌退出也返回成功，不报错"""
    assert client.post('/api/logout').status_code == 200
    assert client.post('/api/logout',
                       headers={'Authorization': 'Bearer not-exist'}).status_code == 200


def test_verify_token_endpoint_is_read_only(client, auth_token):
    """/api/verify-token 不续期：多次校验不会改变过期时间"""
    from database import get_db

    conn = get_db()
    before = conn.execute('SELECT expires_at FROM tokens WHERE token = ?',
                          (auth_token,)).fetchone()['expires_at']
    conn.close()

    time.sleep(1.0)
    for _ in range(3):
        resp = client.post('/api/verify-token',
                           headers={'Authorization': f'Bearer {auth_token}'})
        assert resp.status_code == 200

    conn = get_db()
    after = conn.execute('SELECT expires_at FROM tokens WHERE token = ?',
                         (auth_token,)).fetchone()['expires_at']
    conn.close()
    assert after == before
