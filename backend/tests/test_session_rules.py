"""登录限流与令牌规则的一致性测试。

覆盖三类根因场景：
- 连续输错后正确密码不被误限、只有凭据校验失败才计数、重试不重复计时；
- 刷新令牌并发执行时旧令牌立即失效、只有一个请求成功；
- 主动退出（令牌吊销）后受保护入口一律 401，重新登录旧令牌不复活。

配置常量沿用生产默认语义：5 次失败 / 60 秒窗口 / 300 秒令牌时长。
"""
import threading
import time

import pytest


# ---------------------------------------------------------------------------
# 登录限流
# ---------------------------------------------------------------------------

def test_failures_below_limit_then_correct_password_succeeds(client):
    """连续输错（未达上限）后，正确密码应当立即登录成功，不被误限。"""
    for _ in range(4):
        resp = client.post('/api/auth', json={
            'username': 'admin', 'password': 'wrong'
        })
        assert resp.status_code == 401

    resp = client.post('/api/auth', json={
        'username': 'admin', 'password': 'admin123'
    })
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True


def test_fifth_failure_is_locked_and_retry_after_is_authoritative(client):
    """达到上限后返回 429，且 Retry-After 头与 JSON retry_after 一致。"""
    for _ in range(5):
        client.post('/api/auth', json={'username': 'admin', 'password': 'bad'})

    resp = client.post('/api/auth', json={
        'username': 'admin', 'password': 'admin123'
    })
    assert resp.status_code == 429
    data = resp.get_json()
    assert data['retry_after'] == int(resp.headers['Retry-After'])
    assert 1 <= data['retry_after'] <= 60


def test_correct_password_unlocks_after_window(client, monkeypatch):
    """窗口滑过后，正确密码立刻放行；失败记录不再延续。"""
    import auth as auth_module

    fake_now = [1000.0]
    monkeypatch.setattr(auth_module.time, 'time', lambda: fake_now[0])

    for _ in range(5):
        resp = client.post('/api/auth', json={
            'username': 'admin', 'password': 'bad'
        })
    assert resp.status_code == 429

    # 恰好经过整个窗口：边界口径为 >= 窗口长度即失效
    fake_now[0] += 60

    resp = client.post('/api/auth', json={
        'username': 'admin', 'password': 'admin123'
    })
    assert resp.status_code == 200


def test_repeated_locked_requests_do_not_extend_wait(client, monkeypatch):
    """被锁定期间重复提交（含网络重试）不追加计数，剩余时间单调递减。"""
    import auth as auth_module

    fake_now = [2000.0]
    monkeypatch.setattr(auth_module.time, 'time', lambda: fake_now[0])

    for _ in range(5):
        client.post('/api/auth', json={'username': 'admin', 'password': 'bad'})

    resp1 = client.post('/api/auth', json={
        'username': 'admin', 'password': 'admin123'
    })
    assert resp1.status_code == 429
    first = resp1.get_json()['retry_after']

    # 多次重试/重复提交
    for _ in range(10):
        fake_now[0] += 1
        resp = client.post('/api/auth', json={
            'username': 'admin', 'password': 'admin123'
        })
        assert resp.status_code == 429

    later = resp.get_json()['retry_after']
    assert later < first  # 没有被重新计时


def test_bad_requests_do_not_count_toward_limit(client):
    """参数错误（400）不消耗失败额度。"""
    for _ in range(6):
        resp = client.post('/api/auth', json={'username': '', 'password': ''})
        assert resp.status_code == 400

    resp = client.post('/api/auth', json={
        'username': 'admin', 'password': 'admin123'
    })
    assert resp.status_code == 200


def test_successful_login_resets_failure_count(client):
    """成功登录后历史失败清零，新窗口重新计数。"""
    for _ in range(4):
        client.post('/api/auth', json={'username': 'admin', 'password': 'bad'})

    assert client.post('/api/auth', json={
        'username': 'admin', 'password': 'admin123'
    }).status_code == 200

    # 再来 4 次失败也不应被锁（计数已重置，4 < 5）
    for _ in range(4):
        resp = client.post('/api/auth', json={'username': 'admin', 'password': 'bad'})
        assert resp.status_code == 401


def test_retry_after_identical_across_pages(client):
    """同一时刻任意入口拿到的剩余等待时间完全一致（同一判定来源）。"""
    for _ in range(5):
        client.post('/api/auth', json={'username': 'admin', 'password': 'bad'})

    values = {
        client.post('/api/auth', json={
            'username': 'admin', 'password': 'admin123'
        }).get_json()['retry_after']
        for _ in range(3)
    }
    assert len(values) == 1


# ---------------------------------------------------------------------------
# 令牌刷新：并发与边界
# ---------------------------------------------------------------------------

def test_refresh_rotates_and_old_token_stops_working(client, auth_token):
    """刷新返回新令牌，旧令牌立刻失效。"""
    resp = client.post(
        '/api/refresh-token',
        headers={'Authorization': f'Bearer {auth_token}'}
    )
    assert resp.status_code == 200
    new_token = resp.get_json()['token']
    assert new_token != auth_token

    # 旧令牌不能再用于鉴权
    assert client.get(
        f'/api/download/x?token={auth_token}'
    ).status_code == 401

    # 新令牌有效（用不存在文件验证：通过鉴权后应得到 404）
    assert client.get(
        '/api/download/nonexistent',
        headers={'Authorization': f'Bearer {new_token}'}
    ).status_code == 404


def test_concurrent_refresh_only_one_succeeds(client, auth_token):
    """并发刷新同一令牌：恰好一个成功，其余 401，旧令牌不残留。"""
    from app import app

    results = []
    barrier = threading.Barrier(8)

    def do_refresh():
        # 每个线程使用独立的测试客户端，避免共享请求上下文
        with app.test_client() as local_client:
            barrier.wait()
            resp = local_client.post(
                '/api/refresh-token',
                headers={'Authorization': f'Bearer {auth_token}'}
            )
            results.append(resp.status_code)

    threads = [threading.Thread(target=do_refresh) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(results).count(200) == 1
    assert sorted(results).count(401) == 7

    # 旧令牌必须已失效
    assert client.get(
        f'/api/download/x?token={auth_token}'
    ).status_code == 401


def test_refresh_expired_token_rejected(client, monkeypatch):
    """恰好到期/已过期的令牌不能刷新（边界口径统一为严格大于）。"""
    import auth as auth_module

    resp = client.post('/api/auth', json={
        'username': 'admin', 'password': 'admin123'
    })
    token = resp.get_json()['token']

    # 令牌签发后再把时间拨到恰好到期的时点
    shifted = time.time() + 300
    monkeypatch.setattr(auth_module.time, 'time', lambda: shifted)

    assert client.post(
        '/api/refresh-token',
        headers={'Authorization': f'Bearer {token}'}
    ).status_code == 401
    assert client.get(
        f'/api/download/x?token={token}'
    ).status_code == 401


def test_token_lifetime_unchanged(client, auth_token):
    """刷新后有效期仍是 300 秒，不延长也不缩短。"""
    resp = client.post(
        '/api/refresh-token',
        headers={'Authorization': f'Bearer {auth_token}'}
    )
    expires_at = resp.get_json()['expires_at']
    assert 299 <= expires_at - time.time() <= 300


# ---------------------------------------------------------------------------
# 退出与重新登录
# ---------------------------------------------------------------------------

def test_logout_revokes_token_everywhere(client, auth_token):
    """主动退出后令牌立即作废，所有受保护入口统一 401。"""
    headers = {'Authorization': f'Bearer {auth_token}'}
    assert client.post('/api/logout', headers=headers).status_code == 200

    assert client.get('/api/shares', headers=headers).status_code == 401
    assert client.get(
        '/api/download/x', headers=headers
    ).status_code == 401
    assert client.post('/api/refresh-token', headers=headers).status_code == 401


def test_logout_is_idempotent(client):
    """无令牌退出也返回成功。"""
    assert client.post('/api/logout').status_code == 200


def test_relogin_invalidates_previous_token(client):
    """重新登录签发新令牌，旧令牌失效，旧会话不会复活。"""
    first = client.post('/api/auth', json={
        'username': 'admin', 'password': 'admin123'
    }).get_json()['token']

    second = client.post('/api/auth', json={
        'username': 'admin', 'password': 'admin123'
    }).get_json()['token']

    assert first != second
    assert client.get(
        f'/api/download/x?token={first}'
    ).status_code == 401
    assert client.get(
        '/api/download/nonexistent',
        headers={'Authorization': f'Bearer {second}'}
    ).status_code == 404
