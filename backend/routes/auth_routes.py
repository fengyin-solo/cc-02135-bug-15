"""认证路由"""
import time
import logging
from flask import request, jsonify
from routes import auth_bp
from auth import (
    generate_token,
    rotate_token,
    revoke_token,
    verify_token,
    get_username_from_token,
    extract_token,
    authenticate_user,
    login_lock_status,
    record_login_failure,
    reset_login_failures,
)

logger = logging.getLogger(__name__)


def _login_limited_response(retry_after):
    """统一的限流响应：所有页面展示的剩余等待时间都来自这里的 Retry-After"""
    response = jsonify({
        'success': False,
        'error': f'密码错误次数过多，请 {retry_after} 秒后再试',
        'retry_after': retry_after,
    })
    response.status_code = 429
    response.headers['Retry-After'] = str(retry_after)
    return response


@auth_bp.route('/api/auth', methods=['POST'])
def authenticate():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'success': False, 'error': '无效的请求数据'}), 400

    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'success': False, 'error': '用户名和密码不能为空'}), 400

    if len(username) > 50 or len(password) > 100:
        return jsonify({'success': False, 'error': '输入长度超出限制'}), 400

    # 统一限流判定：锁定中直接拒绝，且不核对密码、不新增计数（重试不重复计时）
    _, retry_after = login_lock_status(username)
    if retry_after > 0:
        logger.warning(f"账号已被限流: {username}，剩余 {retry_after}s")
        return _login_limited_response(retry_after)

    if authenticate_user(username, password):
        # 正确密码：连续失败计数清零，正确密码永远不会被误限
        reset_login_failures(username)
        token = generate_token(username)
        logger.info(f"用户认证成功: {username}")
        return jsonify({'success': True, 'token': token})

    # 仅对“凭据错误”计数；请求格式错误（400）不计入。
    # 第 RATE_LIMIT_REQUESTS 次错误本身仍返回 401，自下一次请求起按 429 锁定，
    # 与“窗口内允许 N 次尝试、第 N+1 次拦截”的限流上限保持一致。
    record_login_failure(username)
    logger.warning(f"用户认证失败: {username}")
    time.sleep(0.5)

    return jsonify({'success': False, 'error': '用户名或密码错误'}), 401


@auth_bp.route('/api/refresh-token', methods=['POST'])
def refresh_token_endpoint():
    """刷新令牌：原子轮换，返回新令牌；旧令牌立即失效"""
    token = extract_token()

    if not token:
        return jsonify({'error': '缺少token'}), 400

    result = rotate_token(token)
    if result is None:
        return jsonify({'error': 'Token无效或已过期'}), 401

    return jsonify({
        'success': True,
        'message': 'Token已刷新',
        'token': result['token'],
        'expires_at': result['expires_at'],
    })


@auth_bp.route('/api/verify-token', methods=['POST'])
def verify_token_endpoint():
    """仅校验令牌是否有效，不续期、不改写过期时间（所有页面共用同一标准）"""
    token = extract_token()
    if not token or not verify_token(token):
        return jsonify({'valid': False}), 401

    return jsonify({'valid': True, 'username': get_username_from_token(token)})


@auth_bp.route('/api/logout', methods=['POST'])
def logout_endpoint():
    """退出登录：服务端删除令牌，随后任意受保护入口都不再放行"""
    revoke_token(extract_token())
    return jsonify({'success': True, 'message': '已退出登录'})
