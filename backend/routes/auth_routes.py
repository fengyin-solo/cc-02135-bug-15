"""认证路由"""
import time
import logging
from flask import request, jsonify
from routes import auth_bp
from auth import (
    login_rate_status,
    record_login_failure,
    reset_login_failures,
    generate_token,
    rotate_token,
    revoke_token,
    authenticate_user,
    get_request_token,
)
from config import TOKEN_EXPIRE_SECONDS

logger = logging.getLogger(__name__)


@auth_bp.route('/api/auth', methods=['POST'])
def authenticate():
    identifier = request.remote_addr

    # 1) 参数校验失败不消耗失败额度（与“连续输错密码才限流”同一标准）
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'success': False, 'error': '无效的请求数据'}), 400

    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'success': False, 'error': '用户名和密码不能为空'}), 400

    if len(username) > 50 or len(password) > 100:
        return jsonify({'success': False, 'error': '输入长度超出限制'}), 400

    # 2) 只对“凭据校验失败”计数：被限流时只读判定，不追加记录，
    #    因此网络重试/重复提交不会重复计时或延长等待。
    locked, retry_after = login_rate_status(identifier)
    if locked:
        response = jsonify({
            'success': False,
            'error': f'尝试过于频繁，请 {retry_after} 秒后再试',
            'retry_after': retry_after
        })
        response.status_code = 429
        response.headers['Retry-After'] = str(retry_after)
        return response

    # 3) 成功登录清零计数并签发唯一令牌；失败才记一次
    if authenticate_user(username, password):
        reset_login_failures(identifier)
        token = generate_token(username)
        logger.info(f"用户认证成功: {username}")
        return jsonify({
            'success': True,
            'token': token,
            'expires_at': time.time() + TOKEN_EXPIRE_SECONDS
        })

    record_login_failure(identifier)
    locked, retry_after = login_rate_status(identifier)

    logger.warning(f"用户认证失败: {username}")
    time.sleep(0.5)

    # 本次失败恰好达到上限时，剩余等待时间与 429 响应来自同一判定，
    # 列表页、详情页和弹窗看到的秒数永远一致。
    if locked:
        response = jsonify({
            'success': False,
            'error': f'用户名或密码错误，尝试次数过多，请 {retry_after} 秒后再试',
            'retry_after': retry_after
        })
        response.status_code = 429
        response.headers['Retry-After'] = str(retry_after)
        return response

    return jsonify({'success': False, 'error': '用户名或密码错误'}), 401


@auth_bp.route('/api/refresh-token', methods=['POST'])
def refresh_token_endpoint():
    token = get_request_token()

    if not token:
        return jsonify({'error': '缺少token'}), 400

    # 原子轮换：旧令牌立即失效，并发刷新只有一个成功，不重复计时
    session = rotate_token(token)
    if session is None:
        return jsonify({'error': 'Token无效或已过期'}), 401

    return jsonify({
        'success': True,
        'message': 'Token已刷新',
        'token': session['token'],
        'expires_at': session['expires_at']
    })


@auth_bp.route('/api/logout', methods=['POST'])
def logout_endpoint():
    """主动退出：服务端令牌立即作废，任何页面恢复时都无法再放行。"""
    token = get_request_token()
    revoke_token(token)
    return jsonify({'success': True, 'message': '已退出登录'})
