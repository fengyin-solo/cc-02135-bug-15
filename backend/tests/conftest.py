"""pytest 配置和 fixtures"""
import os
import sys
import tempfile
import pytest

# 添加 backend 目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 设置测试环境变量
os.environ['UPLOAD_FOLDER'] = tempfile.mkdtemp()
os.environ['DB_FILE'] = os.path.join(tempfile.mkdtemp(), 'test.db')

from app import app
from database import init_db, get_db


@pytest.fixture
def client():
    """创建测试客户端"""
    from auth import _login_failures
    _login_failures.clear()
    app.config['TESTING'] = True
    init_db()
    with app.test_client() as client:
        yield client


@pytest.fixture
def auth_token(client):
    """获取认证 token（每个用例前失败计数已清空）"""
    response = client.post('/api/auth', json={
        'username': 'admin',
        'password': 'admin123'
    })
    assert response.status_code == 200, response.get_json()
    return response.get_json()['token']


@pytest.fixture
def db_conn():
    """获取数据库连接"""
    conn = get_db()
    yield conn
    conn.close()
