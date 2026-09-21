// 从配置文件获取API地址
const API_BASE = CONFIG.API_BASE;

let currentShareFileId = null;
let currentShareLink = null;

// Token 管理
// 统一规则：
// - 令牌是否有效只以服务端 tokens 表为准；校验（verify-token）只读不续期；
// - 刷新（refresh-token）会原子轮换令牌，返回新令牌，旧令牌立即失效；
// - 所有页面（列表/详情/重新进入）共用同一个 isValid 判定与同一份本地状态；
// - 并发校验/刷新合并为同一个请求，避免重复计时与重复轮换。
const TokenManager = {
    TOKEN_KEY: 'auth_token',
    USER_KEY: 'auth_user',

    // 短缓存：同一时刻多个入口只发一次校验
    _checkInFlight: null,
    _checkCache: null,
    _checkCacheKey: null,
    _checkCacheUntil: 0,
    // 刷新单飞：并发刷新只有一个请求，结果回传给所有调用方
    _refreshInFlight: null,

    save(token, username) {
        localStorage.setItem(this.TOKEN_KEY, token);
        localStorage.setItem(this.USER_KEY, username);
        this._resetCache(token);
    },

    get() {
        return localStorage.getItem(this.TOKEN_KEY);
    },

    getUser() {
        return localStorage.getItem(this.USER_KEY);
    },

    clear() {
        localStorage.removeItem(this.TOKEN_KEY);
        localStorage.removeItem(this.USER_KEY);
        this._resetCache(null);
    },

    _resetCache(key) {
        this._checkInFlight = null;
        this._refreshInFlight = null;
        this._checkCache = null;
        this._checkCacheKey = key;
        this._checkCacheUntil = 0;
    },

    // 纯校验：不刷新、不延长有效期。所有页面都通过它判断登录态
    async isValid() {
        const token = this.get();
        if (!token) return false;

        // 令牌在缓存有效期内被换掉/清除（例如刷新轮换、退出）则缓存作废
        if (this._checkCacheKey === token && this._checkCache !== null &&
            Date.now() < this._checkCacheUntil) {
            return this._checkCache;
        }
        if (this._checkInFlight) return this._checkInFlight;

        this._checkInFlight = (async () => {
            let valid = false;
            try {
                const response = await fetch(`${API_BASE}/verify-token`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                valid = response.ok;
            } catch {
                valid = false;
            }
            // 只在令牌仍是当前令牌时写入结果，防止异步竞态覆盖较新状态
            if (this.get() === token) {
                this._checkCache = valid;
                this._checkCacheKey = token;
                this._checkCacheUntil = Date.now() + 4000;
            }
            this._checkInFlight = null;
            return valid;
        })();

        return this._checkInFlight;
    },

    // 原子轮换刷新：并发调用共享同一请求；成功后本地保存新令牌
    async refresh() {
        const token = this.get();
        if (!token) return false;
        if (this._refreshInFlight) return this._refreshInFlight;

        this._refreshInFlight = (async () => {
            try {
                const response = await fetch(`${API_BASE}/refresh-token`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (!response.ok) {
                    this.clear();
                    return false;
                }
                const result = await response.json();
                this.save(result.token, this.getUser());
                return true;
            } catch {
                return false;
            } finally {
                this._refreshInFlight = null;
            }
        })();

        return this._refreshInFlight;
    },

    // 主动退出：通知服务端删除令牌后再清本地，受保护入口立即恢复未登录外观
    async logout() {
        const token = this.get();
        if (token) {
            try {
                await fetch(`${API_BASE}/logout`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
            } catch {
                // 即使网络失败也清除本地状态；令牌在服务端到期后同样会失效
            }
        }
        this.clear();
    }
};

// 统一的登录态恢复：列表、用户栏、分享区、重新进入页面都走这一处
async function renderAuthState() {
    const userBar = document.getElementById('userBar');
    const currentUser = document.getElementById('currentUser');
    const userAvatar = document.getElementById('userAvatar');
    const shareSection = document.getElementById('mySharesSection');
    const user = TokenManager.getUser();
    const loggedIn = !!(user && TokenManager.get() && await TokenManager.isValid());

    if (loggedIn) {
        currentUser.textContent = user;
        userAvatar.textContent = user.charAt(0).toUpperCase();
        userBar.classList.remove('hidden');
        shareSection.style.display = 'block';
        await loadMyShares();
    } else {
        userBar.classList.add('hidden');
        shareSection.style.display = 'none';
    }
    return loggedIn;
}

// 兼容旧调用名
async function updateUserBar() {
    return renderAuthState();
}

// 退出登录：服务端吊销 + 本地清除 + 所有入口统一重绘
async function logout() {
    await TokenManager.logout();
    await renderAuthState();
    await loadFileList();
}

// 受保护请求收到 401 时的统一恢复：清除失效登录态并重绘页面
async function handleUnauthorized() {
    TokenManager.clear();
    await renderAuthState();
    await loadFileList();
}

// 页面加载：以同一套校验标准恢复页面外观，随后加载列表
document.addEventListener('DOMContentLoaded', async () => {
    if (TokenManager.get() && !(await TokenManager.isValid())) {
        TokenManager.clear();
    }
    await renderAuthState();
    loadFileList();
});

// 跨标签页同步：另一个标签登录/退出后，本标签立即恢复一致外观
window.addEventListener('storage', async (e) => {
    if (e.key === TokenManager.TOKEN_KEY || e.key === TokenManager.USER_KEY) {
        TokenManager._resetCache(TokenManager.get());
        await renderAuthState();
        await loadFileList();
    }
});

// 验证文件
function validateFile(file) {
    if (file.size > CONFIG.MAX_FILE_SIZE) {
        return `文件大小超过限制（最大${CONFIG.MAX_FILE_SIZE / 1024 / 1024}MB）`;
    }
    return null;
}

// 上传文件处理函数
async function uploadFile(file) {
    const validationError = validateFile(file);
    if (validationError) {
        document.getElementById('uploadStatus').textContent = `❌ ${validationError}`;
        return;
    }

    showLoading('上传中...');

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch(`${API_BASE}/upload`, {
            method: 'POST',
            body: formData
        });
        const result = await response.json();

        if (response.ok) {
            document.getElementById('uploadStatus').textContent = `✅ ${file.name} 上传成功！`;
            loadFileList();
        } else {
            document.getElementById('uploadStatus').textContent = `❌ 上传失败: ${result.error}`;
        }
    } catch (error) {
        document.getElementById('uploadStatus').textContent = `❌ 上传失败: ${error.message}`;
    } finally {
        hideLoading();
    }
}

// 文件选择上传
document.getElementById('fileInput').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    await uploadFile(file);
    e.target.value = '';
});

// 拖拽上传
const uploadZone = document.querySelector('.upload-zone');

uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.classList.add('drag-over');
});

uploadZone.addEventListener('dragleave', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('drag-over');
});

uploadZone.addEventListener('drop', async (e) => {
    e.preventDefault();
    uploadZone.classList.remove('drag-over');

    const file = e.dataTransfer.files[0];
    if (file) {
        await uploadFile(file);
    }
});

// 加载文件列表（登录态以统一校验为准）
async function loadFileList() {
    showLoading('加载文件列表...');

    try {
        const [response, isLoggedIn] = await Promise.all([
            fetch(`${API_BASE}/files`),
            TokenManager.isValid()
        ]);
        const files = await response.json();

        const fileList = document.getElementById('fileList');

        if (files.length === 0) {
            fileList.innerHTML = '<p class="empty-msg">暂无可下载文件</p>';
        } else {
            fileList.innerHTML = files.map(file => `
                <div class="file-item">
                    <div class="file-info">
                        <div class="file-icon">${getFileIcon(file.name)}</div>
                        <div class="file-details">
                            <div class="file-name">${escapeHtml(file.name)}</div>
                            <div class="file-size">${formatSize(file.size)}</div>
                        </div>
                    </div>
                    <div class="file-actions">
                        ${isLoggedIn ? `<button class="share-btn" onclick="openShareModal('${escapeHtml(file.id)}', '${escapeHtml(file.name)}')">分享</button>` : ''}
                        <button class="download-btn" onclick="requestDownload('${escapeHtml(file.id)}')">
                            下载
                        </button>
                    </div>
                </div>
            `).join('');
        }
    } catch (error) {
        document.getElementById('fileList').innerHTML =
            `<p class="empty-msg">加载失败: ${escapeHtml(error.message)}</p>`;
    } finally {
        hideLoading();
    }
}

// HTML转义防止XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// 统一展示服务端给出的限流剩余等待时间（所有页面同一来源，不自行倒计时）
function formatRateLimitError(result) {
    if (result && result.retry_after) {
        return `密码错误次数过多，请 ${result.retry_after} 秒后再试`;
    }
    return (result && result.error) || '请求过于频繁，请稍后再试';
}

// 请求下载 - 检查token是否有效，有效则直接下载
async function requestDownload(fileId) {
    showLoading('检查授权...');

    // 检查是否有有效的token
    if (await TokenManager.isValid()) {
        // token有效，使用 fetch + Authorization 头下载
        document.getElementById('loadingText').textContent = '正在下载...';
        try {
            const response = await fetch(`${API_BASE}/download/${fileId}`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${TokenManager.get()}`
                }
            });
            if (response.ok) {
                await saveDownloadResponse(response);
            } else if (response.status === 401) {
                // 令牌已失效：恢复未登录外观并弹出验证框
                TokenManager.clear();
                await renderAuthState();
                await loadFileList();
                hideLoading();
                openAuthModal(fileId);
                return;
            } else {
                const result = await response.json();
                alert(`下载失败: ${result.error || '未知错误'}`);
            }
        } catch (error) {
            alert(`下载失败: ${error.message}`);
        } finally {
            hideLoading();
        }
        return;
    }

    // token无效或不存在，弹出登录框
    hideLoading();
    openAuthModal(fileId);
}

// 保存下载响应为本地文件
async function saveDownloadResponse(response) {
    const blob = await response.blob();
    const contentDisposition = response.headers.get('Content-Disposition');
    let filename = 'download';
    if (contentDisposition) {
        const match = contentDisposition.match(/filename\*?=(?:UTF-8'')?["']?([^"';\n]+)/i);
        if (match) filename = decodeURIComponent(match[1]);
    }
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    a.remove();
}

// 弹出登录验证框
function openAuthModal(fileId) {
    TokenManager.clear();
    document.getElementById('downloadFileId').value = fileId;
    document.getElementById('authModal').classList.add('active');
    document.getElementById('authError').textContent = '';
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    document.getElementById('username').focus();
}

// 关闭验证弹窗
function closeAuthModal() {
    document.getElementById('authModal').classList.remove('active');
}

// 身份验证表单提交
document.getElementById('authForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const fileId = document.getElementById('downloadFileId').value;

    if (!username || !password) {
        document.getElementById('authError').textContent = '请输入用户名和密码';
        return;
    }

    showLoading('验证身份...');

    try {
        const response = await fetch(`${API_BASE}/auth`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const result = await response.json();

        if (response.ok && result.success) {
            // 保存token和用户名到本地
            TokenManager.save(result.token, username);
            await renderAuthState();
            loadFileList();

            closeAuthModal();
            document.getElementById('loadingText').textContent = '验证成功，正在下载...';

            // 使用 fetch + Authorization 头下载
            try {
                const downloadResponse = await fetch(`${API_BASE}/download/${fileId}`, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${result.token}`
                    }
                });
                if (downloadResponse.ok) {
                    await saveDownloadResponse(downloadResponse);
                } else if (downloadResponse.status === 401) {
                    await handleUnauthorized();
                    document.getElementById('authError').textContent = '登录态已失效，请重新验证';
                    document.getElementById('authModal').classList.add('active');
                } else {
                    const errResult = await downloadResponse.json();
                    document.getElementById('authError').textContent = `下载失败: ${errResult.error || '未知错误'}`;
                }
            } catch (downloadError) {
                document.getElementById('authError').textContent = `下载失败: ${downloadError.message}`;
            } finally {
                hideLoading();
            }
        } else if (response.status === 429) {
            hideLoading();
            // 剩余等待时间统一展示服务端 Retry-After/retry_after
            document.getElementById('authError').textContent = formatRateLimitError(result);
        } else {
            hideLoading();
            document.getElementById('authError').textContent = result.error || '验证失败，请检查账号密码';
        }
    } catch (error) {
        hideLoading();
        document.getElementById('authError').textContent = `验证失败: ${error.message}`;
    }
});

// 显示加载动画
function showLoading(text = '加载中...') {
    document.getElementById('loadingText').textContent = text;
    document.getElementById('loadingOverlay').classList.add('active');
}

// 隐藏加载动画
function hideLoading() {
    document.getElementById('loadingOverlay').classList.remove('active');
}

// 获取文件图标
function getFileIcon(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const icons = {
        pdf: '📄', doc: '📝', docx: '📝', txt: '📃',
        jpg: '🖼️', jpeg: '🖼️', png: '🖼️', gif: '🖼️',
        mp3: '🎵', wav: '🎵', mp4: '🎬', avi: '🎬',
        zip: '📦', rar: '📦', '7z': '📦',
        js: '💻', py: '🐍', html: '🌐', css: '🎨'
    };
    return icons[ext] || '📁';
}

// 格式化文件大小
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 格式化时间戳
function formatTimestamp(timestamp) {
    if (!timestamp) return '永久有效';
    const date = new Date(timestamp * 1000);
    return date.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// 格式化剩余时间
function formatRemainingTime(expiresAt) {
    if (!expiresAt) return '永久';
    const remaining = expiresAt - (Date.now() / 1000);
    if (remaining <= 0) return '已过期';

    const hours = Math.floor(remaining / 3600);
    const minutes = Math.floor((remaining % 3600) / 60);

    if (hours > 24) {
        const days = Math.floor(hours / 24);
        return `${days} 天 ${hours % 24} 小时`;
    } else if (hours > 0) {
        return `${hours} 小时 ${minutes} 分钟`;
    } else {
        return `${minutes} 分钟`;
    }
}

// 打开分享设置弹窗
function openShareModal(fileId, fileName) {
    currentShareFileId = fileId;
    document.getElementById('shareFileName').textContent = fileName;
    document.getElementById('shareError').textContent = '';
    document.getElementById('expireHours').value = '24';
    document.getElementById('maxDownloads').value = '10';
    document.getElementById('shareModal').classList.add('active');
}

// 关闭分享设置弹窗
function closeShareModal() {
    document.getElementById('shareModal').classList.remove('active');
    currentShareFileId = null;
}

// 确认创建分享链接
async function confirmCreateShare() {
    if (!currentShareFileId) return;

    const expireHours = parseInt(document.getElementById('expireHours').value);
    const maxDownloads = parseInt(document.getElementById('maxDownloads').value);

    showLoading('生成分享链接...');
    document.getElementById('shareError').textContent = '';

    try {
        const response = await fetch(`${API_BASE}/share`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${TokenManager.get()}`
            },
            body: JSON.stringify({
                file_id: currentShareFileId,
                expire_hours: expireHours,
                max_downloads: maxDownloads
            })
        });

        const result = await response.json();

        if (response.ok && result.success) {
            closeShareModal();
            showShareSuccessModal(result);
            loadMyShares();
        } else if (response.status === 401) {
            await handleUnauthorized();
        } else {
            document.getElementById('shareError').textContent = result.error || '生成分享链接失败';
        }
    } catch (error) {
        document.getElementById('shareError').textContent = `错误: ${error.message}`;
    } finally {
        hideLoading();
    }
}

// 显示分享成功弹窗
function showShareSuccessModal(result) {
    currentShareLink = `${window.location.origin}/share.html#${result.share_id}`;

    document.getElementById('shareLinkInput').value = currentShareLink;
    document.getElementById('shareInfoName').textContent = result.filename;
    document.getElementById('shareInfoExpire').textContent = formatTimestamp(result.expires_at);
    document.getElementById('shareInfoDownloads').textContent = result.max_downloads ? `${result.max_downloads} 次` : '无限制';
    document.getElementById('copyBtnText').textContent = '复制';

    const copyBtn = document.querySelector('.copy-btn');
    copyBtn.classList.remove('copied');

    document.getElementById('shareSuccessModal').classList.add('active');
}

// 关闭分享成功弹窗
function closeShareSuccessModal() {
    document.getElementById('shareSuccessModal').classList.remove('active');
    currentShareLink = null;
}

// 复制分享链接
async function copyShareLink() {
    const linkInput = document.getElementById('shareLinkInput');
    const copyBtnText = document.getElementById('copyBtnText');
    const copyBtn = document.querySelector('.copy-btn');

    try {
        await navigator.clipboard.writeText(linkInput.value);
        copyBtnText.textContent = '已复制';
        copyBtn.classList.add('copied');

        setTimeout(() => {
            copyBtnText.textContent = '复制';
            copyBtn.classList.remove('copied');
        }, 2000);
    } catch (error) {
        linkInput.select();
        document.execCommand('copy');
        copyBtnText.textContent = '已复制';
        copyBtn.classList.add('copied');

        setTimeout(() => {
            copyBtnText.textContent = '复制';
            copyBtn.classList.remove('copied');
        }, 2000);
    }
}

// 加载我的分享列表
async function loadMyShares() {
    const section = document.getElementById('mySharesSection');
    const list = document.getElementById('mySharesList');

    if (!(await TokenManager.isValid())) {
        section.style.display = 'none';
        return;
    }

    section.style.display = 'block';

    try {
        const response = await fetch(`${API_BASE}/shares`, {
            headers: {
                'Authorization': `Bearer ${TokenManager.get()}`
            }
        });

        if (response.status === 401) {
            await handleUnauthorized();
            return;
        }

        const shares = await response.json();

        if (shares.length === 0) {
            list.innerHTML = '<p class="empty-msg">暂无分享链接</p>';
            return;
        }

        list.innerHTML = shares.map(share => {
            const statusClass = share.is_valid ? 'valid' : 'invalid';
            const statusText = share.is_valid ? '有效' : (share.error_msg || '无效');

            return `
                <div class="share-item">
                    <div class="share-item-header">
                        <span class="share-item-filename">${escapeHtml(share.filename)}</span>
                        <span class="share-item-status ${statusClass}">${statusText}</span>
                    </div>
                    <div class="share-item-details">
                        <div class="share-item-detail">
                            <span class="share-item-detail-label">剩余时间</span>
                            <span class="share-item-detail-value">${formatRemainingTime(share.expires_at)}</span>
                        </div>
                        <div class="share-item-detail">
                            <span class="share-item-detail-label">已下载</span>
                            <span class="share-item-detail-value">${share.download_count} / ${share.max_downloads || '∞'}</span>
                        </div>
                        <div class="share-item-detail">
                            <span class="share-item-detail-label">创建时间</span>
                            <span class="share-item-detail-value">${new Date(share.created_at).toLocaleString('zh-CN')}</span>
                        </div>
                    </div>
                    <div class="share-item-actions">
                        <button class="copy-link-btn" onclick="copyShareLinkFromList('${share.share_id}')">
                            🔗 复制链接
                        </button>
                        <button class="delete-share-btn" onclick="deleteShare('${share.share_id}')">
                            🗑️ 删除
                        </button>
                    </div>
                </div>
            `;
        }).join('');
    } catch (error) {
        list.innerHTML = `<p class="empty-msg">加载失败: ${escapeHtml(error.message)}</p>`;
    }
}

// 从分享列表复制链接
async function copyShareLinkFromList(shareId) {
    const link = `${window.location.origin}/share.html#${shareId}`;
    try {
        await navigator.clipboard.writeText(link);
        alert('分享链接已复制到剪贴板');
    } catch (error) {
        prompt('请手动复制链接:', link);
    }
}

// 删除分享链接
async function deleteShare(shareId) {
    if (!confirm('确定要删除此分享链接吗？删除后链接将立即失效。')) {
        return;
    }

    showLoading('删除中...');

    try {
        const response = await fetch(`${API_BASE}/share/${shareId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${TokenManager.get()}`
            }
        });

        if (response.ok) {
            loadMyShares();
        } else if (response.status === 401) {
            await handleUnauthorized();
        } else {
            const result = await response.json();
            alert(`删除失败: ${result.error || '未知错误'}`);
        }
    } catch (error) {
        alert(`删除失败: ${error.message}`);
    } finally {
        hideLoading();
    }
}
