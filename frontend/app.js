// 从配置文件获取API地址
const API_BASE = CONFIG.API_BASE;

let currentShareFileId = null;
let currentShareLink = null;

/*
 * 会话判定标准（前后端一致，全页面共用同一套规则）：
 * - 令牌有效性唯一以后端 /api/refresh-token 的原子轮换结论为准；
 * - 刷新采用单飞（single-flight）合并：页面加载、列表、下载等并发场景
 *   只发出一次刷新请求，成功结果在短时间内复用，绝不重复计时或重复轮换；
 * - 401（无效/过期/被退出作废）一律清除本地登录态并恢复未登录外观；
 *   网络错误只视为“未知”，不清登录态，避免误登出。
 */
const TokenManager = {
    TOKEN_KEY: 'auth_token',
    USER_KEY: 'auth_user',

    _refreshing: null,      // 进行中的刷新 Promise（单飞）
    _validUntil: 0,         // 本地已知有效的截止时间戳（ms，短缓存）
    _cacheTtlMs: 5000,

    save(token, username) {
        localStorage.setItem(this.TOKEN_KEY, token);
        localStorage.setItem(this.USER_KEY, username);
        this._validUntil = Date.now() + this._cacheTtlMs;
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
        this._validUntil = 0;
        this._refreshing = null;
    },

    // 带短缓存的登录态判定，同一渲染周期内不重复请求后端
    async isLoggedIn() {
        if (!this.get()) return false;
        if (Date.now() < this._validUntil) return true;
        return this.refreshSession();
    },

    // 原子刷新（单飞）：并发调用共用同一个请求，旧令牌只轮换一次
    async refreshSession() {
        const token = this.get();
        if (!token) return false;
        if (this._refreshing) return this._refreshing;

        this._refreshing = (async () => {
            try {
                const response = await fetch(`${API_BASE}/refresh-token`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}` }
                });

                if (response.ok) {
                    const result = await response.json();
                    // 落库前确认本地令牌仍是发起刷新时的那一个：
                    // 刷新期间若用户已退出（本地被清空），轮换结果不得复活登录态
                    const current = this.get();
                    if (current !== token) return current !== null;

                    // 轮换成功：以服务端返回的新令牌为唯一有效令牌
                    if (result.token && result.token !== token) {
                        this.save(result.token, this.getUser());
                    } else {
                        this._validUntil = Date.now() + this._cacheTtlMs;
                    }
                    return true;
                }

                if (response.status === 401) {
                    // 唯一标准：明确的 401 才说明令牌失效（过期/被退出作废）
                    this.clear();
                }
                return false;
            } catch {
                // 网络错误不改变登录态，保持原有登录外观但本次判定不放行
                return false;
            } finally {
                this._refreshing = null;
            }
        })();

        return this._refreshing;
    },

    // 退出：先通知服务端作废令牌（幂等），再清除本地状态
    async logoutRemote() {
        // 等待在途刷新完成，避免其轮换结果与退出相互竞争
        if (this._refreshing) {
            try { await this._refreshing; } catch { /* 忽略 */ }
        }
        const token = this.get();
        if (token) {
            try {
                await fetch(`${API_BASE}/logout`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
            } catch {
                // 即使请求失败也本地登出；令牌会在到期后自然失效
            }
        }
        this.clear();
    }
};

/*
 * 登录限流状态：剩余等待秒数唯一来自后端响应（Retry-After / retry_after），
 * 本地只做倒计时显示，不自行推算起点，因此列表页、弹窗、重新进入页面
 * 看到的等待时间永远一致，页面重进后可按服务端最新值重新同步。
 */
const LoginLockout = {
    until: 0,           // 解除锁定的本地时刻（ms）
    timer: null,
    onTick: null,

    start(retryAfterSeconds) {
        this.until = Date.now() + retryAfterSeconds * 1000;
        this._schedule();
    },

    clear() {
        this.until = 0;
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
        }
    },

    remainingSeconds() {
        if (!this.until) return 0;
        return Math.max(0, Math.ceil((this.until - Date.now()) / 1000));
    },

    isLocked() {
        return this.remainingSeconds() > 0;
    },

    // 绑定每一秒的 UI 更新
    bind(onTick) {
        this.onTick = onTick;
    },

    _schedule() {
        if (this.timer) clearInterval(this.timer);
        this.timer = setInterval(() => {
            if (!this.isLocked()) this.clear();
            if (this.onTick) this.onTick(this.remainingSeconds());
        }, 1000);
    }
};

// 更新登录弹窗中的限流提示与提交按钮可用性
function renderLockoutUI(secondsLeft) {
    const errorEl = document.getElementById('authError');
    const submitBtn = document.querySelector('#authForm button[type="submit"]');
    if (secondsLeft > 0) {
        errorEl.textContent = `尝试过于频繁，请 ${secondsLeft} 秒后再试`;
        submitBtn.disabled = true;
        submitBtn.textContent = `请等待 ${secondsLeft} 秒`;
    } else {
        errorEl.textContent = '';
        submitBtn.disabled = false;
        submitBtn.textContent = '验证';
    }
}

// 更新用户状态栏
async function updateUserBar() {
    const userBar = document.getElementById('userBar');
    const currentUser = document.getElementById('currentUser');
    const userAvatar = document.getElementById('userAvatar');
    const user = TokenManager.getUser();
    const loggedIn = !!(user && TokenManager.get() && await TokenManager.isLoggedIn());

    if (loggedIn) {
        currentUser.textContent = user;
        userAvatar.textContent = user.charAt(0).toUpperCase();
        userBar.classList.remove('hidden');
        loadMyShares();
    } else {
        // 令牌缺失或被服务端判定失效：受保护入口一律恢复未登录外观
        userBar.classList.add('hidden');
        const shareSection = document.getElementById('mySharesSection');
        if (shareSection) {
            shareSection.style.display = 'none';
        }
    }
    return loggedIn;
}

// 退出登录：先作废服务端令牌，再同步重绘，杜绝“退出后又回到已登录外观”
async function logout() {
    await TokenManager.logoutRemote();
    await renderSessionUI();
    await loadFileList();
}

// 按当前会话状态重绘全部受保护入口
async function renderSessionUI() {
    const loggedIn = await updateUserBar();
    if (!loggedIn) {
        const shareSection = document.getElementById('mySharesSection');
        if (shareSection) shareSection.style.display = 'none';
    }
    return loggedIn;
}

// 页面加载时：只做一次会话判定，列表、状态栏共用同一份结果
document.addEventListener('DOMContentLoaded', async () => {
    LoginLockout.bind(renderLockoutUI);
    await renderSessionUI();
    await loadFileList();
});

// 多标签页同步：一个标签页登录/退出，其他标签页立即恢复正确外观
window.addEventListener('storage', async (e) => {
    if (e.key === TokenManager.TOKEN_KEY) {
        // 令牌被其他标签页清除（退出）时，连带作废本地有效性缓存
        if (e.newValue === null) {
            TokenManager._validUntil = 0;
        }
        await renderSessionUI();
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

// 加载文件列表（登录态复用单飞判定，不再额外打刷新请求）
async function loadFileList() {
    showLoading('加载文件列表...');

    try {
        const response = await fetch(`${API_BASE}/files`);
        const files = await response.json();

        const fileList = document.getElementById('fileList');
        const isLoggedIn = await TokenManager.isLoggedIn();

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

// 统一处理受保护请求的 401：清登录态并恢复未登录外观
async function handleProtectedUnauthorized() {
    TokenManager.clear();
    await renderSessionUI();
    await loadFileList();
}

// 请求下载 - 检查token是否有效，有效则直接下载
async function requestDownload(fileId) {
    showLoading('检查授权...');

    // 检查是否有有效的token（单飞刷新，不重复轮换/计时）
    if (await TokenManager.isLoggedIn()) {
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
                await saveBlobResponse(response);
            } else if (response.status === 401) {
                await handleProtectedUnauthorized();
                alert('登录已过期，请重新验证后下载');
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

// 统一的文件流保存逻辑
async function saveBlobResponse(response) {
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

// 打开登录弹窗（统一样式复位，剩余等待时间按当前限流状态显示）
function openAuthModal(fileId) {
    document.getElementById('downloadFileId').value = fileId || '';
    document.getElementById('authModal').classList.add('active');
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    renderLockoutUI(LoginLockout.remainingSeconds());
    if (!LoginLockout.isLocked()) {
        document.getElementById('username').focus();
    }
}

// 关闭验证弹窗
function closeAuthModal() {
    document.getElementById('authModal').classList.remove('active');
}

// 身份验证表单提交
let authSubmitting = false;
document.getElementById('authForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    // 限流期间或上一次提交未结束，不重复发起，避免网络重试重复计数
    if (LoginLockout.isLocked() || authSubmitting) return;

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const fileId = document.getElementById('downloadFileId').value;

    if (!username || !password) {
        document.getElementById('authError').textContent = '请输入用户名和密码';
        return;
    }

    authSubmitting = true;
    showLoading('验证身份...');

    try {
        const response = await fetch(`${API_BASE}/auth`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const result = await response.json();

        if (response.ok && result.success) {
            // 登录成功：解除任何本地限流提示，保存令牌并统一重绘
            LoginLockout.clear();
            TokenManager.save(result.token, username);
            closeAuthModal();
            await renderSessionUI();
            await loadFileList();

            if (fileId) {
                document.getElementById('loadingText').textContent = '验证成功，正在下载...';
                try {
                    const downloadResponse = await fetch(`${API_BASE}/download/${fileId}`, {
                        method: 'GET',
                        headers: {
                            'Authorization': `Bearer ${result.token}`
                        }
                    });
                    if (downloadResponse.ok) {
                        await saveBlobResponse(downloadResponse);
                    } else if (downloadResponse.status === 401) {
                        await handleProtectedUnauthorized();
                        document.getElementById('authError').textContent = '登录已过期，请重新验证';
                    } else {
                        const errResult = await downloadResponse.json();
                        openAuthModal(fileId);
                        document.getElementById('authError').textContent = `下载失败: ${errResult.error || '未知错误'}`;
                    }
                } catch (downloadError) {
                    openAuthModal(fileId);
                    document.getElementById('authError').textContent = `下载失败: ${downloadError.message}`;
                } finally {
                    hideLoading();
                }
            }
        } else if (response.status === 429) {
            // 剩余等待时间唯一以后端值为准，所有页面显示一致
            hideLoading();
            const retryAfter = result.retry_after ??
                (parseInt(response.headers.get('Retry-After'), 10) || 0);
            LoginLockout.start(retryAfter);
            renderLockoutUI(retryAfter);
        } else {
            hideLoading();
            document.getElementById('authError').textContent = result.error || '验证失败，请检查账号密码';
        }
    } catch (error) {
        hideLoading();
        // 网络失败不触发限流计时，允许用户立即重试
        document.getElementById('authError').textContent = `验证失败: ${error.message}`;
    } finally {
        authSubmitting = false;
        hideLoading();
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
            await handleProtectedUnauthorized();
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

    if (!(await TokenManager.isLoggedIn())) {
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
            await handleProtectedUnauthorized();
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
            await handleProtectedUnauthorized();
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
