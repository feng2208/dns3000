(function () {
    'use strict';

    const state = {
        currentTab: 'dashboard',
        logs: { page: 1, totalPages: 1, items: [] },
        rewrites: { page: 1, totalPages: 1, items: [] },
        devices: [],
        activeDevices: [],
        ruleGroups: [],
        services: [],
        deleteTarget: null,
        modalSaveAction: null,
        deviceEditor: null,
        ruleGroupEditor: null,
    };

    const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

    const text = {
        alertTitle: {
            error: '操作失败',
            success: '操作成功',
            info: '提示',
        },
        logStatus: {
            Blocked: '已拦截',
            Allowed: '已放行',
            Rewritten: '已重写',
        },
        deviceUnknown: '未知设备',
        noRuleGroups: '当前未配置规则组，运行时会回退到 default',
    };

    const $ = (selector, root = document) => root.querySelector(selector);
    const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

    function escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function byId(id) {
        return document.getElementById(id);
    }

    function setText(id, value) {
        const el = byId(id);
        if (el) el.textContent = value;
    }

    async function request(url, options = {}) {
        const response = await fetch(url, options);
        if (!response.ok) {
            const message = await response.text();
            throw new Error(message || `请求失败: ${response.status}`);
        }
        return response;
    }

    async function requestJson(url, options = {}) {
        const response = await request(url, options);
        const contentType = response.headers.get('content-type') || '';
        if (!contentType.includes('application/json')) return null;
        return response.json();
    }

    function formatStatus(status) {
        return text.logStatus[status] || status || '-';
    }

    function formatDateTime(value) {
        if (!value) return '-';
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return '-';
        return date.toLocaleString();
    }

    function formatTimeParts(value) {
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return { time: '-', date: '-' };
        return {
            time: date.toLocaleTimeString(),
            date: date.toLocaleDateString(),
        };
    }

    function openModal(id) {
        byId(id)?.classList.add('active');
    }

    function closeModal(id) {
        byId(id)?.classList.remove('active');
    }

    function showAlert(message, type = 'error') {
        const titleEl = byId('modal-alert-title');
        const messageEl = byId('modal-alert-message');
        const headerEl = byId('modal-alert-header');
        const iconEl = byId('modal-alert-icon');
        if (!titleEl || !messageEl || !headerEl || !iconEl) return;

        const variant = type === 'success' ? 'success' : type === 'info' ? 'info' : 'error';
        titleEl.textContent = text.alertTitle[variant];
        messageEl.textContent = message;

        if (variant === 'error') {
            headerEl.className = 'px-6 py-4 border-b flex items-center space-x-3 bg-red-50';
            iconEl.className = 'flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center bg-red-100';
            iconEl.innerHTML = `
                <svg class="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 15c-.77 1.333.192 3 1.732 3z" />
                </svg>
            `;
        } else {
            headerEl.className = 'px-6 py-4 border-b flex items-center space-x-3 bg-blue-50';
            iconEl.className = 'flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center bg-blue-100';
            iconEl.innerHTML = `
                <svg class="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
            `;
        }

        openModal('modal-alert');
    }

    function setModalEditor(title, contentHtml, saveAction) {
        setText('modal-edit-title', title);
        byId('modal-edit-content').innerHTML = contentHtml;
        state.modalSaveAction = saveAction;
        openModal('modal-edit');
    }

    function syncDeviceEditorFormState() {
        const editor = state.deviceEditor;
        if (!editor) return;

        const nameInput = byId('edit-name');
        const ipInput = byId('edit-ip');
        const idInput = byId('edit-id');

        if (nameInput) editor.device.name = nameInput.value;
        if (ipInput) editor.device.ip = ipInput.value;
        if (idInput) editor.device.id = idInput.value;
    }

    function syncRuleGroupEditorFormState() {
        const editor = state.ruleGroupEditor;
        if (!editor) return;

        const nameInput = byId('rg-edit-name');
        if (nameInput) editor.group.name = nameInput.value;
    }

    async function logout() {
        try {
            await request('/api/auth/logout');
            window.location.href = '/login.html';
        } catch (error) {
            console.error(error);
            showAlert(`退出登录失败: ${error.message}`);
        }
    }

    async function showTab(tabName) {
        state.currentTab = tabName;
        $$('[id^="tab-"]').forEach((el) => el.classList.add('hidden'));
        byId(`tab-${tabName}`)?.classList.remove('hidden');

        $$('.nav-link').forEach((el) => {
            el.classList.remove('text-primary', 'font-semibold');
            el.classList.add('text-gray-600');
        });

        const currentNav = byId(`nav-${tabName}`);
        currentNav?.classList.add('text-primary', 'font-semibold');
        currentNav?.classList.remove('text-gray-600');

        if (tabName === 'dashboard') {
            await Promise.allSettled([
                fetchStats(),
                fetchSettings(),
                fetchDevices(),
                fetchActiveDevices(),
                fetchRuleGroups(),
                fetchServices(),
                fetchUpstreams(),
            ]);
        } else if (tabName === 'logs') {
            await fetchLogs(1);
        } else if (tabName === 'rewrites') {
            await fetchRewrites(1);
        }
    }

    async function fetchStats() {
        try {
            const data = await requestJson('/api/stats');
            if (!data) return;
            setText('stat-total', data.total_queries ?? '-');
            setText('stat-blocked', data.blocked ?? '-');
            setText('stat-rewritten', data.rewritten ?? '-');
            setText('stat-allowed', data.allowed ?? '-');
            setText('stat-percentage', `${Number(data.blocked_percentage || 0).toFixed(1)}%`);
        } catch (error) {
            console.error(error);
        }
    }

    async function fetchSettings() {
        try {
            const data = await requestJson('/api/settings');
            if (!data) return;
            byId('log-count-input').value = data.log_count ?? '';
            byId('rule-update-interval-input').value = data.rule_update_interval || '24h';
        } catch (error) {
            console.error(error);
        }
    }

    async function saveSettings() {
        const logCount = Number.parseInt(byId('log-count-input').value, 10);
        const ruleUpdateInterval = byId('rule-update-interval-input').value.trim();

        try {
            await request('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    log_count: logCount,
                    rule_update_interval: ruleUpdateInterval,
                }),
            });
            showAlert('设置已保存', 'success');
        } catch (error) {
            showAlert(`保存设置失败: ${error.message}`);
        }
    }

    function updateLogsPagination(total, limit) {
        state.logs.totalPages = Math.max(1, Math.ceil(total / limit) || 1);
        setText('logs-info', `共 ${total} 条`);
        setText('page-info', `${state.logs.page} / ${state.logs.totalPages}`);
        byId('btn-prev').disabled = state.logs.page <= 1;
        byId('btn-next').disabled = state.logs.page >= state.logs.totalPages;
    }

    function renderLogsTable(logs) {
        const tbody = byId('logs-table-body');
        tbody.innerHTML = '';

        logs.forEach((log, index) => {
            const row = document.createElement('tr');
            row.className = 'cursor-pointer hover:bg-gray-50';
            row.dataset.action = 'show-log-details';
            row.dataset.index = String(index);

            const { time, date } = formatTimeParts(log.time);
            const statusClass = log.status === 'Blocked'
                ? 'text-red-600'
                : log.status === 'Rewritten'
                    ? 'text-yellow-600'
                    : 'text-green-600';
            const meta = log.rule || log.rule_group || (log.latency_ms !== undefined ? `${Number(log.latency_ms).toFixed(2)} ms` : '-');

            row.innerHTML = `
                <td class="px-4 py-3 text-sm text-gray-500">
                    <div>${escapeHtml(time)}</div>
                    <div class="text-xs">${escapeHtml(date)}</div>
                </td>
                <td class="px-4 py-3 text-sm">
                    <div class="font-medium text-gray-900">${escapeHtml(log.domain)}</div>
                    <div class="text-xs text-gray-500">类型: ${escapeHtml(log.type)}, ${escapeHtml(log.protocol)}</div>
                </td>
                <td class="px-4 py-3 text-sm">
                    <div class="font-medium ${statusClass}">${escapeHtml(formatStatus(log.status))}</div>
                    <div class="text-xs text-gray-500 truncate max-w-[150px]">${escapeHtml(meta)}</div>
                </td>
                <td class="px-4 py-3 text-sm">
                    <div class="text-gray-900">${escapeHtml(log.device_name || '-')}</div>
                    <div class="text-xs text-gray-500">${escapeHtml(log.device_ip)} (${escapeHtml(log.device_id || '-')})</div>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    async function fetchLogs(page) {
        if (page < 1) return;

        const params = new URLSearchParams({
            page: String(page),
            limit: '50',
            domain: byId('filter-domain').value,
            device: byId('filter-device').value,
            status: byId('filter-status').value,
        });

        try {
            const data = await requestJson(`/api/logs?${params.toString()}`);
            if (!data) return;
            state.logs.page = data.page || page;
            state.logs.items = data.logs || [];
            renderLogsTable(state.logs.items);
            updateLogsPagination(data.total || 0, data.limit || 50);
        } catch (error) {
            console.error(error);
            showAlert(`加载日志失败: ${error.message}`);
        }
    }

    function showLogDetails(index) {
        const log = state.logs.items[index];
        if (!log) return;

        let html = `
            <p><strong>状态:</strong> ${escapeHtml(formatStatus(log.status))}</p>
            <p><strong>耗时:</strong> ${escapeHtml(Number(log.latency_ms || 0).toFixed(2))} 毫秒</p>
            <p><strong>域名:</strong> ${escapeHtml(log.domain)}</p>
            <p><strong>类型:</strong> ${escapeHtml(log.type)}</p>
            <p><strong>协议:</strong> ${escapeHtml(log.protocol)}</p>
            <p><strong>设备:</strong> ${escapeHtml(log.device_name ? `${log.device_name} (${log.device_ip})` : (log.device_ip || '-'))}</p>
            <p><strong>设备 ID:</strong> ${escapeHtml(log.device_id || '-')}</p>
        `;

        if (log.upstream) html += `<p><strong>上游 DNS:</strong> ${escapeHtml(log.upstream)}</p>`;
        if (log.rule) html += `<p><strong>规则:</strong> <span class="text-xs bg-gray-100 px-1 py-0.5 rounded">${escapeHtml(log.rule)}</span></p>`;
        if (log.rule_group) html += `<p><strong>规则组:</strong> ${escapeHtml(log.rule_group)}</p>`;
        if (log.rule_source) html += `<p><strong>规则来源:</strong> ${escapeHtml(log.rule_source)}</p>`;
        if (log.response) {
            const responseLines = String(log.response).split('|').map((part) => `<div>${escapeHtml(part)}</div>`).join('');
            html += `
                <div class="mt-2">
                    <strong>响应:</strong>
                    <div class="mt-1 p-2 bg-gray-100 rounded border border-gray-200 font-mono text-xs whitespace-pre-wrap leading-relaxed shadow-sm">
                        ${responseLines}
                    </div>
                </div>
            `;
        }

        byId('modal-log-content').innerHTML = html;
        $('#modal-log-details h3').textContent = '日志详情';
        openModal('modal-log-details');
    }

    function updateRewritesPagination(total, limit) {
        state.rewrites.totalPages = Math.max(1, Math.ceil(total / limit) || 1);
        setText('rewrites-info', `共 ${total} 条`);
        setText('rewrites-page-info', `${state.rewrites.page} / ${state.rewrites.totalPages}`);
        byId('rewrites-btn-prev').disabled = state.rewrites.page <= 1;
        byId('rewrites-btn-next').disabled = state.rewrites.page >= state.rewrites.totalPages;
    }

    function renderRewritesTable(items) {
        const tbody = byId('rewrites-table-body');
        tbody.innerHTML = '';

        items.forEach((item, index) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="px-4 py-3 text-sm text-gray-900">${escapeHtml(item.name)}</td>
                <td class="px-4 py-3 text-sm text-gray-500">${escapeHtml(item.value)}</td>
                <td class="px-4 py-3 text-sm space-x-2">
                    <button type="button" data-action="edit-rewrite" data-index="${index}" class="text-blue-600 hover:underline">编辑</button>
                    <button type="button" data-action="delete-rewrite" data-index="${index}" class="text-red-600 hover:underline">删除</button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    async function fetchRewrites(page = 1) {
        state.rewrites.page = page;
        try {
            const data = await requestJson(`/api/rewrites?page=${page}&limit=20`);
            if (!data) return;
            state.rewrites.items = data.rewrites || [];
            renderRewritesTable(state.rewrites.items);
            updateRewritesPagination(data.total || 0, 20);
        } catch (error) {
            console.error(error);
            showAlert(`加载重写规则失败: ${error.message}`);
        }
    }

    async function addRewrite() {
        const name = byId('rewrite-name').value.trim();
        const value = byId('rewrite-value').value.trim();
        if (!name || !value) {
            showAlert('请填写域名和目标值');
            return;
        }

        try {
            await request('/api/rewrites', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, value }),
            });
            byId('rewrite-name').value = '';
            byId('rewrite-value').value = '';
            await fetchRewrites(1);
        } catch (error) {
            showAlert(`添加重写失败: ${error.message}`);
        }
    }

    function editRewrite(index) {
        const item = state.rewrites.items[index];
        if (!item) return;

        setModalEditor(
            '编辑重写',
            `
                <div>
                    <label class="block text-sm font-medium mb-1">域名</label>
                    <input type="text" id="edit-name" value="${escapeHtml(item.name)}" class="w-full border rounded px-3 py-2">
                </div>
                <div>
                    <label class="block text-sm font-medium mb-1">响应</label>
                    <input type="text" id="edit-value" value="${escapeHtml(item.value)}" class="w-full border rounded px-3 py-2">
                </div>
            `,
            async () => {
                try {
                    await request('/api/rewrites', {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            old_name: item.name,
                            name: byId('edit-name').value.trim(),
                            value: byId('edit-value').value.trim(),
                        }),
                    });
                    closeModal('modal-edit');
                    await fetchRewrites(state.rewrites.page);
                } catch (error) {
                    showAlert(`编辑重写失败: ${error.message}`);
                }
            },
        );
    }

    function summarizeDeviceRuleGroups(ruleGroups) {
        if (!ruleGroups || ruleGroups.length === 0) {
            return '<span class="text-gray-400 text-xs">default</span>';
        }

        return ruleGroups.map((group) => {
            const scheduleText = (group.schedules || [])
                .map((schedule) => {
                    const days = (schedule.days || []).join(', ');
                    const ranges = (schedule.ranges || []).join(', ');
                    return `${days} ${ranges}`.trim();
                })
                .filter(Boolean)
                .join('; ');

            return `
                <div class="mb-1">
                    <span class="inline-block bg-blue-100 text-blue-800 text-xs px-2 py-0.5 rounded">${escapeHtml(group.name)}</span>
                    ${scheduleText ? `<div class="text-gray-400 text-xs pl-2">skip: ${escapeHtml(scheduleText)}</div>` : ''}
                </div>
            `;
        }).join('');
    }

    function renderDevicesTable(items) {
        const tbody = byId('devices-table-body');
        tbody.innerHTML = '';

        items.forEach((device, index) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="px-4 py-3 text-sm text-gray-900">${escapeHtml(device.name)}</td>
                <td class="px-4 py-3 text-sm">
                    <div class="font-mono text-xs">
                        <div>${escapeHtml(device.id || '-')}</div>
                        <div class="text-gray-500">${escapeHtml(device.ip || '-')}</div>
                    </div>
                </td>
                <td class="px-4 py-3 text-sm text-gray-500">${summarizeDeviceRuleGroups(device.rule_groups)}</td>
                <td class="px-4 py-3 text-sm space-x-2">
                    <button type="button" data-action="edit-device" data-index="${index}" class="text-blue-600 hover:underline">编辑</button>
                    <button type="button" data-action="delete-device" data-index="${index}" class="text-red-600 hover:underline">删除</button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    async function fetchDevices() {
        try {
            state.devices = await requestJson('/api/devices') || [];
            renderDevicesTable(state.devices);
        } catch (error) {
            console.error(error);
            showAlert(`加载设备失败: ${error.message}`);
        }
    }

    function renderActiveDevicesTable(items) {
        const tbody = byId('active-devices-table-body');
        tbody.innerHTML = '';

        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="px-4 py-3 text-sm text-gray-500 text-center">暂无活跃设备</td></tr>';
            return;
        }

        items.forEach((device, index) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="px-4 py-3 text-sm text-gray-900">${escapeHtml(device.name || text.deviceUnknown)}</td>
                <td class="px-4 py-3 text-sm">
                    <div class="font-mono text-xs">
                        <div>${escapeHtml(device.id || '-')}</div>
                        <div class="text-gray-500">${escapeHtml(device.ip || '-')}</div>
                    </div>
                </td>
                <td class="px-4 py-3 text-sm text-gray-500">${escapeHtml(formatDateTime(device.last_seen))}</td>
                <td class="px-4 py-3 text-sm text-gray-500">${escapeHtml(device.query_count ?? 0)}</td>
                <td class="px-4 py-3 text-sm">
                    <button type="button" data-action="add-active-device" data-index="${index}" class="text-green-600 hover:underline">添加为设备</button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    async function fetchActiveDevices() {
        try {
            state.activeDevices = await requestJson('/api/active-devices') || [];
            renderActiveDevicesTable(state.activeDevices);
        } catch (error) {
            console.error(error);
            showAlert(`加载活跃设备失败: ${error.message}`);
        }
    }

    function createEmptyDevice() {
        return { name: '', ip: '', id: '', rule_groups: [] };
    }

    async function openDeviceEditor(device, isNew = false, refreshActiveDevices = false) {
        let availableRuleGroups = [];
        try {
            availableRuleGroups = await requestJson('/api/rule-groups') || [];
        } catch (error) {
            console.error(error);
        }

        state.deviceEditor = {
            device: JSON.parse(JSON.stringify(device)),
            isNew,
            refreshActiveDevices,
            availableRuleGroups,
            currentRuleGroups: JSON.parse(JSON.stringify(device.rule_groups || [])),
        };

        renderDeviceEditor();
    }

    function renderDeviceEditor() {
        const editor = state.deviceEditor;
        if (!editor) return;

        const options = editor.availableRuleGroups.map((group) => `
            <option value="${escapeHtml(group.name)}">${escapeHtml(group.name)}</option>
        `).join('');

        const ruleGroupsHtml = editor.currentRuleGroups.length === 0
            ? `<p class="text-xs text-gray-500 text-center py-4">${text.noRuleGroups}</p>`
            : editor.currentRuleGroups.map((group, groupIndex) => `
                <div class="border rounded p-3 bg-gray-50 relative">
                    <div class="flex justify-between items-start mb-2">
                        <span class="font-medium text-sm">${groupIndex + 1}. ${escapeHtml(group.name)}</span>
                        <div class="flex space-x-1">
                            <button type="button" data-action="device-editor-move-rule-group" data-index="${groupIndex}" data-direction="-1" class="p-1 hover:bg-gray-200 rounded" title="上移">↑</button>
                            <button type="button" data-action="device-editor-move-rule-group" data-index="${groupIndex}" data-direction="1" class="p-1 hover:bg-gray-200 rounded" title="下移">↓</button>
                            <button type="button" data-action="device-editor-remove-rule-group" data-index="${groupIndex}" class="p-1 hover:bg-red-100 text-red-600 rounded" title="移除">×</button>
                        </div>
                    </div>
                    <div class="space-y-2">
                        <div class="flex justify-between items-center">
                            <label class="text-xs font-semibold text-gray-600">时间表，命中时跳过该规则组</label>
                            <button type="button" data-action="device-editor-add-schedule" data-index="${groupIndex}" class="text-[10px] text-blue-600 hover:underline">+ 添加时间段</button>
                        </div>
                        ${(group.schedules || []).map((schedule, scheduleIndex) => `
                            <div class="bg-white p-2 border rounded text-xs space-y-1">
                                <div class="flex justify-between">
                                    <div class="flex flex-wrap gap-1">
                                        ${DAYS.map((day) => `
                                            <label class="inline-flex items-center mr-1">
                                                <input type="checkbox" class="mr-0.5" data-action="device-editor-toggle-day" data-group-index="${groupIndex}" data-schedule-index="${scheduleIndex}" data-day="${day}" ${schedule.days?.includes(day) ? 'checked' : ''}>
                                                ${day}
                                            </label>
                                        `).join('')}
                                    </div>
                                    <button type="button" data-action="device-editor-remove-schedule" data-group-index="${groupIndex}" data-schedule-index="${scheduleIndex}" class="text-red-500 hover:text-red-700">移除</button>
                                </div>
                                <div>
                                    <input type="text" value="${escapeHtml((schedule.ranges || []).join(', '))}" placeholder="10:00-12:00, 14:00-16:00" data-action="device-editor-update-ranges" data-group-index="${groupIndex}" data-schedule-index="${scheduleIndex}" class="w-full border rounded px-2 py-1 text-[11px]">
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `).join('');

        setModalEditor(
            editor.isNew ? '添加设备' : '编辑设备',
            `
                <div><label class="block text-sm font-medium mb-1">名称</label><input type="text" id="edit-name" value="${escapeHtml(editor.device.name || '')}" class="w-full border rounded px-3 py-2"></div>
                <div><label class="block text-sm font-medium mb-1">IP 地址</label><input type="text" id="edit-ip" value="${escapeHtml(editor.device.ip || '')}" class="w-full border rounded px-3 py-2"></div>
                <div><label class="block text-sm font-medium mb-1">设备 ID</label><input type="text" id="edit-id" value="${escapeHtml(editor.device.id || '')}" class="w-full border rounded px-3 py-2"></div>
                <p class="text-xs text-gray-400">IP 和 ID 只需填写一个；规则组为空时，运行时会默认使用 default。</p>
                <div class="mb-2 flex justify-between items-center">
                    <label class="block text-sm font-medium">规则组</label>
                    <div class="flex space-x-2">
                        <select id="device-add-rg-select" class="text-sm border rounded px-2 py-1">
                            <option value="">-- 选择规则组 --</option>
                            ${options}
                        </select>
                        <button type="button" data-action="device-editor-add-rule-group" class="bg-blue-500 text-white px-2 py-1 rounded text-xs">添加</button>
                    </div>
                </div>
                <div class="space-y-3 max-h-[400px] overflow-y-auto border-t pt-2">${ruleGroupsHtml}</div>
            `,
            saveDeviceEditor,
        );
    }

    async function saveDeviceEditor() {
        const editor = state.deviceEditor;
        if (!editor) return;

        syncDeviceEditorFormState();

        const ip = byId('edit-ip').value.trim();
        const id = byId('edit-id').value.trim();
        if (!ip && !id) {
            showAlert('请填写 IP 或 ID');
            return;
        }

        const payload = {
            name: byId('edit-name').value.trim(),
            ip,
            id,
            rule_groups: editor.currentRuleGroups
                .filter((group) => (group.name || '').trim())
                .map((group) => ({
                    name: group.name.trim(),
                    schedules: (group.schedules || []).map((schedule) => ({
                        days: schedule.days || [],
                        ranges: schedule.ranges || [],
                    })),
                })),
        };

        try {
            await request('/api/devices', {
                method: editor.isNew ? 'POST' : 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(editor.isNew ? payload : {
                    old_id: editor.device.id || '',
                    old_ip: editor.device.ip || '',
                    ...payload,
                }),
            });
            closeModal('modal-edit');
            await fetchDevices();
            if (editor.refreshActiveDevices) await fetchActiveDevices();
        } catch (error) {
            showAlert(`${editor.isNew ? '添加设备' : '更新设备'}失败: ${error.message}`);
        }
    }

    function showAddDeviceModal() {
        openDeviceEditor(createEmptyDevice(), true);
    }

    function editDevice(index) {
        openDeviceEditor(state.devices[index] || createEmptyDevice(), false);
    }

    function addActiveAsDevice(index) {
        const device = state.activeDevices[index];
        if (!device) return;
        openDeviceEditor({
            name: device.name !== text.deviceUnknown ? (device.name || '') : '',
            ip: device.ip || '',
            id: device.id || '',
            rule_groups: [],
        }, true, true);
    }

    function renderRuleGroupsTable(items) {
        const tbody = byId('rule-groups-table-body');
        tbody.innerHTML = '';

        items.forEach((group, index) => {
            const sourcesHtml = group.sources?.length
                ? group.sources.map((source) => {
                    let detail = '';
                    if (source.url) {
                        const truncated = source.url.length > 40 ? `${source.url.slice(0, 40)}...` : source.url;
                        detail = `<span class="text-gray-400 text-xs ml-1" title="${escapeHtml(source.url)}">(${escapeHtml(truncated)})</span>`;
                    } else if (source.services?.length) {
                        detail = `<span class="text-green-600 text-xs ml-1">(服务: ${escapeHtml(source.services.join(', '))})</span>`;
                    }
                    return `<div class="mb-1"><span class="inline-block bg-purple-100 text-purple-800 text-xs px-2 py-0.5 rounded">${escapeHtml(source.name)}</span>${detail}</div>`;
                }).join('')
                : '<span class="text-gray-400 text-xs">暂无来源</span>';

            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="px-4 py-3 text-sm text-gray-900">${escapeHtml(group.name)}</td>
                <td class="px-4 py-3 text-sm">${sourcesHtml}</td>
                <td class="px-4 py-3 text-sm space-x-2">
                    <button type="button" data-action="show-rule-group-details" data-index="${index}" class="text-gray-600 hover:underline">详情</button>
                    <button type="button" data-action="edit-rule-group" data-index="${index}" class="text-blue-600 hover:underline">编辑</button>
                    ${group.name === 'default' ? '' : `<button type="button" data-action="delete-rule-group" data-index="${index}" class="text-red-600 hover:underline">删除</button>`}
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    async function fetchRuleGroups() {
        try {
            state.ruleGroups = await requestJson('/api/rule-groups') || [];
            renderRuleGroupsTable(state.ruleGroups);
        } catch (error) {
            console.error(error);
            showAlert(`加载规则组失败: ${error.message}`);
        }
    }

    function showAddRuleGroupModal() {
        openRuleGroupEditor({ name: '', sources: [] }, true);
    }

    async function openRuleGroupEditor(group, isNew = false) {
        let allServices = [];
        try {
            allServices = await requestJson('/api/services') || [];
        } catch (error) {
            console.error(error);
        }

        state.ruleGroupEditor = {
            group: JSON.parse(JSON.stringify(group)),
            isNew,
            allServices,
            currentSources: JSON.parse(JSON.stringify(group.sources || [])),
        };

        renderRuleGroupEditor();
    }

    function renderRuleGroupEditor() {
        const editor = state.ruleGroupEditor;
        if (!editor) return;

        const sourcesHtml = editor.currentSources.length === 0
            ? '<p class="text-sm text-gray-500 text-center py-8">点击右上方按钮添加规则来源</p>'
            : editor.currentSources.map((source, index) => `
                <div class="border rounded-lg p-3 bg-white shadow-sm relative border-l-4 ${Object.prototype.hasOwnProperty.call(source, 'url') ? 'border-l-blue-400' : 'border-l-green-400'}">
                    <div class="flex justify-between items-center mb-3">
                        <div class="w-full mr-2">
                            <label class="block text-[10px] font-bold text-gray-400 uppercase leading-none mb-1">来源名称 <span class="text-red-400">(必填)</span></label>
                            <input type="text" value="${escapeHtml(source.name || '')}" data-action="rule-group-editor-update-name" data-index="${index}" class="text-sm font-semibold border rounded px-2 py-1 w-full focus:ring-1 focus:ring-blue-200">
                        </div>
                        <button type="button" data-action="rule-group-editor-remove-source" data-index="${index}" class="p-1.5 hover:bg-red-50 text-red-500 rounded-full transition-colors self-end" title="删除当前来源">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd" />
                            </svg>
                        </button>
                    </div>
                    <div class="flex items-center space-x-4 mb-3 border-t pt-2">
                        <label class="inline-flex items-center text-xs text-gray-600 cursor-pointer">
                            <input type="radio" name="src-type-${index}" class="form-radio text-blue-500 h-3 w-3" data-action="rule-group-editor-switch-type" data-index="${index}" data-type="url" ${Object.prototype.hasOwnProperty.call(source, 'url') ? 'checked' : ''}>
                            <span class="ml-1 font-medium">URL 订阅</span>
                        </label>
                        <label class="inline-flex items-center text-xs text-gray-600 cursor-pointer">
                            <input type="radio" name="src-type-${index}" class="form-radio text-green-500 h-3 w-3" data-action="rule-group-editor-switch-type" data-index="${index}" data-type="services" ${Object.prototype.hasOwnProperty.call(source, 'url') ? '' : 'checked'}>
                            <span class="ml-1 font-medium">内部服务引用</span>
                        </label>
                    </div>
                    <div>
                        ${Object.prototype.hasOwnProperty.call(source, 'url')
                    ? `<div><label class="block text-[10px] font-bold text-gray-400 uppercase leading-none mb-1">订阅 URL</label><input type="text" value="${escapeHtml(source.url || '')}" placeholder="https://example.com/rules.txt" data-action="rule-group-editor-update-url" data-index="${index}" class="w-full border rounded px-3 py-2 text-xs bg-gray-50 focus:bg-white transition-all"></div>`
                    : `<div><label class="block text-[10px] font-bold text-gray-400 uppercase leading-none mb-1">选择包含的服务</label><div class="bg-gray-50 border rounded p-2 max-h-32 overflow-y-auto mt-1"><div class="grid grid-cols-2 gap-x-2 gap-y-1">${editor.allServices.length === 0 ? '<p class="text-[10px] text-gray-400 col-span-2 italic text-center py-2">暂无可用服务</p>' : ''}${editor.allServices.map((service) => `<label class="inline-flex items-center text-[11px] truncate text-gray-700 hover:text-green-700 transition-colors"><input type="checkbox" class="rounded text-green-500 h-3 w-3 mr-1" data-action="rule-group-editor-toggle-service" data-index="${index}" data-service-name="${escapeHtml(service.name)}" ${source.services?.includes(service.name) ? 'checked' : ''}>${escapeHtml(service.name)}</label>`).join('')}</div></div></div>`}
                    </div>
                </div>
            `).join('');

        setModalEditor(
            editor.isNew ? '添加规则组' : '编辑规则组',
            `
                <div class="mb-4">
                    <label class="block text-sm font-medium mb-1">规则组名称</label>
                    <input type="text" id="rg-edit-name" value="${escapeHtml(editor.group.name || '')}" ${editor.isNew ? '' : 'readonly'} class="w-full border rounded px-3 py-2 ${editor.isNew ? '' : 'bg-gray-100'}" placeholder="例如 my-rules">
                </div>
                <div class="mb-2 flex justify-between items-center bg-gray-50 border-b pb-2">
                    <label class="block text-sm font-bold text-gray-700">规则来源</label>
                    <button type="button" data-action="rule-group-editor-add-source" class="bg-blue-600 text-white px-3 py-1.5 rounded text-sm hover:bg-blue-700 shadow-sm transition-colors">+ 添加规则来源</button>
                </div>
                <div id="rg-sources-list" class="space-y-4 max-h-[450px] overflow-y-auto mt-2 pr-1">${sourcesHtml}</div>
            `,
            saveRuleGroupEditor,
        );
    }

    async function saveRuleGroupEditor() {
        const editor = state.ruleGroupEditor;
        if (!editor) return;

        syncRuleGroupEditorFormState();

        const name = byId('rg-edit-name').value.trim();
        if (!name) {
            showAlert('请输入规则组名称');
            return;
        }

        for (let index = 0; index < editor.currentSources.length; index += 1) {
            if (!(editor.currentSources[index].name || '').trim()) {
                showAlert(`第 ${index + 1} 个规则来源必须填写名称`);
                return;
            }
        }

        const body = {
            name,
            sources: editor.currentSources.map((source) => Object.prototype.hasOwnProperty.call(source, 'url')
                ? { name: (source.name || '').trim(), url: (source.url || '').trim() }
                : { name: (source.name || '').trim(), services: source.services || [] }),
        };

        try {
            await request(editor.isNew ? '/api/rule-groups' : `/api/rule-groups?name=${encodeURIComponent(editor.group.name)}`, {
                method: editor.isNew ? 'POST' : 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            closeModal('modal-edit');
            await fetchRuleGroups();
        } catch (error) {
            showAlert(`保存规则组失败: ${error.message}`);
        }
    }

    function showRuleGroupDetails(index) {
        const group = state.ruleGroups[index];
        if (!group) return;

        let html = `<p><strong>名称:</strong> ${escapeHtml(group.name)}</p>`;
        if (group.sources?.length) {
            html += '<p class="mt-2 text-sm font-semibold text-gray-700">规则来源:</p><div class="space-y-2 mt-1">';
            group.sources.forEach((source) => {
                html += `
                    <div class="border rounded p-2 bg-gray-50 text-xs">
                        <div class="flex justify-between items-center mb-1">
                            <span class="font-medium text-gray-900">${escapeHtml(source.name)}</span>
                            <span class="px-1.5 py-0.5 rounded ${source.url ? 'bg-blue-100 text-blue-700' : 'bg-green-100 text-green-700'} text-[10px] uppercase font-bold">
                                ${source.url ? 'URL' : '服务'}
                            </span>
                        </div>
                        <div class="text-gray-600 break-all">${escapeHtml(source.url ? source.url : (source.services?.join(', ') || '未配置服务'))}</div>
                    </div>
                `;
            });
            html += '</div>';
        } else {
            html += '<p class="text-gray-500 mt-2 text-sm italic">暂无来源配置</p>';
        }

        byId('modal-log-content').innerHTML = html;
        $('#modal-log-details h3').textContent = '规则组详情';
        openModal('modal-log-details');
    }

    function renderServicesTable(items) {
        const tbody = byId('services-table-body');
        tbody.innerHTML = '';

        items.forEach((service, index) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="px-4 py-3 text-sm text-gray-900">${escapeHtml(service.name)}</td>
                <td class="px-4 py-3 text-sm text-gray-500">${escapeHtml(service.type || '-')}</td>
                <td class="px-4 py-3 text-sm space-x-2">
                    <button type="button" data-action="show-service-details" data-index="${index}" class="text-gray-600 hover:underline">详情</button>
                    <button type="button" data-action="edit-service" data-index="${index}" class="text-blue-600 hover:underline">编辑</button>
                    <button type="button" data-action="delete-service" data-index="${index}" class="text-red-600 hover:underline">删除</button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    async function fetchServices() {
        try {
            state.services = await requestJson('/api/services') || [];
            renderServicesTable(state.services);
        } catch (error) {
            console.error(error);
            showAlert(`加载服务失败: ${error.message}`);
        }
    }

    function showAddServiceModal() {
        setModalEditor(
            '添加服务',
            `
                <div><label class="block text-sm font-medium mb-1">名称</label><input type="text" id="edit-name" class="w-full border rounded px-3 py-2"></div>
                <div><label class="block text-sm font-medium mb-1">类型</label><input type="text" id="edit-type" class="w-full border rounded px-3 py-2" placeholder="例如 game, video"></div>
                <div><label class="block text-sm font-medium mb-1">规则内容</label><textarea id="edit-content" rows="5" class="w-full border rounded px-3 py-2" placeholder="每行一条规则"></textarea></div>
            `,
            async () => {
                try {
                    await request('/api/services', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            name: byId('edit-name').value.trim(),
                            type: byId('edit-type').value.trim(),
                            content: byId('edit-content').value,
                        }),
                    });
                    closeModal('modal-edit');
                    await fetchServices();
                } catch (error) {
                    showAlert(`添加服务失败: ${error.message}`);
                }
            },
        );
    }

    function showServiceDetails(index) {
        const service = state.services[index];
        if (!service) return;

        byId('modal-log-content').innerHTML = `
            <p><strong>名称:</strong> ${escapeHtml(service.name)}</p>
            <p><strong>类型:</strong> ${escapeHtml(service.type || '-')}</p>
            <p class="mt-2"><strong>规则内容:</strong></p>
            <pre class="bg-gray-100 p-2 rounded text-xs mt-1 max-h-60 overflow-auto">${escapeHtml(service.content || '-')}</pre>
        `;
        $('#modal-log-details h3').textContent = '服务详情';
        openModal('modal-log-details');
    }

    function editService(index) {
        const service = state.services[index];
        if (!service) return;

        setModalEditor(
            '编辑服务',
            `
                <div><label class="block text-sm font-medium mb-1">名称</label><input type="text" id="edit-name" value="${escapeHtml(service.name)}" class="w-full border rounded px-3 py-2"></div>
                <div><label class="block text-sm font-medium mb-1">类型</label><input type="text" id="edit-type" value="${escapeHtml(service.type || '')}" class="w-full border rounded px-3 py-2"></div>
                <div><label class="block text-sm font-medium mb-1">规则内容</label><textarea id="edit-content" rows="5" class="w-full border rounded px-3 py-2">${escapeHtml(service.content || '')}</textarea></div>
            `,
            async () => {
                try {
                    await request(`/api/services?name=${encodeURIComponent(service.name)}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            name: byId('edit-name').value.trim(),
                            type: byId('edit-type').value.trim(),
                            content: byId('edit-content').value,
                        }),
                    });
                    closeModal('modal-edit');
                    await fetchServices();
                } catch (error) {
                    showAlert(`更新服务失败: ${error.message}`);
                }
            },
        );
    }

    async function fetchUpstreams() {
        try {
            const data = await requestJson('/api/upstreams');
            if (!data) return;
            byId('upstreams-default').value = (data.default || []).join('\n');
            byId('upstreams-rules').value = (data.rules || []).join('\n');
        } catch (error) {
            console.error(error);
            showAlert(`加载上游配置失败: ${error.message}`);
        }
    }

    async function saveUpstreams() {
        const defaultUpstreams = byId('upstreams-default').value.split('\n').map((item) => item.trim()).filter(Boolean);
        const rules = byId('upstreams-rules').value.split('\n').map((item) => item.trim()).filter(Boolean);

        try {
            await request('/api/upstreams', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ default: defaultUpstreams, rules }),
            });
            showAlert('上游配置已保存', 'success');
        } catch (error) {
            showAlert(`保存上游配置失败: ${error.message}`);
        }
    }

    function confirmDelete(target) {
        state.deleteTarget = target;
        const displayKey = target.label || target.key || target.ip || '';
        setText('modal-confirm-text', `确定要删除 ${displayKey} 吗？`);
        openModal('modal-confirm');
    }

    async function doDelete() {
        if (!state.deleteTarget) return;

        const target = state.deleteTarget;
        let url = '';

        if (target.type === 'rewrite') {
            url = `/api/rewrites?name=${encodeURIComponent(target.key)}`;
        } else if (target.type === 'device') {
            url = target.key
                ? `/api/devices?id=${encodeURIComponent(target.key)}`
                : `/api/devices?ip=${encodeURIComponent(target.ip)}`;
        } else if (target.type === 'rule-group') {
            url = `/api/rule-groups?name=${encodeURIComponent(target.key)}`;
        } else if (target.type === 'service') {
            url = `/api/services?name=${encodeURIComponent(target.key)}`;
        }

        try {
            await request(url, { method: 'DELETE' });
            closeModal('modal-confirm');
            if (target.type === 'rewrite') await fetchRewrites(state.rewrites.page);
            if (target.type === 'device') await fetchDevices();
            if (target.type === 'rule-group') await fetchRuleGroups();
            if (target.type === 'service') await fetchServices();
        } catch (error) {
            showAlert(`删除失败: ${error.message}`);
        }
    }

    function handleDeviceEditorAction(action, element) {
        const editor = state.deviceEditor;
        if (!editor) return false;

        const index = Number.parseInt(element.dataset.index || '-1', 10);
        const groupIndex = Number.parseInt(element.dataset.groupIndex || '-1', 10);
        const scheduleIndex = Number.parseInt(element.dataset.scheduleIndex || '-1', 10);

        syncDeviceEditorFormState();

        if (action === 'device-editor-add-rule-group') {
            const select = byId('device-add-rg-select');
            if (!select?.value) return true;
            editor.currentRuleGroups.push({ name: select.value, schedules: [] });
            renderDeviceEditor();
            return true;
        }

        if (action === 'device-editor-remove-rule-group') {
            editor.currentRuleGroups.splice(index, 1);
            renderDeviceEditor();
            return true;
        }

        if (action === 'device-editor-move-rule-group') {
            const direction = Number.parseInt(element.dataset.direction || '0', 10);
            const targetIndex = index + direction;
            if (targetIndex < 0 || targetIndex >= editor.currentRuleGroups.length) return true;
            const temp = editor.currentRuleGroups[index];
            editor.currentRuleGroups[index] = editor.currentRuleGroups[targetIndex];
            editor.currentRuleGroups[targetIndex] = temp;
            renderDeviceEditor();
            return true;
        }

        if (action === 'device-editor-add-schedule') {
            const group = editor.currentRuleGroups[index];
            if (!group.schedules) group.schedules = [];
            group.schedules.push({ days: [...DAYS], ranges: [] });
            renderDeviceEditor();
            return true;
        }

        if (action === 'device-editor-remove-schedule') {
            editor.currentRuleGroups[groupIndex]?.schedules?.splice(scheduleIndex, 1);
            renderDeviceEditor();
            return true;
        }

        return false;
    }

    function handleDeviceEditorChange(action, element) {
        const editor = state.deviceEditor;
        if (!editor) return false;

        const groupIndex = Number.parseInt(element.dataset.groupIndex || '-1', 10);
        const scheduleIndex = Number.parseInt(element.dataset.scheduleIndex || '-1', 10);
        const schedule = editor.currentRuleGroups[groupIndex]?.schedules?.[scheduleIndex];
        if (!schedule) return false;

        if (action === 'device-editor-toggle-day') {
            const day = element.dataset.day;
            let days = schedule.days || [];
            if (element.checked && !days.includes(day)) days = [...days, day];
            if (!element.checked) days = days.filter((item) => item !== day);
            schedule.days = days;
            return true;
        }

        if (action === 'device-editor-update-ranges') {
            schedule.ranges = element.value.split(',').map((item) => item.trim()).filter(Boolean);
            return true;
        }

        return false;
    }

    function handleRuleGroupEditorAction(action, element) {
        const editor = state.ruleGroupEditor;
        if (!editor) return false;

        const index = Number.parseInt(element.dataset.index || '-1', 10);
        const source = editor.currentSources[index];

        syncRuleGroupEditorFormState();

        if (action === 'rule-group-editor-add-source') {
            editor.currentSources.push({ name: '', url: '' });
            renderRuleGroupEditor();
            return true;
        }

        if (action === 'rule-group-editor-remove-source') {
            editor.currentSources.splice(index, 1);
            renderRuleGroupEditor();
            return true;
        }

        if (action === 'rule-group-editor-switch-type' && source) {
            const nextType = element.dataset.type;
            const oldName = source.name || '';
            editor.currentSources[index] = nextType === 'url'
                ? { name: oldName, url: '' }
                : { name: oldName, services: [] };
            renderRuleGroupEditor();
            return true;
        }

        return false;
    }

    function handleRuleGroupEditorChange(action, element) {
        const editor = state.ruleGroupEditor;
        if (!editor) return false;

        const index = Number.parseInt(element.dataset.index || '-1', 10);
        const source = editor.currentSources[index];
        if (!source) return false;

        if (action === 'rule-group-editor-update-name') {
            source.name = element.value;
            return true;
        }

        if (action === 'rule-group-editor-update-url') {
            source.url = element.value;
            return true;
        }

        if (action === 'rule-group-editor-toggle-service') {
            const serviceName = element.dataset.serviceName || '';
            if (!source.services) source.services = [];
            if (element.checked) {
                if (!source.services.includes(serviceName)) source.services.push(serviceName);
            } else {
                source.services = source.services.filter((item) => item !== serviceName);
            }
            return true;
        }

        return false;
    }

    async function onAction(action, element) {
        if (!action) return;
        if (handleDeviceEditorAction(action, element)) return;
        if (handleRuleGroupEditorAction(action, element)) return;

        const index = Number.parseInt(element.dataset.index || '-1', 10);

        if (action === 'nav-tab') return showTab(element.dataset.tab);
        if (action === 'logout') return logout();
        if (action === 'save-settings') return saveSettings();
        if (action === 'refresh-active-devices') return fetchActiveDevices();
        if (action === 'show-add-device-modal') return showAddDeviceModal();
        if (action === 'show-add-rule-group-modal') return showAddRuleGroupModal();
        if (action === 'show-add-service-modal') return showAddServiceModal();
        if (action === 'save-upstreams') return saveUpstreams();
        if (action === 'fetch-logs') return fetchLogs(1);
        if (action === 'logs-prev') return fetchLogs(state.logs.page - 1);
        if (action === 'logs-next') return fetchLogs(state.logs.page + 1);
        if (action === 'add-rewrite') return addRewrite();
        if (action === 'rewrites-prev') return fetchRewrites(state.rewrites.page - 1);
        if (action === 'rewrites-next') return fetchRewrites(state.rewrites.page + 1);
        if (action === 'modal-close') return closeModal(element.dataset.modalId);
        if (action === 'modal-save' && typeof state.modalSaveAction === 'function') return state.modalSaveAction();
        if (action === 'modal-confirm-delete') {
            closeModal('modal-confirm');
            return doDelete();
        }
        if (action === 'show-log-details') return showLogDetails(index);
        if (action === 'edit-rewrite') return editRewrite(index);
        if (action === 'delete-rewrite') {
            const item = state.rewrites.items[index];
            if (item) confirmDelete({ type: 'rewrite', key: item.name, label: item.name });
            return;
        }
        if (action === 'edit-device') return editDevice(index);
        if (action === 'delete-device') {
            const device = state.devices[index];
            if (device) confirmDelete({ type: 'device', key: device.id || '', ip: device.ip || '', label: device.name || device.id || device.ip || '' });
            return;
        }
        if (action === 'add-active-device') return addActiveAsDevice(index);
        if (action === 'show-rule-group-details') return showRuleGroupDetails(index);
        if (action === 'edit-rule-group') {
            const group = state.ruleGroups[index];
            if (group) return openRuleGroupEditor(group, false);
            return;
        }
        if (action === 'delete-rule-group') {
            const group = state.ruleGroups[index];
            if (group) confirmDelete({ type: 'rule-group', key: group.name, label: group.name });
            return;
        }
        if (action === 'show-service-details') return showServiceDetails(index);
        if (action === 'edit-service') return editService(index);
        if (action === 'delete-service') {
            const service = state.services[index];
            if (service) confirmDelete({ type: 'service', key: service.name, label: service.name });
        }
    }

    function onChange(action, element) {
        if (handleDeviceEditorChange(action, element)) return;
        handleRuleGroupEditorChange(action, element);
    }

    function bindEvents() {
        document.addEventListener('click', async (event) => {
            const modalOverlay = event.target.closest('.modal-overlay');
            if (modalOverlay && event.target === modalOverlay) {
                closeModal(modalOverlay.id);
                return;
            }

            const actionEl = event.target.closest('[data-action]');
            if (!actionEl) return;

            const tagName = actionEl.tagName;
            if (tagName !== 'INPUT' && tagName !== 'SELECT' && tagName !== 'TEXTAREA') {
                event.preventDefault();
            }
            await onAction(actionEl.dataset.action, actionEl);
        });

        document.addEventListener('change', (event) => {
            const actionEl = event.target.closest('[data-action]');
            if (actionEl) onChange(actionEl.dataset.action, actionEl);
        });

        document.addEventListener('input', (event) => {
            const actionEl = event.target.closest('[data-action]');
            if (actionEl) onChange(actionEl.dataset.action, actionEl);
        });
    }

    function init() {
        bindEvents();
        showTab('dashboard');
    }

    document.addEventListener('DOMContentLoaded', init);
})();
