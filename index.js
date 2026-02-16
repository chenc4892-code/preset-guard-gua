/**
 * PresetGuard - SillyTavern 多内容类型加密保护扩展 v3.0
 *
 * 支持保护：预设(Preset)、角色卡(Character)、世界书(WorldBook)
 * - 从云端服务器下载加密内容并安装到酒馆
 * - 使用占位符替换加密内容，防止用户查看
 * - Fetch 拦截器在发送给 AI 时替换占位符为真实内容
 * - 管理员可配置加密字段并推送内容到服务器
 */

import { extension_settings, getContext } from '../../../extensions.js';
import { getRequestHeaders, saveSettingsDebounced, eventSource, event_types, getCharacters } from '../../../../script.js';
import { getChatCompletionPreset, openai_setting_names, openai_settings } from '../../../openai.js';
import { updateWorldInfoList } from '../../../world-info.js';

// ================================================================
//  常量
// ================================================================
const MODULE_NAME = 'preset-guard';
const PG_PLACEHOLDER_RE = /🔒PG:([a-f0-9-]+):([a-zA-Z0-9_.-]+)/g;

const INTERCEPT_URLS = [
    '/api/backends/chat-completions/generate',
    '/api/backends/text-completions/generate',
    '/api/backends/kobold/generate',
];

// 内容类型定义
const CONTENT_TYPES = {
    preset:    { label: '预设',   icon: 'fa-sliders' },
    theme:     { label: '主题',   icon: 'fa-palette' },
    character: { label: '角色卡', icon: 'fa-user' },
    worldbook: { label: '世界书', icon: 'fa-book' },
};

// 预设根级可加密文本字段
const ROOT_TEXT_FIELDS = [
    'impersonation_prompt', 'continue_nudge_prompt', 'new_chat_prompt',
    'new_group_chat_prompt', 'new_example_chat_prompt', 'group_nudge_prompt',
    'scenario_format', 'personality_format', 'wi_format', 'send_if_empty',
    'assistant_prefill', 'assistant_impersonation', 'continue_postfix',
];

// 角色卡可加密文本字段
const CHARACTER_TEXT_FIELDS = [
    { key: 'description', label: '描述 (Description)' },
    { key: 'personality', label: '性格 (Personality)' },
    { key: 'scenario', label: '场景 (Scenario)' },
    { key: 'first_mes', label: '第一条消息 (First Message)' },
    { key: 'mes_example', label: '对话示例 (Examples)' },
    { key: 'system_prompt', label: '系统提示 (System Prompt)' },
    { key: 'post_history_instructions', label: '历史后指令 (Post-History)' },
    { key: 'creator_notes', label: '创作者注释 (Creator Notes)' },
];


// ================================================================
//  默认设置
// ================================================================
const defaultSettings = {
    serverUrl: 'http://localhost:7123',
    token: null,
    user: null,
    installedPresets: {},      // 向后兼容
    installedContent: {        // 新的多类型存储
        preset: {},
        theme: {},
        character: {},
        worldbook: {},
    },
    _pendingEncryptedFields: null,
    _pendingContentType: null,
    _pendingWorldBookName: null,
    _pendingThemeName: null,
    _pendingDescription: null,
};

// ================================================================
//  内存 Vault（运行时存储解密内容，页面刷新即清空）
// ================================================================
const vault = {}; // { contentId: { fieldKey: "real content", ... } }

// ================================================================
//  设置管理
// ================================================================
function getSettings() {
    if (!extension_settings[MODULE_NAME]) {
        extension_settings[MODULE_NAME] = structuredClone(defaultSettings);
    }
    const s = extension_settings[MODULE_NAME];

    // 迁移: installedPresets → installedContent.preset
    if (!s.installedContent) {
        s.installedContent = { preset: {}, theme: {}, character: {}, worldbook: {} };
    }
    for (const type of Object.keys(CONTENT_TYPES)) {
        if (!s.installedContent[type]) s.installedContent[type] = {};
    }
    if (s.installedPresets && Object.keys(s.installedPresets).length > 0) {
        for (const [id, info] of Object.entries(s.installedPresets)) {
            if (!s.installedContent.preset[id]) {
                s.installedContent.preset[id] = info;
            }
        }
    }

    return s;
}

function saveSettings() {
    saveSettingsDebounced();
}

// ================================================================
//  工具函数
// ================================================================
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

function extractSessionKey(jwtToken) {
    try {
        const base64Url = jwtToken.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const payload = JSON.parse(atob(base64));
        return payload.sessionKey;
    } catch {
        return null;
    }
}

function isSuperAdmin() {
    return getSettings().user?.role === 'superadmin';
}

function isAdmin() {
    const role = getSettings().user?.role;
    return role === 'admin' || role === 'superadmin';
}

function isLoggedIn() {
    return !!getSettings().token;
}

function getCurrentPresetName() {
    return $('#settings_preset_openai option:selected').text();
}

function getCurrentPresetPGData() {
    try {
        const preset = getChatCompletionPreset();
        return preset?.extensions?.presetGuard || null;
    } catch {
        return null;
    }
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function blobToBase64(blob) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onloadend = () => resolve(reader.result.split(',')[1]);
        reader.onerror = reject;
        reader.readAsDataURL(blob);
    });
}

function base64ToBlob(base64, mime = 'image/png') {
    const binary = atob(base64);
    const array = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) array[i] = binary.charCodeAt(i);
    return new Blob([array], { type: mime });
}

// ================================================================
//  AES-256-GCM 纯 JS 回退（用于 HTTP 非安全上下文，crypto.subtle 不可用时）
// ================================================================
const AesGcmFallback = (() => {
    /* AES S-Box */
    const S = new Uint8Array([
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    ]);
    const RC = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

    function subW(w) { return (S[w>>>24&0xff]<<24|S[w>>>16&0xff]<<16|S[w>>>8&0xff]<<8|S[w&0xff])>>>0; }
    function rotW(w) { return (w<<8|w>>>24)>>>0; }
    function xt(a) { return ((a<<1)^(((a>>>7)&1)*0x1b))&0xff; }

    /* AES-256 密钥扩展 → 60 个 32-bit 字 (15 轮密钥) */
    function expandKey(k) {
        const W = new Uint32Array(60);
        for (let i = 0; i < 8; i++) W[i] = (k[4*i]<<24|k[4*i+1]<<16|k[4*i+2]<<8|k[4*i+3])>>>0;
        for (let i = 8; i < 60; i++) {
            let t = W[i-1];
            if (i%8===0) t = subW(rotW(t))^(RC[i/8-1]<<24);
            else if (i%8===4) t = subW(t);
            W[i] = (W[i-8]^t)>>>0;
        }
        return W;
    }

    /* AES 单块加密 (16 字节 → 16 字节) */
    function encBlock(inp, W) {
        const s = new Uint8Array(16);
        s.set(inp);
        /* AddRoundKey round 0 */
        for (let i = 0; i < 4; i++) {
            const w = W[i];
            s[4*i]^=w>>>24&0xff; s[4*i+1]^=w>>>16&0xff; s[4*i+2]^=w>>>8&0xff; s[4*i+3]^=w&0xff;
        }
        for (let r = 1; r <= 14; r++) {
            /* SubBytes */
            for (let i = 0; i < 16; i++) s[i] = S[s[i]];
            /* ShiftRows */
            let t=s[1];s[1]=s[5];s[5]=s[9];s[9]=s[13];s[13]=t;
            t=s[2];s[2]=s[10];s[10]=t; t=s[6];s[6]=s[14];s[14]=t;
            t=s[15];s[15]=s[11];s[11]=s[7];s[7]=s[3];s[3]=t;
            /* MixColumns (skip last round) */
            if (r < 14) {
                for (let c = 0; c < 4; c++) {
                    const a=s[4*c],b=s[4*c+1],d=s[4*c+2],e=s[4*c+3];
                    s[4*c]=xt(a)^xt(b)^b^d^e; s[4*c+1]=a^xt(b)^xt(d)^d^e;
                    s[4*c+2]=a^b^xt(d)^xt(e)^e; s[4*c+3]=xt(a)^a^b^d^xt(e);
                }
            }
            /* AddRoundKey */
            for (let i = 0; i < 4; i++) {
                const w = W[4*r+i];
                s[4*i]^=w>>>24&0xff; s[4*i+1]^=w>>>16&0xff; s[4*i+2]^=w>>>8&0xff; s[4*i+3]^=w&0xff;
            }
        }
        return s;
    }

    /* GF(2^128) 乘法 (GHASH 核心) */
    function gfMul(x, h) {
        const v = new Uint8Array(h); /* 拷贝 h */
        const z = new Uint8Array(16);
        for (let i = 0; i < 128; i++) {
            if ((x[i>>>3]>>>(7-(i&7)))&1) for (let j = 0; j < 16; j++) z[j]^=v[j];
            const lb = v[15]&1;
            for (let j = 15; j > 0; j--) v[j]=(v[j]>>>1)|((v[j-1]&1)<<7);
            v[0]=v[0]>>>1; if (lb) v[0]^=0xe1;
        }
        return z;
    }

    /* GHASH(H, ciphertext) — AAD 为空 */
    function ghash(h, c) {
        let x = new Uint8Array(16);
        const nb = Math.ceil(c.length/16);
        for (let i = 0; i < nb; i++) {
            const bl = new Uint8Array(16), st = i*16;
            bl.set(c.subarray(st, Math.min(st+16, c.length)));
            for (let j = 0; j < 16; j++) x[j]^=bl[j];
            x = gfMul(x, h);
        }
        /* length block: 64-bit AAD bits (0) || 64-bit CT bits */
        const lb = new Uint8Array(16);
        const bits = c.length*8;
        lb[12]=(bits>>>24)&0xff; lb[13]=(bits>>>16)&0xff; lb[14]=(bits>>>8)&0xff; lb[15]=bits&0xff;
        for (let j = 0; j < 16; j++) x[j]^=lb[j];
        return gfMul(x, h);
    }

    function incCtr(c) { for (let i = 15; i >= 12; i--) { c[i]++; if (c[i]) break; } }

    /* AES-256-GCM 解密 + 认证标签验证 */
    function decrypt(key, iv, ct, tag) {
        const W = expandKey(key);
        const h = encBlock(new Uint8Array(16), W);
        /* J0: 初始计数器 */
        const j0 = new Uint8Array(16);
        if (iv.length === 12) { j0.set(iv); j0[15] = 1; }
        else { j0.set(ghash(h, iv)); }
        /* CTR 模式解密（从 J0+1 开始） */
        const ctr = new Uint8Array(j0);
        incCtr(ctr);
        const pt = new Uint8Array(ct.length);
        for (let i = 0, nb = Math.ceil(ct.length/16); i < nb; i++) {
            const ks = encBlock(ctr, W), st = i*16;
            for (let j = st; j < Math.min(st+16, ct.length); j++) pt[j]=ct[j]^ks[j-st];
            incCtr(ctr);
        }
        /* 验证认证标签 */
        const gt = ghash(h, ct), ej = encBlock(j0, W);
        for (let i = 0; i < 16; i++) gt[i]^=ej[i];
        let ok = true;
        for (let i = 0; i < tag.length; i++) if (gt[i]!==tag[i]) ok = false;
        if (!ok) throw new Error('AES-GCM authentication tag mismatch');
        return pt.buffer;
    }

    return { decrypt };
})();

// ================================================================
//  传输解密（AES-256-GCM，使用 sessionKey 原始字节作为密钥）
// ================================================================
async function decryptTransport(transportEncrypted, sessionKey) {
    const keyBytes = hexToBytes(sessionKey);
    const iv = hexToBytes(transportEncrypted.iv);
    const encData = hexToBytes(transportEncrypted.encrypted);
    const authTag = hexToBytes(transportEncrypted.authTag);

    let decrypted;
    if (typeof crypto !== 'undefined' && crypto.subtle) {
        const key = await crypto.subtle.importKey(
            'raw', keyBytes, 'AES-GCM', false, ['decrypt'],
        );
        const combined = new Uint8Array(encData.length + authTag.length);
        combined.set(encData);
        combined.set(authTag, encData.length);
        decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            combined,
        );
    } else {
        console.warn('[PresetGuard] crypto.subtle 不可用 (非安全上下文/HTTP), 使用纯JS解密回退');
        decrypted = AesGcmFallback.decrypt(keyBytes, iv, encData, authTag);
    }

    return new TextDecoder().decode(decrypted);
}

// ================================================================
//  服务器 API 客户端
// ================================================================
async function pgFetch(path, options = {}) {
    const settings = getSettings();
    const url = `${settings.serverUrl}${path}`;
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers,
    };

    if (settings.token) {
        headers['Authorization'] = `Bearer ${settings.token}`;
    }

    const response = await fetch(url, {
        ...options,
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined,
    });

    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
        throw Object.assign(
            new Error(error.error || `请求失败: ${response.status}`),
            { status: response.status },
        );
    }

    return response.json();
}

async function apiLogin(username, password) {
    const data = await pgFetch('/api/auth/login', {
        method: 'POST',
        body: { username, password },
    });
    const settings = getSettings();
    settings.token = data.token;
    settings.user = data.user;
    saveSettings();
    return data;
}

async function apiRegister(username, password, inviteCode) {
    const data = await pgFetch('/api/auth/register', {
        method: 'POST',
        body: { username, password, inviteCode },
    });
    const settings = getSettings();
    settings.token = data.token;
    settings.user = data.user;
    saveSettings();
    return data;
}

// ---- 旧的预设 API（向后兼容）----
async function apiGetPresets() {
    return pgFetch('/api/presets');
}

async function apiDownloadPreset(presetId) {
    return pgFetch(`/api/presets/${presetId}/download`);
}

async function apiCreatePreset(name, description, content, encryptedFields) {
    return pgFetch('/api/presets', {
        method: 'POST',
        body: { name, description, content, encryptedFields },
    });
}

async function apiUpdatePreset(presetId, data) {
    return pgFetch(`/api/presets/${presetId}`, {
        method: 'PUT',
        body: data,
    });
}

async function apiCheckUpdates(presetVersions) {
    return pgFetch('/api/presets/check-updates', {
        method: 'POST',
        body: { presetVersions },
    });
}

// ---- 通用内容 API（v3）----
async function apiGetContent(type) {
    return pgFetch(`/api/content?type=${type}`);
}

async function apiGetAllContent() {
    return pgFetch('/api/content');
}

async function apiDownloadContent(contentId) {
    return pgFetch(`/api/content/${contentId}/download`);
}

async function apiCreateContent(type, name, description, content, encryptedFields) {
    return pgFetch('/api/content', {
        method: 'POST',
        body: { type, name, description, content, encryptedFields },
    });
}

async function apiUpdateContent(contentId, data) {
    return pgFetch(`/api/content/${contentId}`, {
        method: 'PUT',
        body: data,
    });
}

async function apiReportEvent(event, details = {}) {
    try {
        await pgFetch('/api/audit/event', {
            method: 'POST',
            body: { event, details },
        });
    } catch {
        // 静默失败
    }
}

async function apiFollowAuthor(inviteCode) {
    return pgFetch('/api/auth/follow', {
        method: 'POST',
        body: { inviteCode },
    });
}

async function apiUnfollowAuthor(authorId) {
    return pgFetch('/api/auth/unfollow', {
        method: 'POST',
        body: { authorId },
    });
}

async function apiGetMe() {
    return pgFetch('/api/auth/me');
}

async function apiPromoteUser(userId) {
    return pgFetch(`/api/users/${userId}/promote`, {
        method: 'POST',
    });
}

async function apiFeedbackSubmit(contentId, { emoji, comment, messageContent }) {
    return pgFetch(`/api/feedback/${contentId}/submit`, {
        method: 'POST',
        body: { emoji, comment, messageContent },
    });
}

async function apiGetFeedback(contentId) {
    return pgFetch(`/api/feedback/${contentId}`);
}

// ================================================================
//  Vault 管理
// ================================================================

/**
 * 从服务器下载所有已安装内容并填充 Vault
 */
async function populateVault() {
    const settings = getSettings();
    if (!settings.token) return;

    const sessionKey = extractSessionKey(settings.token);
    if (!sessionKey) {
        console.warn('[PresetGuard] 无法从令牌中提取会话密钥');
        return;
    }

    // 加载所有类型的已安装内容
    for (const [type, contents] of Object.entries(settings.installedContent)) {
        for (const [contentId, info] of Object.entries(contents)) {
            if (vault[contentId]) continue; // 已加载
            try {
                const downloadData = await apiDownloadContent(contentId);
                const decryptedStr = await decryptTransport(
                    downloadData.transportEncrypted, sessionKey,
                );
                const fullContent = JSON.parse(decryptedStr);
                const ef = downloadData.encryptedFields || info.encryptedFields || {};

                buildVaultEntry(type, contentId, fullContent, ef);

                console.log(
                    `[PresetGuard] Vault 已加载 ${type}: ${info.localName}` +
                    ` (${Object.keys(vault[contentId] || {}).length} 个字段)`,
                );
            } catch (err) {
                // 服务端已删除的内容（404）：静默清理本地记录
                if (err.status === 404) {
                    console.log(`[PresetGuard] 服务端已删除 ${type}:${contentId}，清理本地记录`);
                    delete contents[contentId];
                    saveSettings();
                    continue;
                }
                console.error(`[PresetGuard] 加载失败 ${type}:${contentId}`, err);
                toastr.warning(
                    `PresetGuard: 无法加载 "${info.localName}"，加密内容将不可用`,
                );
            }
        }
    }
}

/**
 * 根据内容类型构建 Vault 条目
 */
function buildVaultEntry(type, contentId, fullContent, encryptedFields) {
    vault[contentId] = {};

    switch (type) {
        case 'preset':
            // 提示词条目
            if (encryptedFields.prompts && fullContent.prompts) {
                for (const identifier of encryptedFields.prompts) {
                    const prompt = fullContent.prompts.find(p => p.identifier === identifier);
                    if (prompt?.content) {
                        vault[contentId][identifier] = prompt.content;
                    }
                }
            }
            // 根级字段
            if (encryptedFields.rootFields) {
                for (const fieldName of encryptedFields.rootFields) {
                    if (fullContent[fieldName]) {
                        vault[contentId][fieldName] = fullContent[fieldName];
                    }
                }
            }
            break;

        case 'character':
            if (encryptedFields.fields) {
                const charData = fullContent.data || fullContent;
                for (const fieldName of encryptedFields.fields) {
                    if (charData[fieldName] !== undefined && charData[fieldName] !== '') {
                        vault[contentId][fieldName] = charData[fieldName];
                    }
                }
            }
            // 角色世界书条目
            if (encryptedFields.characterBookEntries) {
                const charData = fullContent.data || fullContent;
                const cb = charData.character_book;
                if (cb?.entries) {
                    const entries = cb.entries;
                    for (const uid of encryptedFields.characterBookEntries) {
                        const entry = Array.isArray(entries)
                            ? entries.find(e => e.uid === uid || e.id === uid)
                            : entries[String(uid)];
                        if (entry?.content) {
                            vault[contentId][`cb_entry_${uid}`] = entry.content;
                        }
                    }
                }
            }
            // 正则脚本
            if (encryptedFields.regexScripts) {
                const charData = fullContent.data || fullContent;
                const scripts = charData.extensions?.regex_scripts;
                if (Array.isArray(scripts)) {
                    for (const idx of encryptedFields.regexScripts) {
                        if (scripts[idx]) {
                            vault[contentId][`regex_${idx}`] = structuredClone(scripts[idx]);
                        }
                    }
                }
            }
            break;

        case 'worldbook':
            if (encryptedFields.entries && fullContent.entries) {
                for (const uid of encryptedFields.entries) {
                    const entry = fullContent.entries[String(uid)];
                    if (entry?.content) {
                        vault[contentId][`entry_${uid}`] = entry.content;
                    }
                }
            }
            break;

        case 'theme':
            if (encryptedFields.fields) {
                for (const fieldName of encryptedFields.fields) {
                    if (fullContent[fieldName] !== undefined) {
                        vault[contentId][fieldName] = fullContent[fieldName];
                    }
                }
            }
            break;
    }
}

function clearVault() {
    for (const key of Object.keys(vault)) {
        delete vault[key];
    }
}

// ================================================================
//  预设操作（保留原有功能）
// ================================================================

function createProtectedPreset(fullPreset, encryptedFields, contentId) {
    const protectedCopy = structuredClone(fullPreset);

    if (encryptedFields.prompts && protectedCopy.prompts) {
        for (const identifier of encryptedFields.prompts) {
            const prompt = protectedCopy.prompts.find(p => p.identifier === identifier);
            if (prompt && prompt.content !== undefined) {
                prompt.content = `🔒PG:${contentId}:${identifier}`;
            }
        }
    }

    if (encryptedFields.rootFields) {
        for (const fieldName of encryptedFields.rootFields) {
            if (protectedCopy[fieldName] !== undefined && protectedCopy[fieldName] !== '') {
                protectedCopy[fieldName] = `🔒PG:${contentId}:${fieldName}`;
            }
        }
    }

    if (!protectedCopy.extensions) protectedCopy.extensions = {};
    protectedCopy.extensions.presetGuard = {
        contentId,
        version: 'unknown',
        encryptedFields,
        isProtected: true,
        type: 'preset',
    };

    return protectedCopy;
}

async function savePresetToTavern(name, presetJson) {
    const response = await fetch('/api/presets/save', {
        method: 'POST',
        headers: getRequestHeaders(),
        body: JSON.stringify({
            apiId: 'openai',
            name: name,
            preset: presetJson,
        }),
    });

    if (!response.ok) {
        throw new Error('保存预设到酒馆失败');
    }

    const data = await response.json();

    if (Object.keys(openai_setting_names).includes(data.name)) {
        const idx = openai_setting_names[data.name];
        Object.assign(openai_settings[idx], presetJson);
        $(`#settings_preset_openai option[value="${idx}"]`).prop('selected', true);
        $('#settings_preset_openai').trigger('change');
    } else {
        openai_settings.push(presetJson);
        const idx = openai_settings.length - 1;
        openai_setting_names[data.name] = idx;
        const option = document.createElement('option');
        option.selected = true;
        option.value = String(idx);
        option.innerText = data.name;
        $('#settings_preset_openai').append(option).trigger('change');
    }

    return data.name;
}

async function installPreset(serverContentId) {
    const settings = getSettings();
    const sessionKey = extractSessionKey(settings.token);
    if (!sessionKey) throw new Error('会话密钥无效');

    const downloadData = await apiDownloadPreset(serverContentId);
    const decryptedStr = await decryptTransport(
        downloadData.transportEncrypted, sessionKey,
    );
    const fullPreset = JSON.parse(decryptedStr);
    const encryptedFields = downloadData.encryptedFields || {};

    const protectedPreset = createProtectedPreset(
        fullPreset, encryptedFields, serverContentId,
    );
    protectedPreset.extensions.presetGuard.version = downloadData.version;

    // Vault
    buildVaultEntry('preset', serverContentId, fullPreset, encryptedFields);

    const localName = await savePresetToTavern(downloadData.name, protectedPreset);

    settings.installedContent.preset[serverContentId] = {
        localName,
        version: downloadData.version,
        encryptedFields,
    };
    // 向后兼容
    settings.installedPresets[serverContentId] = settings.installedContent.preset[serverContentId];
    saveSettings();

    return localName;
}

async function pushPreset(changelogMessage) {
    const settings = getSettings();
    const currentPreset = getChatCompletionPreset();
    const presetName = getCurrentPresetName();
    const pgData = currentPreset?.extensions?.presetGuard;

    if (!currentPreset) {
        throw new Error('无法读取当前预设');
    }

    const hasPlaceholders = currentPreset.prompts?.some(p =>
        typeof p.content === 'string' && p.content.includes('🔒PG:'),
    ) || Object.values(currentPreset).some(v =>
        typeof v === 'string' && v.includes('🔒PG:'),
    );

    if (hasPlaceholders && pgData?.contentId && !vault[pgData.contentId]) {
        throw new Error('加密内容未加载，请确保服务器可访问并刷新页面后重试');
    }

    const encryptedFields = settings._pendingEncryptedFields ||
        pgData?.encryptedFields ||
        { prompts: [], rootFields: [] };

    const cleanPreset = structuredClone(currentPreset);

    // 还原占位符
    const pid = pgData?.contentId || pgData?.presetId;
    if (pgData?.isProtected && pid && vault[pid]) {
        if (cleanPreset.prompts) {
            for (const prompt of cleanPreset.prompts) {
                const match = prompt.content?.match?.(/🔒PG:([^:]+):(.+)/);
                if (match) {
                    const [, cid, fid] = match;
                    if (vault[cid]?.[fid]) prompt.content = vault[cid][fid];
                }
            }
        }
        for (const [key, val] of Object.entries(cleanPreset)) {
            if (typeof val === 'string') {
                const match = val.match(/🔒PG:([^:]+):(.+)/);
                if (match) {
                    const [, cid, fid] = match;
                    if (vault[cid]?.[fid]) cleanPreset[key] = vault[cid][fid];
                }
            }
        }
    }

    if (cleanPreset.extensions?.presetGuard) {
        delete cleanPreset.extensions.presetGuard;
    }

    if (pid) {
        const result = await apiUpdatePreset(pid, {
            name: presetName,
            content: cleanPreset,
            encryptedFields,
            changelogMessage: changelogMessage || undefined,
        });

        const protectedPreset = createProtectedPreset(cleanPreset, encryptedFields, pid);
        protectedPreset.extensions.presetGuard.version = result.version;
        await savePresetToTavern(presetName, protectedPreset);

        buildVaultEntry('preset', pid, cleanPreset, encryptedFields);

        settings.installedContent.preset[pid] = {
            localName: presetName,
            version: result.version,
            encryptedFields,
        };
        settings.installedPresets[pid] = settings.installedContent.preset[pid];
        settings._pendingEncryptedFields = null;
        saveSettings();
        return result;

    } else {
        const result = await apiCreatePreset(
            presetName, '', cleanPreset, encryptedFields,
        );

        const protectedPreset = createProtectedPreset(cleanPreset, encryptedFields, result.id);
        protectedPreset.extensions.presetGuard.version = '1.0.0';
        await savePresetToTavern(presetName, protectedPreset);

        buildVaultEntry('preset', result.id, cleanPreset, encryptedFields);

        settings.installedContent.preset[result.id] = {
            localName: presetName,
            version: '1.0.0',
            encryptedFields,
        };
        settings.installedPresets[result.id] = settings.installedContent.preset[result.id];
        settings._pendingEncryptedFields = null;
        saveSettings();
        return result;
    }
}

// ================================================================
//  角色卡操作
// ================================================================

function createProtectedCharacter(fullCharData, encryptedFields, contentId) {
    const protectedCopy = structuredClone(fullCharData);
    const data = protectedCopy.data || protectedCopy;

    console.log('[PresetGuard] createProtectedCharacter 入参:', {
        hasDataWrapper: !!protectedCopy.data,
        hasCharacterBook: !!data.character_book,
        cbEntriesType: data.character_book?.entries ? (Array.isArray(data.character_book.entries) ? 'array' : 'object') : 'null',
        cbEntriesCount: data.character_book?.entries ? (Array.isArray(data.character_book.entries) ? data.character_book.entries.length : Object.keys(data.character_book.entries).length) : 0,
        encryptedCBEntries: encryptedFields.characterBookEntries,
        hasRegexScripts: !!data.extensions?.regex_scripts,
        regexCount: data.extensions?.regex_scripts?.length,
        encryptedRegex: encryptedFields.regexScripts,
    });

    // 文本字段占位符
    if (encryptedFields.fields) {
        for (const fieldName of encryptedFields.fields) {
            if (data[fieldName] !== undefined && data[fieldName] !== '') {
                data[fieldName] = `🔒PG:${contentId}:${fieldName}`;
            }
        }
    }

    // 角色世界书条目占位符
    if (encryptedFields.characterBookEntries && data.character_book?.entries) {
        const entries = data.character_book.entries;
        for (const uid of encryptedFields.characterBookEntries) {
            const entry = Array.isArray(entries)
                ? entries.find(e => e.uid === uid || e.id === uid)
                : entries[String(uid)];
            console.log(`[PresetGuard] CB entry lookup uid=${uid}:`, {
                found: !!entry,
                hasContent: entry ? entry.content !== undefined : false,
                contentPreview: entry?.content ? String(entry.content).substring(0, 50) : null,
                entryKeys: entry ? Object.keys(entry) : null,
            });
            if (entry && entry.content !== undefined && entry.content !== '') {
                entry.content = `🔒PG:${contentId}:cb_entry_${uid}`;
            }
        }
    } else {
        console.warn('[PresetGuard] 跳过 character_book 加密:', {
            hasCBEntries: !!encryptedFields.characterBookEntries,
            cbEntriesLength: encryptedFields.characterBookEntries?.length,
            hasCharacterBook: !!data.character_book,
            hasEntries: !!data.character_book?.entries,
        });
    }

    // 正则脚本占位符（加密 findRegex、replaceString、placement）
    if (encryptedFields.regexScripts && Array.isArray(data.extensions?.regex_scripts)) {
        for (const idx of encryptedFields.regexScripts) {
            const script = data.extensions.regex_scripts[idx];
            if (script) {
                script.findRegex = `🔒PG:${contentId}:regex_${idx}`;
                script.replaceString = `🔒PG:${contentId}:regex_${idx}_replace`;
                script.placement = [];
            }
        }
    }

    // 写入 PG 标记到 extensions
    if (!data.extensions) data.extensions = {};
    data.extensions.presetGuard = {
        contentId,
        version: 'unknown',
        encryptedFields,
        isProtected: true,
        type: 'character',
    };

    return protectedCopy;
}

async function installCharacter(serverContentId) {
    const settings = getSettings();
    const sessionKey = extractSessionKey(settings.token);
    if (!sessionKey) throw new Error('会话密钥无效');

    const downloadData = await apiDownloadContent(serverContentId);
    const decryptedStr = await decryptTransport(
        downloadData.transportEncrypted, sessionKey,
    );
    const fullContent = JSON.parse(decryptedStr);
    const encryptedFields = downloadData.encryptedFields || {};

    // fullContent 格式: { name, description, ..., extensions, character_book, avatar_base64 }
    const charName = fullContent.name || downloadData.name;
    const avatarBase64 = fullContent.avatar_base64;

    console.log('[PresetGuard] installCharacter 下载内容:', {
        hasCharacterBook: !!fullContent.character_book,
        cbEntryCount: fullContent.character_book?.entries ? (Array.isArray(fullContent.character_book.entries) ? fullContent.character_book.entries.length : Object.keys(fullContent.character_book.entries).length) : 0,
        hasDataWrapper: !!fullContent.data,
        hasRegexScripts: !!fullContent.extensions?.regex_scripts,
        regexCount: fullContent.extensions?.regex_scripts?.length,
        encryptedFields: JSON.stringify(encryptedFields),
        topLevelKeys: Object.keys(fullContent).filter(k => k !== 'avatar_base64'),
    });

    // 构建受保护版本（替换加密字段为占位符）
    const protectedData = createProtectedCharacter(fullContent, encryptedFields, serverContentId);
    protectedData.extensions = protectedData.extensions || {};
    protectedData.extensions.presetGuard = {
        contentId: serverContentId,
        version: downloadData.version,
        encryptedFields,
        isProtected: true,
        type: 'character',
    };

    // 构建 V2 Spec JSON 用于 /api/characters/import
    const v2Json = {
        spec: 'chara_card_v2',
        spec_version: '2.0',
        data: {
            name: protectedData.name || charName,
            description: protectedData.description || '',
            personality: protectedData.personality || '',
            scenario: protectedData.scenario || '',
            first_mes: protectedData.first_mes || '',
            mes_example: protectedData.mes_example || '',
            system_prompt: protectedData.system_prompt || '',
            post_history_instructions: protectedData.post_history_instructions || '',
            creator_notes: protectedData.creator_notes || '',
            creator: protectedData.creator || '',
            character_version: protectedData.character_version || '',
            tags: protectedData.tags || [],
            alternate_greetings: protectedData.alternate_greetings || [],
            extensions: protectedData.extensions || {},
        },
        // V1 顶层字段（向后兼容）
        name: protectedData.name || charName,
        description: protectedData.description || '',
        personality: protectedData.personality || '',
        scenario: protectedData.scenario || '',
        first_mes: protectedData.first_mes || '',
        mes_example: protectedData.mes_example || '',
    };

    // 添加角色世界书到 V2 data
    if (protectedData.character_book) {
        v2Json.data.character_book = protectedData.character_book;
    }

    // 验证 V2 JSON 内容
    console.log('[PresetGuard] V2 JSON 构建结果:', {
        hasCharacterBook: !!v2Json.data.character_book,
        cbEntryCount: v2Json.data.character_book?.entries?.length || 0,
        firstEntrySample: v2Json.data.character_book?.entries?.[0]
            ? { id: v2Json.data.character_book.entries[0].id, contentPreview: String(v2Json.data.character_book.entries[0].content).substring(0, 60) }
            : null,
        hasRegex: !!v2Json.data.extensions?.regex_scripts,
        regexCount: v2Json.data.extensions?.regex_scripts?.length,
        firstRegexSample: v2Json.data.extensions?.regex_scripts?.[0]
            ? { findRegexPreview: String(v2Json.data.extensions.regex_scripts[0].findRegex).substring(0, 60) }
            : null,
    });

    // 通过 /api/characters/import 上传 V2 JSON
    const jsonBlob = new Blob([JSON.stringify(v2Json)], { type: 'application/json' });
    const formData = new FormData();
    formData.append('avatar', jsonBlob, `${charName}.json`);
    formData.append('file_type', 'json');

    const headers = getRequestHeaders();
    delete headers['Content-Type'];

    const importResp = await fetch('/api/characters/import', {
        method: 'POST',
        headers,
        body: formData,
    });

    if (!importResp.ok) {
        const errText = await importResp.text().catch(() => '');
        throw new Error(`导入角色失败: ${importResp.status} ${errText}`);
    }

    const importResult = await importResp.json();
    const fileName = importResult.file_name; // 内部 PNG 文件名（无扩展名）
    console.log(`[PresetGuard] 角色导入成功: ${fileName}`);

    // 如果有头像，补充上传头像（需传递全部字段以避免 charaFormatData 覆盖为空）
    if (avatarBase64 && fileName) {
        try {
            const avatarBlob = base64ToBlob(avatarBase64, 'image/png');
            const editForm = new FormData();
            editForm.append('avatar_url', `${fileName}.png`);
            editForm.append('avatar', avatarBlob, `${charName}.png`);
            editForm.append('json_data', JSON.stringify(v2Json));
            editForm.append('ch_name', charName);
            editForm.append('description', protectedData.description || '');
            editForm.append('personality', protectedData.personality || '');
            editForm.append('scenario', protectedData.scenario || '');
            editForm.append('first_mes', protectedData.first_mes || '');
            editForm.append('mes_example', protectedData.mes_example || '');
            editForm.append('system_prompt', protectedData.system_prompt || '');
            editForm.append('post_history_instructions', protectedData.post_history_instructions || '');
            editForm.append('creator_notes', protectedData.creator_notes || '');
            editForm.append('creator', protectedData.creator || '');
            editForm.append('character_version', protectedData.character_version || '');
            editForm.append('tags', Array.isArray(protectedData.tags) ? protectedData.tags.join(',') : '');
            editForm.append('talkativeness', String(protectedData.talkativeness ?? 0.5));
            editForm.append('fav', 'false');
            editForm.append('extensions', JSON.stringify(protectedData.extensions || {}));
            if (Array.isArray(protectedData.alternate_greetings)) {
                for (const g of protectedData.alternate_greetings) {
                    editForm.append('alternate_greetings', g);
                }
            }

            const editHeaders = getRequestHeaders();
            delete editHeaders['Content-Type'];

            const editResp = await fetch('/api/characters/edit', {
                method: 'POST',
                headers: editHeaders,
                body: editForm,
            });
            if (editResp.ok) {
                console.log('[PresetGuard] 角色头像上传成功');
            } else {
                console.warn('[PresetGuard] 角色头像上传失败，使用默认头像');
            }
        } catch (e) {
            console.warn('[PresetGuard] 角色头像上传出错:', e);
        }
    }

    const localName = charName;

    // Vault
    buildVaultEntry('character', serverContentId, fullContent, encryptedFields);

    settings.installedContent.character[serverContentId] = {
        localName,
        version: downloadData.version,
        encryptedFields,
    };
    saveSettings();

    // 刷新角色列表让新角色出现
    try { await getCharacters(); } catch { /* ignore */ }

    // ====== 安装后验证：读回角色数据检查加密是否生效 ======
    if (fileName) {
        try {
            const verifyResp = await fetch('/api/characters/get', {
                method: 'POST',
                headers: getRequestHeaders(),
                body: JSON.stringify({ avatar_url: `${fileName}.png` }),
            });
            if (verifyResp.ok) {
                const verifyData = await verifyResp.json();
                const vd = verifyData.data || verifyData;
                const vReport = {
                    description: vd.description ? (vd.description.startsWith('🔒PG:') ? '✅加密' : '❌明文: ' + vd.description.substring(0, 40)) : '⚠️空',
                    hasCharacterBook: !!vd.character_book,
                    cbEntries: [],
                    hasRegexScripts: !!vd.extensions?.regex_scripts,
                    regexScripts: [],
                    hasPGMeta: !!vd.extensions?.presetGuard,
                    pgMetaEF: vd.extensions?.presetGuard?.encryptedFields ? JSON.stringify(vd.extensions.presetGuard.encryptedFields) : 'N/A',
                };
                if (vd.character_book?.entries) {
                    const entries = Array.isArray(vd.character_book.entries)
                        ? vd.character_book.entries
                        : Object.values(vd.character_book.entries);
                    for (const e of entries) {
                        const uid = e.uid ?? e.id ?? '?';
                        vReport.cbEntries.push({
                            uid,
                            encrypted: typeof e.content === 'string' && e.content.startsWith('🔒PG:'),
                            preview: String(e.content || '').substring(0, 50),
                        });
                    }
                }
                if (Array.isArray(vd.extensions?.regex_scripts)) {
                    for (let i = 0; i < vd.extensions.regex_scripts.length; i++) {
                        const s = vd.extensions.regex_scripts[i];
                        vReport.regexScripts.push({
                            idx: i,
                            findRegexEncrypted: typeof s.findRegex === 'string' && s.findRegex.startsWith('🔒PG:'),
                            replaceEncrypted: typeof s.replaceString === 'string' && s.replaceString.startsWith('🔒PG:'),
                            placementCleared: Array.isArray(s.placement) && s.placement.length === 0,
                            findRegexPreview: String(s.findRegex || '').substring(0, 50),
                            replacePreview: String(s.replaceString || '').substring(0, 50),
                        });
                    }
                }
                console.log('[PresetGuard] ====== 安装后验证报告 ======');
                console.log(JSON.stringify(vReport, null, 2));
                if (vReport.cbEntries.some(e => !e.encrypted) && encryptedFields.characterBookEntries?.length) {
                    console.error('[PresetGuard] ❌❌❌ 角色世界书条目未正确加密！请检查上方日志。');
                }
                if (vReport.regexScripts.some(s => !s.findRegexEncrypted) && encryptedFields.regexScripts?.length) {
                    console.error('[PresetGuard] ❌❌❌ 正则脚本未正确加密！请检查上方日志。');
                }
            }
        } catch (e) {
            console.warn('[PresetGuard] 安装后验证失败:', e);
        }
    }

    // ====== 关键：同步加密独立世界书文件 ======
    // 角色 PNG 里的 character_book 已加密，但 SillyTavern 实际使用的是独立的世界书文件
    // （通过 extensions.world 链接）。如果不同步加密独立文件，用户看到的仍然是明文。
    const worldName = protectedData.extensions?.world;
    if (worldName && encryptedFields.characterBookEntries?.length) {
        try {
            const wiResp = await fetch('/api/worldinfo/get', {
                method: 'POST',
                headers: getRequestHeaders(),
                body: JSON.stringify({ name: worldName }),
            });
            if (wiResp.ok) {
                const wiData = await wiResp.json();
                if (wiData?.entries) {
                    let modified = false;
                    for (const uid of encryptedFields.characterBookEntries) {
                        const entry = wiData.entries[String(uid)];
                        if (entry && entry.content && typeof entry.content === 'string'
                            && !entry.content.startsWith('🔒PG:')) {
                            entry.content = `🔒PG:${serverContentId}:cb_entry_${uid}`;
                            modified = true;
                        }
                    }
                    if (modified) {
                        // 注入 PG 元数据到世界书文件，以便保存拦截器保护
                        wiData._presetGuard = {
                            isProtected: true,
                            contentId: serverContentId,
                            type: 'character_world',
                            encryptedFields: { entries: encryptedFields.characterBookEntries },
                            vaultKeyPrefix: 'cb_entry_',
                        };
                        await fetch('/api/worldinfo/edit', {
                            method: 'POST',
                            headers: getRequestHeaders(),
                            body: JSON.stringify({ name: worldName, data: wiData }),
                        });
                        console.log(`[PresetGuard] 已同步加密独立世界书文件: ${worldName} (${encryptedFields.characterBookEntries.length} 条条目)`);
                    }
                } else {
                    console.log(`[PresetGuard] 独立世界书 ${worldName} 没有条目`);
                }
            } else {
                console.log(`[PresetGuard] 独立世界书 ${worldName} 不存在，跳过同步`);
            }
        } catch (e) {
            console.warn('[PresetGuard] 同步加密独立世界书失败:', e);
        }
    }

    // ====== 同步加密独立正则脚本（如果角色加载后正则在内存中运行） ======
    // 正则已通过 restoreCharacterRegex 在内存中恢复，这里不需要额外处理独立文件
    // 正则脚本存储在角色 PNG 的 extensions.regex_scripts 中，不是独立文件

    return localName;
}

async function pushCharacter(changelogMessage) {
    const settings = getSettings();
    const context = getContext();
    const charIndex = context.characterId;

    if (charIndex === undefined || charIndex < 0) {
        throw new Error('请先选择一个角色');
    }

    // 获取完整角色数据
    const charBasic = context.characters[charIndex];
    if (!charBasic?.avatar) throw new Error('无法读取角色数据');

    const response = await fetch('/api/characters/get', {
        method: 'POST',
        headers: getRequestHeaders(),
        body: JSON.stringify({ avatar_url: charBasic.avatar }),
    });
    if (!response.ok) throw new Error('获取角色详情失败');
    const fullChar = await response.json();

    // 获取头像 base64
    let avatarBase64 = null;
    try {
        const avatarResp = await fetch(`/characters/${charBasic.avatar}`);
        if (avatarResp.ok) {
            const blob = await avatarResp.blob();
            avatarBase64 = await blobToBase64(blob);
        }
    } catch { /* 头像获取失败不影响推送 */ }

    // 构建上传内容
    const charData = fullChar.data || fullChar;

    // 始终优先从独立世界书文件加载 character_book（因为 PNG 里嵌入的可能是过期数据）
    let characterBook = null;
    if (charData.extensions?.world) {
        try {
            const wiResp = await fetch('/api/worldinfo/get', {
                method: 'POST',
                headers: getRequestHeaders(),
                body: JSON.stringify({ name: charData.extensions.world }),
            });
            if (wiResp.ok) {
                const wiData = await wiResp.json();
                if (wiData?.entries) {
                    const cbEntries = [];
                    for (const [key, entry] of Object.entries(wiData.entries)) {
                        cbEntries.push({
                            id: entry.uid ?? Number(key),
                            keys: entry.key || [],
                            secondary_keys: entry.keysecondary || [],
                            comment: entry.comment || '',
                            content: entry.content || '',
                            constant: entry.constant || false,
                            selective: entry.selective || false,
                            insertion_order: entry.order || 100,
                            enabled: !entry.disable,
                            position: entry.position ?? 'before_char',
                            case_sensitive: entry.caseSensitive ?? true,
                            use_regex: entry.useRegex ?? false,
                            extensions: entry.extensions || {},
                        });
                    }
                    characterBook = { entries: cbEntries, name: charData.extensions.world };
                    console.log(`[PresetGuard] 从独立世界书 "${charData.extensions.world}" 加载 ${cbEntries.length} 条条目（优先于 PNG 嵌入数据）`);
                }
            }
        } catch (e) {
            console.warn('[PresetGuard] 加载独立世界书失败:', e);
        }
    }
    // 回退：如果独立文件不存在或加载失败，使用 PNG 嵌入的 character_book
    if (!characterBook && charData.character_book) {
        characterBook = structuredClone(charData.character_book);
        console.log('[PresetGuard] 使用 PNG 嵌入的 character_book（独立文件不可用）');
    }

    console.log('[PresetGuard] pushCharacter character_book 状态:', {
        fromCharData: !!charData.character_book,
        fromWorldInfo: !charData.character_book && !!characterBook,
        final: !!characterBook,
        entryCount: characterBook?.entries ? (Array.isArray(characterBook.entries) ? characterBook.entries.length : Object.keys(characterBook.entries).length) : 0,
        worldLink: charData.extensions?.world || null,
    });

    const uploadContent = {
        name: charData.name || charBasic.name,
        description: charData.description || '',
        personality: charData.personality || '',
        scenario: charData.scenario || '',
        first_mes: charData.first_mes || '',
        mes_example: charData.mes_example || '',
        system_prompt: charData.system_prompt || '',
        post_history_instructions: charData.post_history_instructions || '',
        creator_notes: charData.creator_notes || '',
        creator: charData.creator || '',
        character_version: charData.character_version || '',
        tags: charData.tags || [],
        talkativeness: charData.extensions?.talkativeness ?? 0.5,
        alternate_greetings: charData.alternate_greetings || [],
        extensions: structuredClone(charData.extensions || {}),
        character_book: characterBook,
        avatar_base64: avatarBase64,
    };

    // 还原文本字段占位符
    for (const [key, val] of Object.entries(uploadContent)) {
        if (typeof val === 'string') {
            const match = val.match(/🔒PG:([^:]+):(.+)/);
            if (match) {
                const [, cid, fid] = match;
                if (vault[cid]?.[fid]) uploadContent[key] = vault[cid][fid];
            }
        }
    }

    // 还原 character_book 条目占位符
    if (uploadContent.character_book?.entries) {
        const entries = uploadContent.character_book.entries;
        const entryList = Array.isArray(entries) ? entries : Object.values(entries);
        for (const entry of entryList) {
            if (typeof entry.content === 'string') {
                const match = entry.content.match(/🔒PG:([^:]+):(.+)/);
                if (match) {
                    const [, cid, fid] = match;
                    if (vault[cid]?.[fid]) entry.content = vault[cid][fid];
                }
            }
        }
    }

    // 还原 regex_scripts 占位符
    if (Array.isArray(uploadContent.extensions?.regex_scripts)) {
        for (let i = 0; i < uploadContent.extensions.regex_scripts.length; i++) {
            const script = uploadContent.extensions.regex_scripts[i];
            if (typeof script.findRegex === 'string' && script.findRegex.startsWith('🔒PG:')) {
                const match = script.findRegex.match(/🔒PG:([^:]+):(.+)/);
                if (match) {
                    const [, cid, fid] = match;
                    const realScript = vault[cid]?.[fid];
                    if (realScript) {
                        Object.assign(script, realScript);
                    }
                }
            }
        }
    }

    // 查找 encryptedFields：优先使用待定配置，其次角色 PG 元数据，再次已安装记录
    let installedEF = null;
    const charNameForLookup = uploadContent.name;
    for (const [id, info] of Object.entries(settings.installedContent?.character || {})) {
        if (info.localName === charNameForLookup && info.encryptedFields) {
            installedEF = info.encryptedFields;
            break;
        }
    }
    const encryptedFields = settings._pendingEncryptedFields ||
        charData.extensions?.presetGuard?.encryptedFields ||
        installedEF ||
        { fields: [] };

    console.log('[PresetGuard] pushCharacter encryptedFields 来源:', {
        fromPending: !!settings._pendingEncryptedFields,
        fromCharMeta: !!charData.extensions?.presetGuard?.encryptedFields,
        fromInstalled: !!installedEF && !settings._pendingEncryptedFields && !charData.extensions?.presetGuard?.encryptedFields,
        result: JSON.stringify(encryptedFields),
    });

    const existingId = charData.extensions?.presetGuard?.contentId ||
        findContentIdByLocalName('character', uploadContent.name);

    // 推送前最终验证
    console.log('[PresetGuard] pushCharacter 最终上传内容验证:', {
        hasCharacterBook: !!uploadContent.character_book,
        cbEntryCount: uploadContent.character_book?.entries
            ? (Array.isArray(uploadContent.character_book.entries) ? uploadContent.character_book.entries.length : Object.keys(uploadContent.character_book.entries).length)
            : 0,
        cbFirstEntry: (() => {
            const entries = uploadContent.character_book?.entries;
            if (!entries) return null;
            const first = Array.isArray(entries) ? entries[0] : Object.values(entries)[0];
            return first ? { id: first.id ?? first.uid, contentPreview: String(first.content || '').substring(0, 50) } : null;
        })(),
        hasRegex: !!uploadContent.extensions?.regex_scripts,
        regexCount: uploadContent.extensions?.regex_scripts?.length,
        regexFirst: uploadContent.extensions?.regex_scripts?.[0]
            ? { findRegex: String(uploadContent.extensions.regex_scripts[0].findRegex || '').substring(0, 50) }
            : null,
        encryptedFields: JSON.stringify(encryptedFields),
        existingId,
    });

    if (existingId) {
        const result = await apiUpdateContent(existingId, {
            name: uploadContent.name,
            content: uploadContent,
            encryptedFields,
            changelogMessage: changelogMessage || undefined,
        });

        buildVaultEntry('character', existingId, uploadContent, encryptedFields);

        settings.installedContent.character[existingId] = {
            localName: uploadContent.name,
            version: result.version,
            encryptedFields,
        };
        settings._pendingEncryptedFields = null;
        settings._pendingContentType = null;
        saveSettings();
        return result;
    } else {
        const result = await apiCreateContent(
            'character', uploadContent.name, '', uploadContent, encryptedFields,
        );

        buildVaultEntry('character', result.id, uploadContent, encryptedFields);

        settings.installedContent.character[result.id] = {
            localName: uploadContent.name,
            version: '1.0.0',
            encryptedFields,
        };
        settings._pendingEncryptedFields = null;
        settings._pendingContentType = null;
        saveSettings();
        return result;
    }
}

// ================================================================
//  世界书操作
// ================================================================

function createProtectedWorldBook(fullWorldData, encryptedFields, contentId) {
    const protectedCopy = structuredClone(fullWorldData);

    if (encryptedFields.entries && protectedCopy.entries) {
        for (const uid of encryptedFields.entries) {
            const entry = protectedCopy.entries[String(uid)];
            if (entry && entry.content !== undefined && entry.content !== '') {
                entry.content = `🔒PG:${contentId}:entry_${uid}`;
            }
        }
    }

    protectedCopy._presetGuard = {
        contentId,
        version: 'unknown',
        encryptedFields,
        isProtected: true,
        type: 'worldbook',
    };

    return protectedCopy;
}

async function installWorldBook(serverContentId) {
    const settings = getSettings();
    const sessionKey = extractSessionKey(settings.token);
    if (!sessionKey) throw new Error('会话密钥无效');

    const downloadData = await apiDownloadContent(serverContentId);
    const decryptedStr = await decryptTransport(
        downloadData.transportEncrypted, sessionKey,
    );
    const fullWorldData = JSON.parse(decryptedStr);
    const encryptedFields = downloadData.encryptedFields || {};

    const protectedWorld = createProtectedWorldBook(
        fullWorldData, encryptedFields, serverContentId,
    );
    protectedWorld._presetGuard.version = downloadData.version;

    // 保存到酒馆
    const worldName = downloadData.name;
    const response = await fetch('/api/worldinfo/edit', {
        method: 'POST',
        headers: getRequestHeaders(),
        body: JSON.stringify({
            name: worldName,
            data: protectedWorld,
        }),
    });

    if (!response.ok) {
        throw new Error('保存世界书到酒馆失败');
    }

    buildVaultEntry('worldbook', serverContentId, fullWorldData, encryptedFields);

    settings.installedContent.worldbook[serverContentId] = {
        localName: worldName,
        version: downloadData.version,
        encryptedFields,
    };
    saveSettings();

    // 刷新世界书下拉列表（使用酒馆内置函数更新 world_names 和 UI）
    try {
        await updateWorldInfoList();
    } catch { /* 刷新失败不影响安装结果 */ }

    return worldName;
}

async function pushWorldBook(worldBookName, changelogMessage) {
    const settings = getSettings();

    if (!worldBookName) throw new Error('请指定世界书名称');

    // 获取世界书数据
    const response = await fetch('/api/worldinfo/get', {
        method: 'POST',
        headers: getRequestHeaders(),
        body: JSON.stringify({ name: worldBookName }),
    });
    if (!response.ok) throw new Error('获取世界书数据失败');
    const fullWorldData = await response.json();

    // 还原占位符
    if (fullWorldData.entries) {
        for (const [uid, entry] of Object.entries(fullWorldData.entries)) {
            if (typeof entry.content === 'string') {
                const match = entry.content.match(/🔒PG:([^:]+):(.+)/);
                if (match) {
                    const [, cid, fid] = match;
                    if (vault[cid]?.[fid]) entry.content = vault[cid][fid];
                }
            }
        }
    }

    const encryptedFields = settings._pendingEncryptedFields ||
        fullWorldData._presetGuard?.encryptedFields ||
        { entries: [] };

    // 清理 PG 元数据
    const cleanData = structuredClone(fullWorldData);
    delete cleanData._presetGuard;

    const existingId = fullWorldData._presetGuard?.contentId ||
        findContentIdByLocalName('worldbook', worldBookName);

    if (existingId) {
        const result = await apiUpdateContent(existingId, {
            name: worldBookName,
            content: cleanData,
            encryptedFields,
            changelogMessage: changelogMessage || undefined,
        });

        const protectedWorld = createProtectedWorldBook(cleanData, encryptedFields, existingId);
        protectedWorld._presetGuard.version = result.version;
        await fetch('/api/worldinfo/edit', {
            method: 'POST',
            headers: getRequestHeaders(),
            body: JSON.stringify({ name: worldBookName, data: protectedWorld }),
        });

        buildVaultEntry('worldbook', existingId, cleanData, encryptedFields);

        settings.installedContent.worldbook[existingId] = {
            localName: worldBookName,
            version: result.version,
            encryptedFields,
        };
        settings._pendingEncryptedFields = null;
        settings._pendingContentType = null;
        saveSettings();
        return result;
    } else {
        const result = await apiCreateContent(
            'worldbook', worldBookName, '', cleanData, encryptedFields,
        );

        const protectedWorld = createProtectedWorldBook(cleanData, encryptedFields, result.id);
        protectedWorld._presetGuard.version = '1.0.0';
        await fetch('/api/worldinfo/edit', {
            method: 'POST',
            headers: getRequestHeaders(),
            body: JSON.stringify({ name: worldBookName, data: protectedWorld }),
        });

        buildVaultEntry('worldbook', result.id, cleanData, encryptedFields);

        settings.installedContent.worldbook[result.id] = {
            localName: worldBookName,
            version: '1.0.0',
            encryptedFields,
        };
        settings._pendingEncryptedFields = null;
        settings._pendingContentType = null;
        saveSettings();
        return result;
    }
}

// ================================================================
//  主题操作
// ================================================================

function createProtectedTheme(fullTheme, encryptedFields, contentId) {
    const protectedCopy = structuredClone(fullTheme);

    if (encryptedFields.fields) {
        for (const fieldName of encryptedFields.fields) {
            if (protectedCopy[fieldName] !== undefined && protectedCopy[fieldName] !== '') {
                protectedCopy[fieldName] = `🔒PG:${contentId}:${fieldName}`;
            }
        }
    }

    protectedCopy._presetGuard = {
        contentId,
        version: 'unknown',
        encryptedFields,
        isProtected: true,
        type: 'theme',
    };

    return protectedCopy;
}

async function installTheme(serverContentId) {
    const settings = getSettings();
    const sessionKey = extractSessionKey(settings.token);
    if (!sessionKey) throw new Error('会话密钥无效');

    const downloadData = await apiDownloadContent(serverContentId);
    const decryptedStr = await decryptTransport(
        downloadData.transportEncrypted, sessionKey,
    );
    const fullTheme = JSON.parse(decryptedStr);
    const encryptedFields = downloadData.encryptedFields || {};

    console.log(`[PresetGuard] 安装主题: 解密成功, custom_css 长度=${(fullTheme.custom_css || '').length}, 字段数=${Object.keys(fullTheme).length}`);

    const protectedTheme = createProtectedTheme(
        fullTheme, encryptedFields, serverContentId,
    );
    protectedTheme._presetGuard.version = downloadData.version;

    // 保存到酒馆
    const themeName = downloadData.name || fullTheme.name;
    protectedTheme.name = themeName;

    const response = await fetch('/api/themes/save', {
        method: 'POST',
        headers: getRequestHeaders(),
        body: JSON.stringify(protectedTheme),
    });

    if (!response.ok) {
        throw new Error('保存主题到酒馆失败');
    }

    buildVaultEntry('theme', serverContentId, fullTheme, encryptedFields);

    settings.installedContent.theme[serverContentId] = {
        localName: themeName,
        version: downloadData.version,
        encryptedFields,
    };
    saveSettings();

    // 刷新主题下拉列表并重载主题数据到内存
    try {
        const $select = $('#themes');
        if ($select.length) {
            const exists = $select.find(`option[value="${themeName}"]`).length > 0;
            if (!exists) {
                const option = document.createElement('option');
                option.value = themeName;
                option.innerText = themeName;
                $select.append(option);
            }
        }
    } catch { /* 刷新失败不影响安装结果 */ }

    console.log(`[PresetGuard] 主题安装完成: "${themeName}", vault custom_css 长度=${(vault[serverContentId]?.custom_css || '').length}`);
    return themeName;
}

async function pushTheme(themeName, changelogMessage) {
    const settings = getSettings();

    if (!themeName) throw new Error('请指定主题名称');

    // 获取主题数据：从酒馆设置中获取主题列表并匹配
    let themeData = null;
    try {
        const resp = await fetch('/api/settings/get', {
            method: 'POST',
            headers: getRequestHeaders(),
            body: JSON.stringify({}),
        });
        if (resp.ok) {
            const data = await resp.json();
            const themes = data.themes || [];
            themeData = themes.find(t => t.name === themeName);
            console.log(`[PresetGuard] 从酒馆获取主题 "${themeName}":`,
                themeData ? `找到 (custom_css 长度: ${(themeData.custom_css || '').length})` : '未找到');
        }
    } catch (e) {
        console.error('[PresetGuard] 获取主题列表失败:', e);
    }

    if (!themeData) {
        throw new Error(`无法获取主题 "${themeName}" 的数据`);
    }

    const contentId = findContentIdByLocalName('theme', themeName);
    const encryptedFields = settings._pendingEncryptedFields
        || (contentId && settings.installedContent.theme[contentId]?.encryptedFields)
        || { fields: ['custom_css'] };

    // 从 vault 恢复真实内容
    const uploadData = structuredClone(themeData);
    delete uploadData._presetGuard;

    if (contentId && vault[contentId] && encryptedFields.fields) {
        for (const fieldName of encryptedFields.fields) {
            if (vault[contentId][fieldName]) {
                uploadData[fieldName] = vault[contentId][fieldName];
                console.log(`[PresetGuard] 从 Vault 恢复字段 ${fieldName} (长度: ${vault[contentId][fieldName].length})`);
            }
        }
    }

    // 如果内容仍包含占位符，说明 vault 中没有真实内容
    if (encryptedFields.fields) {
        for (const fieldName of encryptedFields.fields) {
            if (typeof uploadData[fieldName] === 'string' && uploadData[fieldName].includes('🔒PG:')) {
                throw new Error(`字段 "${fieldName}" 仍为占位符，请确保 Vault 已加载`);
            }
        }
    }

    // 验证加密字段有内容
    if (encryptedFields.fields) {
        for (const fieldName of encryptedFields.fields) {
            const val = uploadData[fieldName];
            if (!val || (typeof val === 'string' && !val.trim())) {
                console.warn(`[PresetGuard] 警告: 字段 "${fieldName}" 为空，加密无实际意义`);
                toastr.warning(`字段 "${fieldName}" 为空，没有需要保护的内容`);
            }
        }
    }

    console.log(`[PresetGuard] 推送主题 "${themeName}": custom_css 长度=${(uploadData.custom_css || '').length}, 字段数=${Object.keys(uploadData).length}`);

    let result;
    if (contentId) {
        result = await apiUpdateContent(contentId, {
            name: themeName,
            content: uploadData,
            encryptedFields,
            changelogMessage: changelogMessage || undefined,
        });
    } else {
        result = await apiCreateContent(
            'theme', themeName,
            settings._pendingDescription || '',
            uploadData, encryptedFields,
        );
    }

    console.log('[PresetGuard] 推送结果:', result);

    // 安装回本地（用受保护版本覆盖）
    const newContentId = result.id || contentId;
    if (!newContentId) {
        throw new Error('服务器未返回内容 ID');
    }

    const protectedTheme = createProtectedTheme(
        uploadData, encryptedFields, newContentId,
    );
    protectedTheme._presetGuard.version = result.version || '1.0.0';
    protectedTheme.name = themeName;

    await fetch('/api/themes/save', {
        method: 'POST',
        headers: getRequestHeaders(),
        body: JSON.stringify(protectedTheme),
    });

    buildVaultEntry('theme', newContentId, uploadData, encryptedFields);

    settings.installedContent.theme[newContentId] = {
        localName: themeName,
        version: result.version || '1.0.0',
        encryptedFields,
    };
    settings._pendingEncryptedFields = null;
    settings._pendingContentType = null;
    saveSettings();

    console.log(`[PresetGuard] 主题推送完成, contentId=${newContentId}, vault 字段数=${Object.keys(vault[newContentId] || {}).length}`);
    return result;
}

// ================================================================
//  辅助：已安装内容查询
// ================================================================

function findContentIdByLocalName(type, localName) {
    const contents = getSettings().installedContent[type] || {};
    for (const [id, info] of Object.entries(contents)) {
        if (info.localName === localName) return id;
    }
    return null;
}

function findInstalledByLocalName(type, localName) {
    const contents = getSettings().installedContent[type] || {};
    for (const info of Object.values(contents)) {
        if (info.localName === localName) return info;
    }
    return null;
}

function getAllInstalledCount() {
    const ic = getSettings().installedContent;
    let count = 0;
    for (const type of Object.keys(CONTENT_TYPES)) {
        count += Object.keys(ic[type] || {}).length;
    }
    return count;
}

// ================================================================
//  Fetch 拦截器
// ================================================================
function installFetchInterceptor() {
    const originalFetch = window.fetch;

    window.fetch = async function (input, init) {
        const url = typeof input === 'string' ? input : input?.url || '';

        // ---- 1. AI 请求拦截：替换占位符 ----
        const shouldIntercept = INTERCEPT_URLS.some(u => url.includes(u));

        if (shouldIntercept && init?.body) {
            try {
                const bodyStr = typeof init.body === 'string'
                    ? init.body
                    : new TextDecoder().decode(init.body);

                if (bodyStr.includes('🔒PG:')) {
                    const body = JSON.parse(bodyStr);
                    let replaced = false;

                    if (Array.isArray(body.messages)) {
                        for (const msg of body.messages) {
                            if (typeof msg.content === 'string' && msg.content.includes('🔒PG:')) {
                                msg.content = msg.content.replace(
                                    PG_PLACEHOLDER_RE,
                                    (match, contentId, fieldId) => {
                                        const real = vault[contentId]?.[fieldId];
                                        if (real) { replaced = true; return real; }
                                        return match;
                                    },
                                );
                            }
                            if (Array.isArray(msg.content)) {
                                for (const part of msg.content) {
                                    if (part.type === 'text' && typeof part.text === 'string' && part.text.includes('🔒PG:')) {
                                        part.text = part.text.replace(
                                            PG_PLACEHOLDER_RE,
                                            (match, contentId, fieldId) => {
                                                const real = vault[contentId]?.[fieldId];
                                                if (real) { replaced = true; return real; }
                                                return match;
                                            },
                                        );
                                    }
                                }
                            }
                        }
                    }

                    if (typeof body.prompt === 'string' && body.prompt.includes('🔒PG:')) {
                        body.prompt = body.prompt.replace(
                            PG_PLACEHOLDER_RE,
                            (match, contentId, fieldId) => {
                                const real = vault[contentId]?.[fieldId];
                                if (real) { replaced = true; return real; }
                                return match;
                            },
                        );
                    }

                    if (replaced) {
                        console.log('[PresetGuard] 已替换请求中的加密占位符');
                        init = { ...init, body: JSON.stringify(body) };
                    }
                }
            } catch (e) {
                console.error('[PresetGuard] AI 拦截器错误:', e);
            }
        }

        // ---- 2. 预设保存拦截 ----
        if (url.includes('/api/presets/save') && init?.body) {
            try {
                const saveStr = typeof init.body === 'string'
                    ? init.body : new TextDecoder().decode(init.body);
                const saveBody = JSON.parse(saveStr);
                const preset = saveBody.preset || saveBody;
                const pgMeta = preset?.extensions?.presetGuard;

                if (pgMeta?.isProtected && pgMeta?.contentId) {
                    const ef = pgMeta.encryptedFields || {};
                    let enforced = false;
                    const cid = pgMeta.contentId;

                    if (ef.prompts && preset.prompts) {
                        for (const id of ef.prompts) {
                            const p = preset.prompts.find(x => x.identifier === id);
                            if (p && p.content && !p.content.startsWith('🔒PG:')) {
                                if (!vault[cid]) vault[cid] = {};
                                if (p.content.trim()) vault[cid][id] = p.content;
                                p.content = `🔒PG:${cid}:${id}`;
                                enforced = true;
                            }
                        }
                    }
                    if (ef.rootFields) {
                        for (const fn of ef.rootFields) {
                            if (preset[fn] && typeof preset[fn] === 'string'
                                && !preset[fn].startsWith('🔒PG:')) {
                                if (!vault[cid]) vault[cid] = {};
                                if (preset[fn].trim()) vault[cid][fn] = preset[fn];
                                preset[fn] = `🔒PG:${cid}:${fn}`;
                                enforced = true;
                            }
                        }
                    }

                    if (enforced) {
                        console.log('[PresetGuard] 预设保存拦截：已强制替换泄露内容');
                        init = { ...init, body: JSON.stringify(saveBody) };
                    }
                }
            } catch (e) {
                console.error('[PresetGuard] 预设保存拦截器错误:', e);
            }
        }

        // ---- 4. 世界书保存拦截 ----
        if (url.includes('/api/worldinfo/edit') && init?.body) {
            try {
                const saveStr = typeof init.body === 'string'
                    ? init.body : new TextDecoder().decode(init.body);
                const wiBody = JSON.parse(saveStr);
                const data = wiBody.data;
                const pgMeta = data?._presetGuard;

                if (pgMeta?.isProtected && pgMeta?.contentId) {
                    const ef = pgMeta.encryptedFields || {};
                    let enforced = false;
                    const cid = pgMeta.contentId;
                    // 支持两种类型：独立世界书 (entry_) 和角色绑定世界书 (cb_entry_)
                    const keyPrefix = pgMeta.vaultKeyPrefix || 'entry_';
                    const entryUids = ef.entries;

                    if (entryUids && data.entries) {
                        for (const uid of entryUids) {
                            const entry = data.entries[String(uid)];
                            if (entry && entry.content && !entry.content.startsWith('🔒PG:')) {
                                if (!vault[cid]) vault[cid] = {};
                                if (entry.content.trim()) vault[cid][`${keyPrefix}${uid}`] = entry.content;
                                entry.content = `🔒PG:${cid}:${keyPrefix}${uid}`;
                                enforced = true;
                            }
                        }
                    }

                    if (enforced) {
                        console.log('[PresetGuard] 世界书保存拦截：已强制替换泄露内容');
                        init = { ...init, body: JSON.stringify(wiBody) };
                    }
                }
            } catch (e) {
                console.error('[PresetGuard] 世界书保存拦截器错误:', e);
            }
        }

        // ---- 5. 角色卡保存拦截 ----
        if ((url.includes('/api/characters/edit') || url.includes('/api/characters/create'))
            && init?.body instanceof FormData) {
            try {
                const extStr = init.body.get('extensions');
                if (extStr) {
                    const ext = JSON.parse(extStr);
                    const pgMeta = ext?.presetGuard;

                    if (pgMeta?.isProtected && pgMeta?.contentId) {
                        const ef = pgMeta.encryptedFields || {};
                        const cid = pgMeta.contentId;
                        let enforced = false;

                        // 文本字段
                        if (ef.fields) {
                            for (const fn of ef.fields) {
                                const val = init.body.get(fn);
                                if (val && typeof val === 'string' && !val.startsWith('🔒PG:')) {
                                    if (!vault[cid]) vault[cid] = {};
                                    if (val.trim()) vault[cid][fn] = val;
                                    init.body.set(fn, `🔒PG:${cid}:${fn}`);
                                    enforced = true;
                                }
                            }
                        }

                        // 正则脚本（在 extensions JSON 内部）
                        if (ef.regexScripts?.length && Array.isArray(ext.regex_scripts)) {
                            let regexEnforced = false;
                            for (const idx of ef.regexScripts) {
                                const script = ext.regex_scripts[idx];
                                if (script && typeof script.findRegex === 'string'
                                    && !script.findRegex.startsWith('🔒PG:')) {
                                    if (!vault[cid]) vault[cid] = {};
                                    vault[cid][`regex_${idx}`] = structuredClone(script);
                                    script.findRegex = `🔒PG:${cid}:regex_${idx}`;
                                    script.replaceString = `🔒PG:${cid}:regex_${idx}_replace`;
                                    script.placement = [];
                                    regexEnforced = true;
                                }
                            }
                            if (regexEnforced) {
                                init.body.set('extensions', JSON.stringify(ext));
                                enforced = true;
                            }
                        }

                        // 角色世界书条目（在 json_data 内部的 character_book）
                        if (ef.characterBookEntries?.length) {
                            // 关键：移除 world 表单字段，防止服务端 charaFormatData 从磁盘读取
                            // 世界书文件并覆盖已加密的 character_book 条目
                            if (init.body.has('world')) {
                                console.log('[PresetGuard] 移除 world 表单字段以保护加密的 character_book');
                                init.body.delete('world');
                            }
                            const jsonDataStr = init.body.get('json_data');
                            if (jsonDataStr && typeof jsonDataStr === 'string') {
                                try {
                                    const jsonData = JSON.parse(jsonDataStr);
                                    const cbContainer = jsonData.data || jsonData;
                                    const entries = cbContainer.character_book?.entries;
                                    if (entries) {
                                        let cbEnforced = false;
                                        for (const uid of ef.characterBookEntries) {
                                            const entry = Array.isArray(entries)
                                                ? entries.find(e => e.uid === uid || e.id === uid)
                                                : entries[String(uid)];
                                            if (entry && entry.content && typeof entry.content === 'string'
                                                && !entry.content.startsWith('🔒PG:')) {
                                                if (!vault[cid]) vault[cid] = {};
                                                if (entry.content.trim()) vault[cid][`cb_entry_${uid}`] = entry.content;
                                                entry.content = `🔒PG:${cid}:cb_entry_${uid}`;
                                                cbEnforced = true;
                                            }
                                        }
                                        if (cbEnforced) {
                                            init.body.set('json_data', JSON.stringify(jsonData));
                                            enforced = true;
                                        }
                                    }
                                } catch (e) {
                                    console.warn('[PresetGuard] json_data character_book 拦截失败:', e);
                                }
                            }
                        }

                        if (enforced) {
                            console.log('[PresetGuard] 角色卡保存拦截：已强制替换泄露内容');
                        }
                    }
                }
            } catch (e) {
                console.error('[PresetGuard] 角色卡保存拦截器错误:', e);
            }
        }

        // ---- 6. 主题保存拦截 ----
        if (url.includes('/api/themes/save') && init?.body) {
            try {
                const saveStr = typeof init.body === 'string'
                    ? init.body : new TextDecoder().decode(init.body);
                const themeBody = JSON.parse(saveStr);
                const pgMeta = themeBody?._presetGuard;

                if (pgMeta?.isProtected && pgMeta?.contentId) {
                    const ef = pgMeta.encryptedFields || {};
                    let enforced = false;
                    const cid = pgMeta.contentId;

                    if (ef.fields) {
                        for (const fn of ef.fields) {
                            if (themeBody[fn] && typeof themeBody[fn] === 'string'
                                && !themeBody[fn].startsWith('🔒PG:')) {
                                if (!vault[cid]) vault[cid] = {};
                                if (themeBody[fn].trim()) vault[cid][fn] = themeBody[fn];
                                themeBody[fn] = `🔒PG:${cid}:${fn}`;
                                enforced = true;
                            }
                        }
                    }

                    if (enforced) {
                        console.log('[PresetGuard] 主题保存拦截：已强制替换泄露内容');
                        init = { ...init, body: JSON.stringify(themeBody) };
                    }
                }
            } catch (e) {
                console.error('[PresetGuard] 主题保存拦截器错误:', e);
            }
        }

        return originalFetch.call(this, input, init);
    };

    console.log('[PresetGuard] Fetch 拦截器已安装');
}

// ================================================================
//  导出拦截
// ================================================================

function installExportGuard() {
    // 文档级捕获阶段拦截
    document.addEventListener('click', function (e) {
        // 预设导出
        const presetExportBtn = e.target.closest('#export_oai_preset, .export_preset');
        if (presetExportBtn) {
            const pgData = getCurrentPresetPGData();
            if (pgData?.isProtected && !isAdmin()) {
                e.stopImmediatePropagation();
                e.preventDefault();
                toastr.warning('此预设受 PresetGuard 保护，不允许导出');
                apiReportEvent('export_attempt', { type: 'preset', name: getCurrentPresetName() });
                return;
            }
        }

        // 角色卡导出
        const charExportBtn = e.target.closest('#export_button');
        if (charExportBtn) {
            const context = getContext();
            const charIndex = context.characterId;
            if (charIndex !== undefined && charIndex >= 0) {
                const charData = context.characters[charIndex];
                const pgMeta = charData?.data?.extensions?.presetGuard;
                if (pgMeta?.isProtected && !isAdmin()) {
                    e.stopImmediatePropagation();
                    e.preventDefault();
                    toastr.warning('此角色卡受 PresetGuard 保护，不允许导出');
                    apiReportEvent('export_attempt', { type: 'character', name: charData?.name });
                    return;
                }
            }
        }

        // 世界书导出
        const worldExportBtn = e.target.closest('#world_popup_export');
        if (worldExportBtn) {
            // 检查当前世界书是否受保护
            if (isWorldBookProtected() && !isAdmin()) {
                e.stopImmediatePropagation();
                e.preventDefault();
                toastr.warning('此世界书受 PresetGuard 保护，不允许导出');
                apiReportEvent('export_attempt', { type: 'worldbook' });
                return;
            }
        }

        // 主题导出
        const themeExportBtn = e.target.closest('#ui_preset_export_button');
        if (themeExportBtn) {
            if (isCurrentThemeProtected() && !isAdmin()) {
                e.stopImmediatePropagation();
                e.preventDefault();
                toastr.warning('此主题受 PresetGuard 保护，不允许导出');
                apiReportEvent('export_attempt', { type: 'theme', name: String($('#themes').val() || '') });
                return;
            }
        }
    }, true);

    // OAI_PRESET_EXPORT_READY 事件安全网
    try {
        if (event_types.OAI_PRESET_EXPORT_READY) {
            eventSource.on(event_types.OAI_PRESET_EXPORT_READY, (preset) => {
                handleExportReady(preset);
            });
        }
    } catch { /* 事件类型不存在则忽略 */ }
}

function isWorldBookProtected() {
    // 检查已安装的世界书中是否有当前正在查看的
    const settings = getSettings();
    for (const info of Object.values(settings.installedContent.worldbook)) {
        // 简化检查：如果有任何已安装世界书就认为可能受保护
        // 更精确的检查需要知道当前正在查看哪个世界书
        if (info.localName) return true;
    }
    return false;
}

function isCurrentThemeProtected() {
    const themeName = String($('#themes').find(':selected').val() || '');
    if (!themeName) return false;
    return !!findContentIdByLocalName('theme', themeName);
}

function handleExportReady(preset) {
    const pgData = preset?.extensions?.presetGuard;
    if (!pgData?.isProtected) return;

    const contentId = pgData.contentId || pgData.presetId;
    const encryptedFields = pgData.encryptedFields || {};

    if (isAdmin() && vault[contentId]) {
        if (encryptedFields.prompts && preset.prompts) {
            for (const identifier of encryptedFields.prompts) {
                const prompt = preset.prompts.find(p => p.identifier === identifier);
                if (prompt && vault[contentId][identifier]) {
                    prompt.content = vault[contentId][identifier];
                }
            }
        }
        if (encryptedFields.rootFields) {
            for (const fieldName of encryptedFields.rootFields) {
                if (vault[contentId][fieldName]) {
                    preset[fieldName] = vault[contentId][fieldName];
                }
            }
        }
        if (preset.extensions?.presetGuard) {
            delete preset.extensions.presetGuard;
        }
    } else {
        if (encryptedFields.prompts && preset.prompts) {
            for (const identifier of encryptedFields.prompts) {
                const prompt = preset.prompts.find(p => p.identifier === identifier);
                if (prompt) prompt.content = '';
            }
        }
        if (encryptedFields.rootFields) {
            for (const fieldName of encryptedFields.rootFields) {
                if (preset[fieldName] !== undefined) preset[fieldName] = '';
            }
        }
        if (preset.extensions?.presetGuard) {
            delete preset.extensions.presetGuard;
        }
    }
}

// ================================================================
//  UI: 扩展设置面板
// ================================================================
function renderSettingsPanel() {
    const html = `
    <div id="pg-settings-container" class="pg-container">
        <div class="inline-drawer">
            <div class="inline-drawer-toggle inline-drawer-header">
                <b>PresetGuard</b>
                <div class="inline-drawer-icon fa-solid fa-circle-chevron-down down"></div>
            </div>
            <div class="inline-drawer-content">
                <div style="text-align:center;margin-bottom:6px;font-size:0.85em;opacity:0.7">
                    作者 金瓜瓜 @gua.guagua.uk
                </div>
                <!-- 服务器配置 -->
                <div class="pg-section">
                    <label>服务器地址</label>
                    <div class="pg-row">
                        <input id="pg-server-url" type="text" class="text_pole wide100p"
                               placeholder="http://localhost:7123" />
                        <div id="pg-btn-test" class="menu_button menu_button_icon interactable"
                             title="测试连接">
                            <i class="fa-solid fa-plug"></i>
                        </div>
                    </div>
                    <small id="pg-server-status" class="pg-status"></small>
                </div>

                <!-- 登录 -->
                <div id="pg-login-form" class="pg-section">
                    <label>用户登录</label>
                    <input id="pg-username" type="text" class="text_pole wide100p"
                           placeholder="用户名" />
                    <input id="pg-password" type="password" class="text_pole wide100p"
                           placeholder="密码" />
                    <div class="pg-row pg-gap" style="margin-top:6px">
                        <div id="pg-btn-login" class="menu_button menu_button_icon interactable">
                            <i class="fa-solid fa-right-to-bracket"></i>
                            <span>登录</span>
                        </div>
                        <div id="pg-btn-register" class="menu_button menu_button_icon interactable">
                            <i class="fa-solid fa-user-plus"></i>
                            <span>注册</span>
                        </div>
                    </div>
                    <div id="pg-invite-row" style="margin-top:6px">
                        <input id="pg-invite-code" type="text" class="text_pole wide100p"
                               placeholder="邀请码（必填）" />
                    </div>
                </div>

                <!-- 用户信息 -->
                <div id="pg-user-info" class="pg-section" style="display:none">
                    <div class="pg-row pg-between">
                        <span>
                            <i class="fa-solid fa-user"></i>
                            <span id="pg-display-name"></span>
                            <span id="pg-display-role" class="pg-badge"></span>
                        </span>
                        <div id="pg-btn-logout" class="menu_button menu_button_icon interactable">
                            <i class="fa-solid fa-right-from-bracket"></i>
                            <span>登出</span>
                        </div>
                    </div>
                </div>

                <!-- 服务器内容列表 -->
                <div id="pg-content-section" class="pg-section" style="display:none">
                    <label>服务器内容</label>
                    <div class="pg-row pg-gap" style="margin-bottom:6px">
                        <select id="pg-content-type-filter" class="text_pole" style="width:auto">
                            <option value="">全部</option>
                            <option value="preset">预设</option>
                            <option value="character">角色卡</option>
                            <option value="worldbook">世界书</option>
                        </select>
                        <div id="pg-btn-refresh" class="menu_button menu_button_icon interactable"
                             title="刷新列表">
                            <i class="fa-solid fa-arrows-rotate"></i>
                        </div>
                    </div>
                    <div id="pg-content-list" class="pg-list"></div>
                </div>

                <!-- 已安装内容 -->
                <div id="pg-installed-section" class="pg-section" style="display:none">
                    <label>已安装内容</label>
                    <div id="pg-installed-list" class="pg-list"></div>
                </div>

                <!-- 关注作者（user 角色专属） -->
                <div id="pg-follow-section" class="pg-section" style="display:none">
                    <label>关注的作者</label>
                    <div id="pg-followed-authors" class="pg-list"></div>
                    <div class="pg-row pg-gap" style="margin-top:6px">
                        <input id="pg-follow-code" type="text" class="text_pole wide100p"
                               placeholder="输入作者邀请码" />
                        <div id="pg-btn-follow" class="menu_button menu_button_icon interactable"
                             title="关注作者">
                            <i class="fa-solid fa-user-plus"></i>
                            <span>关注</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>`;

    $('#extensions_settings2').append(html);
    bindSettingsEvents();
}

function bindSettingsEvents() {
    $('#pg-server-url')
        .val(getSettings().serverUrl)
        .on('input', function () {
            getSettings().serverUrl = $(this).val().replace(/\/+$/, '');
            saveSettings();
        });

    $('#pg-btn-test').on('click', async () => {
        try {
            $('#pg-server-status').text('连接中...').removeClass('pg-error pg-success');
            const data = await pgFetch('/api/health');
            if (data.status === 'ok') {
                $('#pg-server-status').text('✓ 服务器连接正常').addClass('pg-success');
            }
        } catch (e) {
            $('#pg-server-status')
                .text('✗ 连接失败: ' + e.message)
                .addClass('pg-error');
        }
    });

    $('#pg-btn-login').on('click', async () => {
        const username = $('#pg-username').val().trim();
        const password = $('#pg-password').val().trim();
        if (!username || !password) {
            toastr.warning('请输入用户名和密码');
            return;
        }
        try {
            await apiLogin(username, password);
            toastr.success('登录成功');
            await populateVault();
            updateSettingsUI();
            applyOcclusion();
        } catch (e) {
            toastr.error('登录失败: ' + e.message);
        }
    });

    $('#pg-btn-register').on('click', async () => {
        const username = $('#pg-username').val().trim();
        const password = $('#pg-password').val().trim();
        const inviteCode = $('#pg-invite-code').val().trim();
        if (!username || !password || !inviteCode) {
            toastr.warning('请输入用户名、密码和邀请码');
            return;
        }
        try {
            const data = await apiRegister(username, password, inviteCode);
            toastr.success(data.message || '注册成功');
            updateSettingsUI();
        } catch (e) {
            toastr.error('注册失败: ' + e.message);
        }
    });

    $('#pg-btn-logout').on('click', () => {
        getSettings().token = null;
        getSettings().user = null;
        clearVault();
        saveSettings();
        toastr.info('已登出');
        updateSettingsUI();
        removeOcclusion();
    });

    $('#pg-btn-refresh').on('click', () => refreshContentList());
    $('#pg-content-type-filter').on('change', () => refreshContentList());

    $('#pg-btn-follow').on('click', async () => {
        const code = $('#pg-follow-code').val().trim();
        if (!code) {
            toastr.warning('请输入作者邀请码');
            return;
        }
        try {
            const data = await apiFollowAuthor(code);
            toastr.success(`已关注作者: ${data.authorUsername}`);
            $('#pg-follow-code').val('');
            refreshFollowedAuthors();
            refreshContentList();
            await populateVault();
        } catch (e) {
            toastr.error('关注失败: ' + e.message);
        }
    });
}

async function refreshFollowedAuthors() {
    const $list = $('#pg-followed-authors').empty();
    try {
        const me = await apiGetMe();
        if (!me.authorAccess || me.authorAccess.length === 0) {
            $list.html('<div class="pg-empty">暂未关注任何作者</div>');
            return;
        }
        for (const author of me.authorAccess) {
            const $row = $(`
                <div class="pg-followed-author-item pg-row pg-between">
                    <span><i class="fa-solid fa-user-pen"></i> ${escapeHtml(author.authorUsername)}</span>
                    <div class="pg-btn-unfollow menu_button menu_button_icon interactable"
                         data-author-id="${author.authorId}" title="取消关注">
                        <i class="fa-solid fa-user-minus"></i>
                    </div>
                </div>
            `);
            $row.find('.pg-btn-unfollow').on('click', async function () {
                const authorId = $(this).data('author-id');
                try {
                    await apiUnfollowAuthor(authorId);
                    toastr.info('已取消关注');
                    refreshFollowedAuthors();
                    refreshContentList();
                } catch (e) {
                    toastr.error('取消关注失败: ' + e.message);
                }
            });
            $list.append($row);
        }
    } catch (e) {
        $list.html(`<div class="pg-error">获取失败: ${escapeHtml(e.message)}</div>`);
    }
}

function updateSettingsUI() {
    const loggedIn = isLoggedIn();
    const settings = getSettings();

    $('#pg-login-form').toggle(!loggedIn);
    $('#pg-user-info').toggle(loggedIn);
    $('#pg-content-section').toggle(loggedIn);
    $('#pg-installed-section').toggle(loggedIn && getAllInstalledCount() > 0);

    if (loggedIn) {
        $('#pg-display-name').text(settings.user?.username || '未知');
        const roleLabels = { superadmin: '超级管理员', admin: '管理员', user: '用户' };
        const role = settings.user?.role || 'user';
        $('#pg-display-role')
            .text(roleLabels[role] || '用户')
            .toggleClass('pg-badge-admin', role === 'admin')
            .toggleClass('pg-badge-superadmin', role === 'superadmin');
        $('#pg-follow-section').toggle(role === 'user' || role === 'admin');
        if (role === 'user' || role === 'admin') {
            refreshFollowedAuthors();
        }
        refreshContentList();
        refreshInstalledList();
    }

    updatePresetButtonsVisibility();
}

async function refreshContentList() {
    if (!isLoggedIn()) return;

    const typeFilter = $('#pg-content-type-filter').val();

    try {
        let items;
        if (typeFilter) {
            items = await apiGetContent(typeFilter);
        } else {
            items = await apiGetAllContent();
        }

        const $list = $('#pg-content-list').empty();

        if (items.length === 0) {
            $list.html('<div class="pg-empty">暂无可用内容</div>');
            return;
        }

        const settings = getSettings();
        const currentUsername = settings.user?.username;

        // 按作者分组
        const authorGroups = new Map();
        for (const item of items) {
            const authorKey = item.createdBy || '未知作者';
            if (!authorGroups.has(authorKey)) {
                authorGroups.set(authorKey, []);
            }
            authorGroups.get(authorKey).push(item);
        }

        for (const [authorName, groupItems] of authorGroups) {
            const isSelf = authorName === currentUsername;
            const label = isSelf ? `${escapeHtml(authorName)} (我)` : escapeHtml(authorName);
            $list.append(`
                <div class="pg-author-group-header">
                    <i class="fa-solid fa-user-pen"></i> ${label}
                    <span class="pg-author-count">${groupItems.length} 项</span>
                </div>
            `);

            for (const item of groupItems) {
            const type = item.type || 'preset';
            const typeDef = CONTENT_TYPES[type] || CONTENT_TYPES.preset;
            const installed = settings.installedContent[type]?.[item.id];
            const hasUpdate = installed && installed.version !== item.version;

            const $item = $(`
                <div class="pg-preset-item pg-grouped-item" data-id="${item.id}" data-type="${type}">
                    <div class="pg-preset-info">
                        <span class="pg-type-badge pg-type-${type}">
                            <i class="fa-solid ${typeDef.icon}"></i> ${typeDef.label}
                        </span>
                        <span class="pg-preset-name">${escapeHtml(item.name)}</span>
                        <span class="pg-preset-version">v${escapeHtml(item.version)}</span>
                        ${item.description ? `<br><small class="pg-preset-desc">${escapeHtml(item.description)}</small>` : ''}
                    </div>
                    <div class="pg-preset-actions">
                        ${installed
                            ? (hasUpdate
                                ? '<div class="menu_button menu_button_icon pg-install-btn interactable" title="更新"><i class="fa-solid fa-download"></i></div>'
                                : '<span class="pg-installed-badge">✓ 已安装</span>')
                            : '<div class="menu_button menu_button_icon pg-install-btn interactable" title="安装"><i class="fa-solid fa-download"></i></div>'
                        }
                    </div>
                </div>
            `);

            $item.find('.pg-install-btn').on('click', async function () {
                try {
                    toastr.info(`正在${installed ? '更新' : '安装'} ${typeDef.label}...`);
                    let localName;
                    switch (type) {
                        case 'preset':
                            localName = await installPreset(item.id);
                            break;
                        case 'character':
                            localName = await installCharacter(item.id);
                            break;
                        case 'worldbook':
                            localName = await installWorldBook(item.id);
                            break;
                    }
                    toastr.success(`"${localName}" ${installed ? '已更新' : '已安装'}`);
                    updateSettingsUI();
                    applyOcclusion();
                } catch (e) {
                    toastr.error(`安装失败: ${e.message}`);
                }
            });

            $list.append($item);
            }
        }
    } catch (e) {
        console.error('[PresetGuard] 获取内容列表失败:', e);
        $('#pg-content-list').html(
            `<div class="pg-error">获取失败: ${escapeHtml(e.message)}</div>`,
        );
    }
}

function refreshInstalledList() {
    const settings = getSettings();
    const $list = $('#pg-installed-list').empty();

    for (const [type, contents] of Object.entries(settings.installedContent)) {
        const typeDef = CONTENT_TYPES[type];
        if (!typeDef) continue;

        for (const [contentId, info] of Object.entries(contents)) {
            const inVault = !!vault[contentId];
            $list.append(`
                <div class="pg-installed-item">
                    <span class="pg-type-badge pg-type-${type}">
                        <i class="fa-solid ${typeDef.icon}"></i>
                    </span>
                    <span>${escapeHtml(info.localName)}</span>
                    <span class="pg-version">v${escapeHtml(info.version)}</span>
                    <span class="pg-vault-status ${inVault ? 'pg-active' : 'pg-inactive'}">
                        ${inVault ? '🔓 已解锁' : '🔒 未解锁'}
                    </span>
                </div>
            `);
        }
    }

    $('#pg-installed-section').toggle(getAllInstalledCount() > 0);
}

// ================================================================
//  UI: 预设面板按钮（嵌入酒馆预设下拉框区域）
// ================================================================
function injectPresetButtons() {
    const $btnGroup = $(`
        <div id="pg-preset-btns" class="pg-preset-btn-group" style="display:none">
            <div id="pg-btn-pull" class="pg-icon-btn interactable"
                 title="从服务器安装/更新">
                <span>📥</span>
            </div>
            <div id="pg-btn-encrypt" class="pg-icon-btn pg-admin-only interactable"
                 title="加密管理" style="display:none">
                <span>🔒</span>
            </div>
            <div id="pg-btn-push" class="pg-icon-btn pg-admin-only interactable"
                 title="推送到服务器" style="display:none">
                <span>⬆️</span>
            </div>
        </div>
    `);

    const $presetRow = $('#settings_preset_openai').closest('.flex-container');
    $presetRow.after($btnGroup);

    // 拉取
    $('#pg-btn-pull').on('click', async () => {
        if (!isLoggedIn()) {
            toastr.warning('请先在扩展设置中登录 PresetGuard');
            return;
        }
        showContentInstallDialog();
    });

    // 加密管理
    $('#pg-btn-encrypt').on('click', () => {
        if (!isAdmin()) return;
        showEncryptionDialog('preset');
    });

    // 推送
    $('#pg-btn-push').on('click', () => {
        if (!isAdmin()) return;
        showPushDialog('preset');
    });
}

/**
 * 在角色卡面板注入 PG 按钮
 * 📥 拉取按钮 → 角色列表工具栏 (#rm_buttons_container)
 * 🔒⬆️ 加密/推送按钮 → 角色编辑器 (#export_button 旁)
 */
function injectCharacterButtons() {
    // 📥 拉取按钮 - 注入到角色列表工具栏
    const $pullBtn = $(`
        <div id="pg-char-pull" class="menu_button pg-loggedin-btn interactable"
             title="从 PresetGuard 服务器安装/更新内容" style="display:none">
            <i class="fa-solid fa-download"></i>
            <span data-i18n="PG">PG</span>
        </div>
    `);

    const $rmBtnContainer = $('#rm_buttons_container');
    if ($rmBtnContainer.length) {
        $rmBtnContainer.append($pullBtn);
    }

    // 🔒⬆️ 加密/推送按钮 - 注入到角色编辑器导出按钮旁
    const $encryptBtn = $(`
        <div id="pg-char-encrypt" class="menu_button fa-solid fa-lock pg-admin-only interactable"
             title="角色卡加密管理" style="display:none">
        </div>
    `);
    const $pushBtn = $(`
        <div id="pg-char-push" class="menu_button fa-solid fa-cloud-arrow-up pg-admin-only interactable"
             title="推送角色卡到服务器" style="display:none">
        </div>
    `);

    const $exportBtn = $('#export_button');
    if ($exportBtn.length) {
        $exportBtn.after($pushBtn);
        $exportBtn.after($encryptBtn);
    }

    $('#pg-char-pull').on('click', async () => {
        if (!isLoggedIn()) {
            toastr.warning('请先在扩展设置中登录 PresetGuard');
            return;
        }
        showContentInstallDialog();
    });

    $('#pg-char-encrypt').on('click', () => {
        if (!isAdmin()) return;
        showEncryptionDialog('character');
    });

    $('#pg-char-push').on('click', () => {
        if (!isAdmin()) return;
        showPushDialog('character');
    });
}

/**
 * 在世界书面板注入 PG 按钮（📥拉取 + 🔒加密 + ⬆️推送）
 */
function injectWorldBookButtons() {
    const $pullBtn = $(`
        <div id="pg-wb-pull" class="menu_button fa-solid fa-download pg-loggedin-btn interactable"
             title="从服务器安装/更新世界书" style="display:none">
        </div>
    `);
    const $encryptBtn = $(`
        <div id="pg-wb-encrypt" class="menu_button fa-solid fa-lock pg-admin-only interactable"
             title="世界书加密管理" style="display:none">
        </div>
    `);
    const $pushBtn = $(`
        <div id="pg-wb-push" class="menu_button fa-solid fa-cloud-arrow-up pg-admin-only interactable"
             title="推送世界书到服务器" style="display:none">
        </div>
    `);

    const $exportBtn = $('#world_popup_export');
    if ($exportBtn.length) {
        $exportBtn.after($pushBtn);
        $exportBtn.after($encryptBtn);
        $exportBtn.after($pullBtn);
    }

    $('#pg-wb-pull').on('click', async () => {
        if (!isLoggedIn()) {
            toastr.warning('请先在扩展设置中登录 PresetGuard');
            return;
        }
        showContentInstallDialog();
    });

    $('#pg-wb-encrypt').on('click', () => {
        if (!isAdmin()) return;
        showEncryptionDialog('worldbook');
    });

    $('#pg-wb-push').on('click', () => {
        if (!isAdmin()) return;
        showPushDialog('worldbook');
    });
}

/**
 * 在主题面板注入 PG 按钮（📥拉取 + 🔒加密 + ⬆️推送）
 */
function injectThemeButtons() {
    const $pullBtn = $(`
        <div id="pg-theme-pull" class="menu_button fa-solid fa-download pg-loggedin-btn interactable"
             title="从服务器安装/更新主题" style="display:none">
        </div>
    `);
    const $encryptBtn = $(`
        <div id="pg-theme-encrypt" class="menu_button fa-solid fa-lock pg-admin-only interactable"
             title="主题加密管理" style="display:none">
        </div>
    `);
    const $pushBtn = $(`
        <div id="pg-theme-push" class="menu_button fa-solid fa-cloud-arrow-up pg-admin-only interactable"
             title="推送主题到服务器" style="display:none">
        </div>
    `);

    const $exportBtn = $('#ui_preset_export_button');
    if ($exportBtn.length) {
        $exportBtn.after($pushBtn);
        $exportBtn.after($encryptBtn);
        $exportBtn.after($pullBtn);
    }

    $('#pg-theme-pull').on('click', async () => {
        if (!isLoggedIn()) {
            toastr.warning('请先在扩展设置中登录 PresetGuard');
            return;
        }
        showContentInstallDialog();
    });

    $('#pg-theme-encrypt').on('click', () => {
        if (!isAdmin()) return;
        showEncryptionDialog('theme');
    });

    $('#pg-theme-push').on('click', () => {
        if (!isAdmin()) return;
        showPushDialog('theme');
    });
}

function updatePresetButtonsVisibility() {
    const loggedIn = isLoggedIn();
    const admin = isAdmin();
    // 按钮组容器
    $('#pg-preset-btns').toggle(loggedIn);
    // 角色卡/世界书的独立按钮
    $('.pg-loggedin-btn').toggle(loggedIn);
    // 管理员专属按钮
    $('.pg-admin-only').toggle(admin);
}

// ================================================================
//  UI: 内容安装对话框
// ================================================================
async function showContentInstallDialog() {
    try {
        const items = await apiGetAllContent();
        const settings = getSettings();

        let html = '<div class="pg-dialog-list">';
        if (items.length === 0) {
            html += '<div class="pg-empty">暂无可用内容</div>';
        } else {
            for (const item of items) {
                const type = item.type || 'preset';
                const typeDef = CONTENT_TYPES[type] || CONTENT_TYPES.preset;
                const installed = settings.installedContent[type]?.[item.id];
                const hasUpdate = installed && installed.version !== item.version;
                html += `
                    <div class="pg-dialog-item" data-id="${item.id}" data-type="${type}">
                        <div>
                            <span class="pg-type-badge pg-type-${type}">
                                <i class="fa-solid ${typeDef.icon}"></i> ${typeDef.label}
                            </span>
                            <b>${escapeHtml(item.name)}</b>
                            <small>v${escapeHtml(item.version)}</small>
                            ${item.description ? `<br><small>${escapeHtml(item.description)}</small>` : ''}
                            ${installed
                                ? `<br><small class="pg-hint">${hasUpdate
                                    ? '⚡ 有更新 (当前 v' + escapeHtml(installed.version) + ')'
                                    : '✓ 已安装'}</small>`
                                : ''}
                        </div>
                        <div class="menu_button menu_button_icon pg-dialog-install interactable"
                             data-id="${item.id}" data-type="${type}" data-name="${escapeHtml(item.name)}">
                            <i class="fa-solid fa-download"></i>
                            <span>${installed ? (hasUpdate ? '更新' : '重装') : '安装'}</span>
                        </div>
                    </div>`;
            }
        }
        html += '</div>';

        showPGModal('选择要安装的内容', html, (modal) => {
            modal.find('.pg-dialog-install').on('click', async function () {
                const id = $(this).data('id');
                const type = $(this).data('type');
                const name = $(this).data('name');
                const typeDef = CONTENT_TYPES[type];
                closePGModal();
                try {
                    toastr.info(`正在安装 "${name}"...`);
                    let localName;
                    switch (type) {
                        case 'preset':   localName = await installPreset(id); break;
                        case 'theme':    localName = await installTheme(id); break;
                        case 'character': localName = await installCharacter(id); break;
                        case 'worldbook': localName = await installWorldBook(id); break;
                    }
                    toastr.success(`"${localName}" 安装成功！`);
                    updateSettingsUI();
                    applyOcclusion();
                    // 各类型安装后刷新前端列表
                    if (type === 'character') {
                        await getCharacters();
                    }
                    // 主题安装后需刷新页面，否则酒馆内存中的 themes 数组无新主题
                    if (type === 'theme') {
                        toastr.info('正在刷新页面以加载主题…');
                        setTimeout(() => location.reload(), 1200);
                    }
                } catch (e) {
                    toastr.error(`安装失败: ${e.message}`);
                }
            });
        });
    } catch (e) {
        toastr.error('获取内容列表失败: ' + e.message);
    }
}

// ================================================================
//  UI: 加密管理对话框
// ================================================================
function showEncryptionDialog(contentType) {
    switch (contentType) {
        case 'preset': return showPresetEncryptionDialog();
        case 'theme': return showThemeEncryptionDialog();
        case 'character': return showCharacterEncryptionDialog();
        case 'worldbook': return showWorldBookEncryptionDialog();
    }
}

function showPresetEncryptionDialog() {
    let currentPreset;
    try {
        currentPreset = getChatCompletionPreset();
    } catch {
        toastr.error('无法读取当前预设');
        return;
    }
    if (!currentPreset) {
        toastr.error('无法读取当前预设');
        return;
    }

    const pgData = currentPreset.extensions?.presetGuard;
    const currentEncrypted = getSettings()._pendingEncryptedFields ||
        pgData?.encryptedFields ||
        { prompts: [], rootFields: [] };

    let html = '<div class="pg-encrypt-config">';

    html += '<h4>提示词条目 (Prompts)</h4>';
    html += '<div class="pg-select-all-row">'
        + '<button type="button" class="pg-select-all-btn" data-target="pg-encrypt-prompt">全选</button>'
        + '<button type="button" class="pg-deselect-all-btn" data-target="pg-encrypt-prompt">全不选</button>'
        + '</div>';
    const prompts = currentPreset.prompts || [];
    let promptCount = 0;
    for (const prompt of prompts) {
        if (prompt.marker) continue;
        if (prompt.content === undefined) continue;
        const isChecked = currentEncrypted.prompts?.includes(prompt.identifier);
        const displayName = prompt.name || prompt.identifier;
        html += `
            <label class="pg-checkbox-row">
                <input type="checkbox" class="pg-encrypt-prompt"
                    data-identifier="${escapeHtml(prompt.identifier)}"
                    ${isChecked ? 'checked' : ''} />
                <span>${escapeHtml(displayName)}</span>
            </label>`;
        promptCount++;
    }
    if (promptCount === 0) {
        html += '<div class="pg-hint">没有可加密的提示词条目</div>';
    }

    html += '<h4>根级文本字段</h4>';
    html += '<div class="pg-select-all-row">'
        + '<button type="button" class="pg-select-all-btn" data-target="pg-encrypt-root">全选</button>'
        + '<button type="button" class="pg-deselect-all-btn" data-target="pg-encrypt-root">全不选</button>'
        + '</div>';
    let rootCount = 0;
    for (const field of ROOT_TEXT_FIELDS) {
        if (currentPreset[field] === undefined) continue;
        const isChecked = currentEncrypted.rootFields?.includes(field);
        html += `
            <label class="pg-checkbox-row">
                <input type="checkbox" class="pg-encrypt-root"
                    data-field="${field}"
                    ${isChecked ? 'checked' : ''} />
                <span>${field}</span>
            </label>`;
        rootCount++;
    }
    if (rootCount === 0) {
        html += '<div class="pg-hint">没有可加密的根级字段</div>';
    }

    html += '</div>';

    showPGModal('加密配置 - 预设: ' + escapeHtml(getCurrentPresetName()), html, null, () => {
        const encryptedFields = { prompts: [], rootFields: [] };
        $('.pg-encrypt-prompt:checked').each(function () {
            encryptedFields.prompts.push($(this).data('identifier'));
        });
        $('.pg-encrypt-root:checked').each(function () {
            encryptedFields.rootFields.push($(this).data('field'));
        });
        getSettings()._pendingEncryptedFields = encryptedFields;
        getSettings()._pendingContentType = 'preset';
        saveSettings();
        toastr.success('加密配置已保存（推送时生效）');
    });
}

async function showCharacterEncryptionDialog() {
    const context = getContext();
    const charIndex = context.characterId;

    if (charIndex === undefined || charIndex < 0) {
        toastr.error('请先选择一个角色');
        return;
    }

    const charBasic = context.characters[charIndex];
    const charName = charBasic?.name || '未知角色';
    const pgMeta = charBasic?.data?.extensions?.presetGuard;

    // 获取完整角色数据（含 character_book 和 regex_scripts）
    let fullCharData = charBasic?.data || charBasic;
    try {
        if (charBasic?.avatar) {
            const resp = await fetch('/api/characters/get', {
                method: 'POST',
                headers: getRequestHeaders(),
                body: JSON.stringify({ avatar_url: charBasic.avatar }),
            });
            if (resp.ok) {
                const full = await resp.json();
                fullCharData = full.data || full;
            }
        }
    } catch (e) {
        console.warn('[PresetGuard] 获取完整角色数据失败，使用基础数据:', e);
    }

    // 如果角色没有嵌入 character_book 但有外部世界书链接，尝试加载
    if (!fullCharData.character_book && fullCharData.extensions?.world) {
        try {
            const wiResp = await fetch('/api/worldinfo/get', {
                method: 'POST',
                headers: getRequestHeaders(),
                body: JSON.stringify({ name: fullCharData.extensions.world }),
            });
            if (wiResp.ok) {
                const wiData = await wiResp.json();
                if (wiData?.entries) {
                    const cbEntries = [];
                    for (const [key, entry] of Object.entries(wiData.entries)) {
                        cbEntries.push({
                            id: entry.uid ?? Number(key),
                            keys: entry.key || [],
                            secondary_keys: entry.keysecondary || [],
                            comment: entry.comment || '',
                            content: entry.content || '',
                            constant: entry.constant || false,
                            selective: entry.selective || false,
                            insertion_order: entry.order || 100,
                            enabled: !entry.disable,
                        });
                    }
                    fullCharData.character_book = { entries: cbEntries, name: fullCharData.extensions.world };
                    console.log(`[PresetGuard] 加密对话框：从世界书 "${fullCharData.extensions.world}" 加载 ${cbEntries.length} 条条目`);
                }
            }
        } catch (e) {
            console.warn('[PresetGuard] 加载外部世界书失败:', e);
        }
    }

    const currentEncrypted = getSettings()._pendingEncryptedFields ||
        pgMeta?.encryptedFields ||
        { fields: [], characterBookEntries: [], regexScripts: [] };

    let html = '<div class="pg-encrypt-config">';

    // ---- 文本字段 ----
    html += '<h4>角色卡文本字段</h4>';
    html += '<div class="pg-select-all-row">'
        + '<button type="button" class="pg-select-all-btn" data-target="pg-encrypt-field">全选</button>'
        + '<button type="button" class="pg-deselect-all-btn" data-target="pg-encrypt-field">全不选</button>'
        + '</div>';
    for (const field of CHARACTER_TEXT_FIELDS) {
        const isChecked = currentEncrypted.fields?.includes(field.key);
        html += `
            <label class="pg-checkbox-row">
                <input type="checkbox" class="pg-encrypt-field"
                    data-field="${field.key}"
                    ${isChecked ? 'checked' : ''} />
                <span>${escapeHtml(field.label)}</span>
            </label>`;
    }

    // ---- 角色世界书 ----
    const cb = fullCharData.character_book;
    const cbEntries = cb?.entries;
    if (cbEntries) {
        const entryList = Array.isArray(cbEntries) ? cbEntries : Object.values(cbEntries);
        html += `<h4>角色世界书 (共 ${entryList.length} 条)</h4>`;
        if (entryList.length > 0) {
            html += '<div class="pg-select-all-row">'
                + '<button type="button" class="pg-select-all-btn" data-target="pg-encrypt-cb-entry">全选</button>'
                + '<button type="button" class="pg-deselect-all-btn" data-target="pg-encrypt-cb-entry">全不选</button>'
                + '</div>';
            for (const entry of entryList) {
                const uid = entry.uid ?? entry.id ?? 0;
                const title = entry.comment || entry.key?.[0] || `条目 ${uid}`;
                const isChecked = currentEncrypted.characterBookEntries?.includes(uid);
                html += `
                    <label class="pg-checkbox-row">
                        <input type="checkbox" class="pg-encrypt-cb-entry"
                            data-uid="${uid}"
                            ${isChecked ? 'checked' : ''} />
                        <span>[${uid}] ${escapeHtml(title)}</span>
                    </label>`;
            }
        } else {
            html += '<div class="pg-hint">没有世界书条目</div>';
        }
    } else {
        html += '<h4>角色世界书</h4>';
        html += '<div class="pg-hint">该角色没有绑定世界书</div>';
    }

    // ---- 正则脚本 ----
    const regexScripts = fullCharData.extensions?.regex_scripts;
    if (Array.isArray(regexScripts) && regexScripts.length > 0) {
        html += `<h4>角色正则脚本 (共 ${regexScripts.length} 条)</h4>`;
        html += '<div class="pg-select-all-row">'
            + '<button type="button" class="pg-select-all-btn" data-target="pg-encrypt-regex">全选</button>'
            + '<button type="button" class="pg-deselect-all-btn" data-target="pg-encrypt-regex">全不选</button>'
            + '</div>';
        for (let i = 0; i < regexScripts.length; i++) {
            const script = regexScripts[i];
            const scriptName = script.scriptName || script.description || `脚本 ${i}`;
            const isChecked = currentEncrypted.regexScripts?.includes(i);
            html += `
                <label class="pg-checkbox-row">
                    <input type="checkbox" class="pg-encrypt-regex"
                        data-index="${i}"
                        ${isChecked ? 'checked' : ''} />
                    <span>[${i}] ${escapeHtml(scriptName)}</span>
                </label>`;
        }
    } else {
        html += '<h4>角色正则脚本</h4>';
        html += '<div class="pg-hint">该角色没有正则脚本</div>';
    }

    html += '</div>';

    showPGModal('加密配置 - 角色: ' + escapeHtml(charName), html, null, () => {
        const encryptedFields = { fields: [], characterBookEntries: [], regexScripts: [] };
        $('.pg-encrypt-field:checked').each(function () {
            encryptedFields.fields.push($(this).data('field'));
        });
        $('.pg-encrypt-cb-entry:checked').each(function () {
            encryptedFields.characterBookEntries.push(Number($(this).data('uid')));
        });
        $('.pg-encrypt-regex:checked').each(function () {
            encryptedFields.regexScripts.push(Number($(this).data('index')));
        });
        getSettings()._pendingEncryptedFields = encryptedFields;
        getSettings()._pendingContentType = 'character';
        saveSettings();
        toastr.success('加密配置已保存（推送时生效）');
    });
}

async function showWorldBookEncryptionDialog() {
    // 获取世界书列表让用户选择
    let worldList = [];
    try {
        const resp = await fetch('/api/worldinfo/list', {
            method: 'POST',
            headers: getRequestHeaders(),
            body: JSON.stringify({}),
        });
        if (resp.ok) worldList = await resp.json();
    } catch (e) {
        toastr.error('获取世界书列表失败');
        return;
    }

    if (worldList.length === 0) {
        toastr.warning('没有可用的世界书');
        return;
    }

    // 第一步：选择世界书
    let html = '<div class="pg-encrypt-config">';
    html += '<h4>选择世界书</h4>';
    html += '<select id="pg-wb-select" class="text_pole wide100p">';
    for (const wb of worldList) {
        const name = typeof wb === 'string' ? wb : wb.name || wb;
        html += `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`;
    }
    html += '</select>';
    html += '<div id="pg-wb-entries" style="margin-top:10px"></div>';
    html += '</div>';

    showPGModal('加密配置 - 世界书', html, (modal) => {
        const loadEntries = async () => {
            const name = modal.find('#pg-wb-select').val();
            if (!name) return;

            try {
                const resp = await fetch('/api/worldinfo/get', {
                    method: 'POST',
                    headers: getRequestHeaders(),
                    body: JSON.stringify({ name }),
                });
                if (!resp.ok) throw new Error('获取失败');
                const worldData = await resp.json();

                const pgMeta = worldData._presetGuard;
                const currentEncrypted = getSettings()._pendingEncryptedFields ||
                    pgMeta?.encryptedFields ||
                    { entries: [] };

                const $entries = modal.find('#pg-wb-entries').empty();
                $entries.append('<h4>选择要加密的条目</h4>');

                const entries = worldData.entries || {};
                const sortedUids = Object.keys(entries)
                    .sort((a, b) => (entries[a].displayIndex || 0) - (entries[b].displayIndex || 0));

                if (sortedUids.length === 0) {
                    $entries.append('<div class="pg-hint">此世界书没有条目</div>');
                    return;
                }

                $entries.append(
                    '<div class="pg-select-all-row">'
                    + '<button type="button" class="pg-select-all-btn" data-target="pg-encrypt-entry">全选</button>'
                    + '<button type="button" class="pg-deselect-all-btn" data-target="pg-encrypt-entry">全不选</button>'
                    + '</div>'
                );

                for (const uid of sortedUids) {
                    const entry = entries[uid];
                    const isChecked = currentEncrypted.entries?.includes(Number(uid));
                    const entryName = entry.comment || entry.key?.join(', ') || `条目 ${uid}`;
                    const contentPreview = (entry.content || '').substring(0, 60) +
                        ((entry.content?.length > 60) ? '...' : '');

                    $entries.append(`
                        <label class="pg-checkbox-row">
                            <input type="checkbox" class="pg-encrypt-entry"
                                data-uid="${uid}"
                                ${isChecked ? 'checked' : ''} />
                            <span>
                                <b>${escapeHtml(entryName)}</b>
                                ${contentPreview ? `<br><small class="pg-hint">${escapeHtml(contentPreview)}</small>` : ''}
                            </span>
                        </label>
                    `);
                }
            } catch (e) {
                modal.find('#pg-wb-entries').html(
                    `<div class="pg-error">加载条目失败: ${escapeHtml(e.message)}</div>`,
                );
            }
        };

        modal.find('#pg-wb-select').on('change', loadEntries);
        loadEntries();
    }, () => {
        const wbName = $('#pg-wb-select').val();
        const encryptedFields = { entries: [] };
        $('.pg-encrypt-entry:checked').each(function () {
            encryptedFields.entries.push(Number($(this).data('uid')));
        });
        getSettings()._pendingEncryptedFields = encryptedFields;
        getSettings()._pendingContentType = 'worldbook';
        getSettings()._pendingWorldBookName = wbName;
        saveSettings();
        toastr.success(`世界书 "${wbName}" 加密配置已保存（推送时生效）`);
    });
}

function showThemeEncryptionDialog() {
    const themeName = String($('#themes').find(':selected').val() || '');
    if (!themeName) {
        toastr.error('请先选择一个主题');
        return;
    }

    const contentId = findContentIdByLocalName('theme', themeName);
    const currentEncrypted = getSettings()._pendingEncryptedFields
        || (contentId && getSettings().installedContent.theme[contentId]?.encryptedFields)
        || { fields: [] };

    let html = '<div class="pg-encrypt-config">';
    html += '<h4>主题可加密字段</h4>';

    const isChecked = currentEncrypted.fields?.includes('custom_css');
    html += `
        <label class="pg-checkbox-row">
            <input type="checkbox" class="pg-encrypt-field"
                data-field="custom_css"
                ${isChecked ? 'checked' : ''} />
            <span>自定义 CSS (custom_css)</span>
        </label>`;

    html += '</div>';

    showPGModal('加密配置 - 主题: ' + escapeHtml(themeName), html, null, () => {
        const encryptedFields = { fields: [] };
        $('.pg-encrypt-field:checked').each(function () {
            encryptedFields.fields.push($(this).data('field'));
        });
        getSettings()._pendingEncryptedFields = encryptedFields;
        getSettings()._pendingContentType = 'theme';
        getSettings()._pendingThemeName = themeName;
        saveSettings();
        toastr.success('加密配置已保存（推送时生效）');
    });
}

// ================================================================
//  UI: 推送对话框
// ================================================================
function showPushDialog(contentType) {
    switch (contentType) {
        case 'preset': return showPresetPushDialog();
        case 'theme': return showThemePushDialog();
        case 'character': return showCharacterPushDialog();
        case 'worldbook': return showWorldBookPushDialog();
    }
}

function showPresetPushDialog() {
    const presetName = getCurrentPresetName();
    const pgData = getCurrentPresetPGData();
    const isUpdate = !!(pgData?.contentId || pgData?.presetId);

    const html = `
        <div class="pg-push-config">
            <p>将预设 "<b>${escapeHtml(presetName)}</b>"
               ${isUpdate ? '更新' : '上传'}到服务器</p>
            ${isUpdate ? `
                <label>更新说明</label>
                <input id="pg-push-changelog" type="text" class="text_pole wide100p"
                       placeholder="本次更新内容..." />
            ` : ''}
            <p class="pg-hint">
                ${isUpdate
                    ? '将使用当前加密配置更新服务器上的预设。'
                    : '首次推送。请先通过 🔒 按钮配置要加密的字段。'}
            </p>
        </div>`;

    showPGModal(
        isUpdate ? '推送更新 - 预设' : '推送新预设',
        html, null,
        async () => {
            const changelog = $('#pg-push-changelog').val()?.trim();
            try {
                toastr.info('正在推送预设...');
                await pushPreset(changelog);
                toastr.success('推送成功！');
                updateSettingsUI();
            } catch (e) {
                toastr.error('推送失败: ' + e.message);
            }
        },
    );
}

function showCharacterPushDialog() {
    const context = getContext();
    const charIndex = context.characterId;
    if (charIndex === undefined || charIndex < 0) {
        toastr.error('请先选择一个角色');
        return;
    }
    const charData = context.characters[charIndex];
    const charName = charData?.name || '未知角色';
    const pgMeta = charData?.data?.extensions?.presetGuard;
    const isUpdate = !!pgMeta?.contentId;

    const html = `
        <div class="pg-push-config">
            <p>将角色 "<b>${escapeHtml(charName)}</b>"
               ${isUpdate ? '更新' : '上传'}到服务器</p>
            ${isUpdate ? `
                <label>更新说明</label>
                <input id="pg-push-changelog" type="text" class="text_pole wide100p"
                       placeholder="本次更新内容..." />
            ` : ''}
            <p class="pg-hint">
                ${isUpdate
                    ? '将使用当前加密配置更新服务器上的角色卡。'
                    : '首次推送。请先通过加密管理配置要加密的字段。'}
            </p>
        </div>`;

    showPGModal(
        isUpdate ? '推送更新 - 角色卡' : '推送新角色卡',
        html, null,
        async () => {
            const changelog = $('#pg-push-changelog').val()?.trim();
            try {
                toastr.info('正在推送角色卡...');
                await pushCharacter(changelog);
                toastr.success('推送成功！');
                updateSettingsUI();
            } catch (e) {
                toastr.error('推送失败: ' + e.message);
            }
        },
    );
}

function showWorldBookPushDialog() {
    const settings = getSettings();
    const wbName = settings._pendingWorldBookName || '';

    if (!wbName) {
        toastr.warning('请先在加密管理中选择世界书并配置加密条目');
        return;
    }

    const existingId = findContentIdByLocalName('worldbook', wbName);
    const isUpdate = !!existingId;

    const html = `
        <div class="pg-push-config">
            <p>将世界书 "<b>${escapeHtml(wbName)}</b>"
               ${isUpdate ? '更新' : '上传'}到服务器</p>
            ${isUpdate ? `
                <label>更新说明</label>
                <input id="pg-push-changelog" type="text" class="text_pole wide100p"
                       placeholder="本次更新内容..." />
            ` : ''}
            <p class="pg-hint">
                ${isUpdate
                    ? '将使用当前加密配置更新服务器上的世界书。'
                    : '首次推送。请先通过加密管理配置要加密的条目。'}
            </p>
        </div>`;

    showPGModal(
        isUpdate ? '推送更新 - 世界书' : '推送新世界书',
        html, null,
        async () => {
            const changelog = $('#pg-push-changelog').val()?.trim();
            try {
                toastr.info('正在推送世界书...');
                await pushWorldBook(wbName, changelog);
                toastr.success('推送成功！');
                updateSettingsUI();
            } catch (e) {
                toastr.error('推送失败: ' + e.message);
            }
        },
    );
}

function showThemePushDialog() {
    const settings = getSettings();
    const themeName = settings._pendingThemeName || String($('#themes').find(':selected').val() || '');

    if (!themeName) {
        toastr.warning('请先选择一个主题');
        return;
    }

    const existingId = findContentIdByLocalName('theme', themeName);
    const isUpdate = !!existingId;

    const html = `
        <div class="pg-push-config">
            <p>将主题 "<b>${escapeHtml(themeName)}</b>"
               ${isUpdate ? '更新' : '上传'}到服务器</p>
            ${isUpdate ? `
                <label>更新说明</label>
                <input id="pg-push-changelog" type="text" class="text_pole wide100p"
                       placeholder="本次更新内容..." />
            ` : ''}
            <p class="pg-hint">
                ${isUpdate
                    ? '将使用当前加密配置更新服务器上的主题。'
                    : '首次推送。请先通过加密管理配置要加密的字段。'}
            </p>
        </div>`;

    showPGModal(
        isUpdate ? '推送更新 - 主题' : '推送新主题',
        html, null,
        async () => {
            const changelog = $('#pg-push-changelog').val()?.trim();
            try {
                toastr.info('正在推送主题...');
                await pushTheme(themeName, changelog);
                toastr.success('推送成功！');
                updateSettingsUI();
            } catch (e) {
                toastr.error('推送失败: ' + e.message);
            }
        },
    );
}

// ================================================================
//  UI: 管理员快捷操作面板
// ================================================================
function showAdminActionsDialog() {
    const html = `
        <div class="pg-admin-actions">
            <h4>选择操作类型</h4>
            <div class="pg-action-grid">
                <div class="pg-action-card" data-action="encrypt" data-type="preset">
                    <i class="fa-solid fa-sliders"></i>
                    <span>预设加密配置</span>
                </div>
                <div class="pg-action-card" data-action="push" data-type="preset">
                    <i class="fa-solid fa-sliders"></i>
                    <span>推送预设</span>
                </div>
                <div class="pg-action-card" data-action="encrypt" data-type="theme">
                    <i class="fa-solid fa-palette"></i>
                    <span>主题加密配置</span>
                </div>
                <div class="pg-action-card" data-action="push" data-type="theme">
                    <i class="fa-solid fa-palette"></i>
                    <span>推送主题</span>
                </div>
                <div class="pg-action-card" data-action="encrypt" data-type="character">
                    <i class="fa-solid fa-user"></i>
                    <span>角色加密配置</span>
                </div>
                <div class="pg-action-card" data-action="push" data-type="character">
                    <i class="fa-solid fa-user"></i>
                    <span>推送角色卡</span>
                </div>
                <div class="pg-action-card" data-action="encrypt" data-type="worldbook">
                    <i class="fa-solid fa-book"></i>
                    <span>世界书加密配置</span>
                </div>
                <div class="pg-action-card" data-action="push" data-type="worldbook">
                    <i class="fa-solid fa-book"></i>
                    <span>推送世界书</span>
                </div>
            </div>
        </div>
    `;

    showPGModal('管理员操作', html, (modal) => {
        modal.find('.pg-action-card').on('click', function () {
            const action = $(this).data('action');
            const type = $(this).data('type');
            closePGModal();
            setTimeout(() => {
                if (action === 'encrypt') showEncryptionDialog(type);
                else if (action === 'push') showPushDialog(type);
            }, 200);
        });
    });
}

// ================================================================
//  UI: 聊天消息反馈按钮注入
// ================================================================

/**
 * 获取所有已安装的 PG 内容列表（用于反馈内容选择）
 */
function getInstalledContentList() {
    const ic = getSettings().installedContent;
    const list = [];
    for (const [type, contents] of Object.entries(ic)) {
        const typeDef = CONTENT_TYPES[type];
        if (!typeDef) continue;
        for (const [contentId, info] of Object.entries(contents)) {
            list.push({
                id: contentId,
                type,
                typeLabel: typeDef.label,
                name: info.localName || info.name || contentId,
            });
        }
    }
    return list;
}

/**
 * 向聊天消息注入 PG 反馈按钮
 */
function injectChatFeedbackButtons() {
    if (!isLoggedIn()) return;
    const installed = getInstalledContentList();
    if (installed.length === 0) return;

    $('#chat .mes[is_user="false"]').each(function () {
        const $mes = $(this);
        if ($mes.find('.pg_mes_feedback').length) return;
        const $extraButtons = $mes.find('.extraMesButtons');
        if ($extraButtons.length) {
            $extraButtons.append(
                '<div title="PG 反馈" class="mes_button pg_mes_feedback fa-solid fa-comment-dots"></div>',
            );
        }
    });
}

/**
 * 聊天消息反馈弹窗（compose-then-send 模式）
 */
function showChatFeedbackModal(messageText) {
    const installed = getInstalledContentList();
    if (installed.length === 0) {
        toastr.warning('没有已安装的 PG 保护内容');
        return;
    }

    // 截取消息预览（前200字）
    const preview = messageText.length > 200
        ? messageText.substring(0, 200) + '...'
        : messageText;

    const emojis = ['👍', '❤️', '🔥', '⭐', '😕'];

    const contentOptions = installed.map((c, i) =>
        `<option value="${c.id}" ${i === 0 ? 'selected' : ''}>[${c.typeLabel}] ${escapeHtml(c.name)}</option>`,
    ).join('');

    const emojiHtml = emojis.map(emoji =>
        `<div class="pg-emoji-btn" data-emoji="${emoji}">${emoji}</div>`,
    ).join('');

    const html = `
        <div class="pg-feedback-content">
            <div class="pg-feedback-section">
                <label class="pg-label">反馈对象</label>
                <select id="pg-feedback-target" class="pg-select">${contentOptions}</select>
            </div>
            <div class="pg-feedback-section">
                <label class="pg-label">相关消息</label>
                <div class="pg-message-preview">${escapeHtml(preview)}</div>
            </div>
            <div class="pg-feedback-section">
                <label class="pg-label">反应</label>
                <div class="pg-emoji-row">${emojiHtml}</div>
            </div>
            <div class="pg-feedback-section">
                <label class="pg-label">评论 <span class="pg-hint-text">（选填，最多500字）</span></label>
                <textarea id="pg-feedback-comment" placeholder="写下你的反馈..." maxlength="500"></textarea>
            </div>
        </div>
    `;

    let selectedEmoji = null;

    showPGModal('反馈', html, ($modal) => {
        // emoji 本地选择（不发请求）
        $modal.on('click', '.pg-emoji-btn', function () {
            const emoji = $(this).data('emoji');
            if (selectedEmoji === emoji) {
                // 取消选择
                selectedEmoji = null;
                $modal.find('.pg-emoji-btn').removeClass('selected');
            } else {
                selectedEmoji = emoji;
                $modal.find('.pg-emoji-btn').removeClass('selected');
                $(this).addClass('selected');
            }
        });
    }, async () => {
        // onSave — 一次性提交
        const contentId = $('#pg-feedback-target').val();
        const comment = $('#pg-feedback-comment').val().trim();

        if (!selectedEmoji && !comment) {
            toastr.warning('请至少选择一个反应或填写评论');
            throw new Error('abort'); // 阻止关闭
        }

        try {
            await apiFeedbackSubmit(contentId, {
                emoji: selectedEmoji || undefined,
                comment: comment || undefined,
                messageContent: messageText || undefined,
            });
            toastr.success('反馈已发送');
        } catch (e) {
            if (e.message === 'abort') throw e;
            toastr.error('发送失败: ' + e.message);
            throw e; // 阻止关闭
        }
    });
}

// ================================================================
//  UI: 通用模态框
// ================================================================
function showPGModal(title, contentHtml, onRender, onSave) {
    closePGModal();

    const $modal = $(`
        <div id="pg-modal-overlay" class="pg-modal-overlay">
            <div class="pg-modal">
                <div class="pg-modal-header">
                    <h3>${title}</h3>
                    <div class="pg-modal-close interactable">✕</div>
                </div>
                <div class="pg-modal-body">
                    ${contentHtml}
                </div>
                <div class="pg-modal-footer">
                    <div class="menu_button pg-modal-cancel interactable">取消</div>
                    ${onSave
                        ? '<div class="menu_button menu_button_icon pg-modal-save interactable"><i class="fa-solid fa-check"></i> 确定</div>'
                        : ''}
                </div>
            </div>
        </div>
    `);

    $('body').append($modal);

    $modal.find('.pg-modal-close, .pg-modal-cancel').on('click', closePGModal);
    $modal.on('click', function (e) {
        if (e.target === this) closePGModal();
    });

    if (onSave) {
        $modal.find('.pg-modal-save').on('click', async () => {
            try {
                await onSave();
                closePGModal();
            } catch {
                // onSave 抛出异常时不关闭弹窗
            }
        });
    }

    if (onRender) {
        onRender($modal);
    }

    // 全选/全不选按钮通用绑定
    $modal.on('click', '.pg-select-all-btn', function () {
        const target = $(this).data('target');
        $modal.find('.' + target).prop('checked', true);
    });
    $modal.on('click', '.pg-deselect-all-btn', function () {
        const target = $(this).data('target');
        $modal.find('.' + target).prop('checked', false);
    });
}

function closePGModal() {
    $('#pg-modal-overlay').remove();
}

// ================================================================
//  UI: 遮蔽层（隐藏加密内容）
// ================================================================

/**
 * 检查元素是否是正则编辑器中被保护的字段（已从 vault 恢复了真实值）。
 * restoreCharacterRegex 会把真实值写入内存让正则引擎运行，但 UI 编辑器不应展示。
 */
function isRestoredRegexValue(el, val) {
    if (!el.matches?.('.find_regex, .regex_replace_string')) return false;
    if (!val) return false;

    const context = getContext();
    const charIdx = context.characterId;
    if (charIdx === undefined || charIdx < 0) return false;

    const charData = context.characters[charIdx];
    const pgMeta = charData?.data?.extensions?.presetGuard;
    if (!pgMeta?.isProtected || !pgMeta?.contentId) return false;

    const ef = pgMeta.encryptedFields || {};
    if (!ef.regexScripts?.length) return false;

    const scripts = charData.data?.extensions?.regex_scripts;
    if (!Array.isArray(scripts)) return false;

    // 检查该输入框的值是否匹配某个受保护脚本的已恢复值
    for (const idx of ef.regexScripts) {
        const script = scripts[idx];
        if (!script) continue;
        if (el.matches('.find_regex') && script.findRegex === val) return true;
        if (el.matches('.regex_replace_string') && script.replaceString === val) return true;
    }
    return false;
}

function applyOcclusion() {
    removeOcclusion();

    // 对于预设：检查当前预设
    const pgData = getCurrentPresetPGData();
    const presetProtected = pgData?.isProtected;

    // 跳过管理员
    if (isAdmin()) return;

    // 检查是否有任何受保护内容
    const hasProtected = presetProtected || getAllInstalledCount() > 0;
    if (!hasProtected) return;

    const occludeElement = (el) => {
        if (el.dataset.pgOccluded) return;
        const val = el.value ?? el.textContent ?? '';
        const hasPlaceholder = val.includes('🔒PG:');

        if (!hasPlaceholder && !isRestoredRegexValue(el, val)) return;

        el.dataset.pgOccluded = 'true';
        el.readOnly = true;
        el.style.color = 'transparent';
        el.style.userSelect = 'none';
        el.style.webkitUserSelect = 'none';

        // 为元素创建专属包裹层，确保遮蔽层只覆盖该元素而非父容器
        let wrap = el.parentElement;
        if (!wrap?.classList.contains('pg-occlusion-wrap')) {
            wrap = document.createElement('div');
            wrap.className = 'pg-occlusion-wrap';
            el.parentNode.insertBefore(wrap, el);
            wrap.appendChild(el);
        }

        if (!wrap.querySelector('.pg-occlusion-overlay')) {
            const overlay = document.createElement('div');
            overlay.className = 'pg-occlusion-overlay';
            overlay.textContent = '🔒 内容已加密保护';
            wrap.appendChild(overlay);
        }
    };

    // 解除不再含占位符的元素的遮蔽
    const unoccludeStale = () => {
        document.querySelectorAll('[data-pg-occluded]').forEach(el => {
            const val = el.value ?? el.textContent ?? '';
            if (!val.includes('🔒PG:') && !isRestoredRegexValue(el, val)) {
                el.readOnly = false;
                el.style.color = '';
                el.style.userSelect = '';
                el.style.webkitUserSelect = '';
                delete el.dataset.pgOccluded;
                const wrap = el.parentElement;
                if (wrap?.classList.contains('pg-occlusion-wrap')) {
                    const overlay = wrap.querySelector('.pg-occlusion-overlay');
                    if (overlay) overlay.remove();
                    const parent = wrap.parentNode;
                    while (wrap.firstChild) {
                        parent.insertBefore(wrap.firstChild, wrap);
                    }
                    wrap.remove();
                }
            }
        });
    };

    let scanning = false;
    const scanAll = () => {
        if (scanning) return;
        scanning = true;
        unoccludeStale();
        document.querySelectorAll('textarea, input[type="text"], [contenteditable="true"]')
            .forEach(occludeElement);
        scanning = false;
    };

    scanAll();

    const observer = new MutationObserver(() => scanAll());
    observer.observe(document.body, { childList: true, subtree: true });
    window._pgOcclusionObserver = observer;

    window._pgOcclusionInterval = setInterval(scanAll, 300);

    document.addEventListener('focusin', window._pgFocusHandler = (e) => {
        const el = e.target;
        if (el.matches?.('textarea, input[type="text"], [contenteditable="true"]')) {
            occludeElement(el);
        }
    }, true);
}

function removeOcclusion() {
    if (window._pgOcclusionInterval) {
        clearInterval(window._pgOcclusionInterval);
        window._pgOcclusionInterval = null;
    }
    if (window._pgOcclusionObserver) {
        window._pgOcclusionObserver.disconnect();
        window._pgOcclusionObserver = null;
    }
    if (window._pgFocusHandler) {
        document.removeEventListener('focusin', window._pgFocusHandler, true);
        window._pgFocusHandler = null;
    }

    document.querySelectorAll('.pg-occlusion-overlay').forEach(el => el.remove());
    document.querySelectorAll('[data-pg-occluded]').forEach(el => {
        el.readOnly = false;
        el.style.color = '';
        el.style.userSelect = '';
        el.style.webkitUserSelect = '';
        delete el.dataset.pgOccluded;
    });
    // 解除专属包裹层，还原 DOM 结构
    document.querySelectorAll('.pg-occlusion-wrap').forEach(wrap => {
        const parent = wrap.parentNode;
        while (wrap.firstChild) {
            parent.insertBefore(wrap.firstChild, wrap);
        }
        wrap.remove();
    });
}

// ================================================================
//  CSS 注入：将受保护主题的真实 CSS 注入到 <style id="custom-style">
// ================================================================
function startCSSInjection() {
    let lastLog = 0;
    setInterval(() => {
        const styleEl = document.getElementById('custom-style');
        if (!styleEl) return;

        const content = styleEl.textContent || styleEl.innerHTML;
        if (!content.includes('🔒PG:')) return;

        // 提取占位符中的 contentId
        const match = content.match(/🔒PG:([a-f0-9-]+):([a-zA-Z0-9_.-]+)/);
        if (!match) return;

        const contentId = match[1];
        const fieldId = match[2];
        const realCSS = vault[contentId]?.[fieldId];

        if (realCSS) {
            styleEl.textContent = realCSS;
            console.log(`[PresetGuard] CSS 注入成功 (${realCSS.length} 字符)`);
        } else {
            // 每 5 秒打印一次等待日志，避免刷屏
            const now = Date.now();
            if (now - lastLog > 5000) {
                console.log(`[PresetGuard] CSS 注入等待中: vault[${contentId}] ${vault[contentId] ? '存在但缺少 ' + fieldId : '不存在'}`);
                lastLog = now;
            }
        }
    }, 500);
}

// ================================================================
//  正则脚本运行时恢复：将占位符正则从 vault 还原到内存
// ================================================================
function restoreCharacterRegex() {
    const context = getContext();
    const charIndex = context.characterId;
    if (charIndex === undefined || charIndex < 0) return;

    const charData = context.characters[charIndex];
    const pgMeta = charData?.data?.extensions?.presetGuard;
    if (!pgMeta?.isProtected || !pgMeta?.contentId) return;

    const ef = pgMeta.encryptedFields || {};
    const cid = pgMeta.contentId;
    if (!ef.regexScripts?.length || !vault[cid]) return;

    const scripts = charData.data?.extensions?.regex_scripts;
    if (!Array.isArray(scripts)) return;

    let restored = 0;
    for (const idx of ef.regexScripts) {
        const realScript = vault[cid][`regex_${idx}`];
        if (realScript && scripts[idx]) {
            Object.assign(scripts[idx], realScript);
            restored++;
        }
    }
    if (restored > 0) {
        console.log(`[PresetGuard] 已恢复 ${restored} 个正则脚本到内存`);
    }
}

function startRegexRestoration() {
    eventSource.on(event_types.CHAT_CHANGED, () => {
        restoreCharacterRegex();
    });
}

// ================================================================
//  初始化
// ================================================================
jQuery(async () => {
    console.log('[PresetGuard] 扩展 v3.2 加载中...');

    // 渲染 UI
    renderSettingsPanel();
    injectPresetButtons();
    injectCharacterButtons();
    injectWorldBookButtons();
    injectThemeButtons();

    // 安装 Fetch 拦截器
    installFetchInterceptor();

    // 安装导出保护
    installExportGuard();

    // 启动 CSS 注入轮询
    startCSSInjection();

    // 启动正则脚本运行时恢复
    startRegexRestoration();

    // 若已登录，从服务器加载 Vault
    if (isLoggedIn()) {
        try {
            await populateVault();
        } catch (e) {
            console.error('[PresetGuard] Vault 初始化失败:', e);
        }
    }

    // 更新 UI
    updateSettingsUI();
    applyOcclusion();

    // 监听预设切换
    $('#settings_preset_openai').on('change', () => {
        setTimeout(() => {
            applyOcclusion();
            updatePresetButtonsVisibility();
        }, 500);
    });

    // 监听事件
    try {
        if (event_types.OAI_PRESET_CHANGED_AFTER) {
            eventSource.on(event_types.OAI_PRESET_CHANGED_AFTER, () => {
                applyOcclusion();
                updatePresetButtonsVisibility();
            });
        }
    } catch { /* 事件类型不存在，忽略 */ }

    // 聊天消息反馈按钮：事件委托 + 注入 + 监听新消息
    $(document).on('click', '.pg_mes_feedback', function () {
        const $mes = $(this).closest('.mes');
        const messageText = $mes.find('.mes_text').text().trim();
        showChatFeedbackModal(messageText);
    });

    injectChatFeedbackButtons();

    // 监听新消息渲染，注入反馈按钮
    try {
        if (event_types.MESSAGE_RECEIVED) {
            eventSource.on(event_types.MESSAGE_RECEIVED, () => {
                setTimeout(injectChatFeedbackButtons, 300);
            });
        }
        if (event_types.CHAT_CHANGED) {
            eventSource.on(event_types.CHAT_CHANGED, () => {
                setTimeout(injectChatFeedbackButtons, 500);
            });
        }
    } catch { /* 事件类型不存在，忽略 */ }

    console.log('[PresetGuard] 扩展 v3.2 已就绪');
});
