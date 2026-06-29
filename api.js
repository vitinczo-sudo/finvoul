/**
 * FinVault — API Client
 * Conecta o frontend ao backend real
 * Inclua este script em finvault-login.html e finvault-app.html
 */

const API_BASE = window.location.hostname === 'localhost'
  ? 'http://localhost:3001/api'
  : '/api';

// ── Token storage (memory-first, sessionStorage fallback)
let _accessToken  = null;
let _refreshToken = sessionStorage.getItem('fv_rt') || null;

function setTokens(access, refresh) {
  _accessToken  = access;
  _refreshToken = refresh;
  if (refresh) sessionStorage.setItem('fv_rt', refresh);
  else sessionStorage.removeItem('fv_rt');
}

function clearTokens() {
  _accessToken = _refreshToken = null;
  sessionStorage.removeItem('fv_rt');
}

// ── Fetch wrapper com auto-refresh
async function apiFetch(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };
  if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`;

  let res = await fetch(API_BASE + path, { ...options, headers });

  // Token expirado → tentar refresh automático
  if (res.status === 401 && _refreshToken) {
    const rr = await fetch(API_BASE + '/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: _refreshToken }),
    });
    if (rr.ok) {
      const data = await rr.json();
      setTokens(data.accessToken, data.refreshToken);
      headers['Authorization'] = `Bearer ${_accessToken}`;
      res = await fetch(API_BASE + path, { ...options, headers });
    } else {
      clearTokens();
      window.location.href = '/finvault-login.html';
      return;
    }
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw Object.assign(new Error(err.error || 'Erro'), { status: res.status, body: err });
  }
  return res.status === 204 ? null : res.json();
}

// ══════════════════════════════════════════════
// AUTH API
// ══════════════════════════════════════════════
const Auth = {
  async register({ nome, email, senha }) {
    const data = await apiFetch('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ nome, email, senha, lgpd: true }),
    });
    setTokens(data.accessToken, data.refreshToken);
    return data;
  },

  async login({ email, senha, deviceFp, remember }) {
    const data = await apiFetch('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, senha, device_fp: deviceFp, remember }),
    });
    if (data.requires2FA) return data; // Continua no fluxo 2FA
    setTokens(data.accessToken, data.refreshToken);
    return data;
  },

  async verify2FA({ challToken, code }) {
    const data = await apiFetch('/auth/2fa/verify', {
      method: 'POST',
      body: JSON.stringify({ challToken, code }),
    });
    setTokens(data.accessToken, data.refreshToken);
    return data;
  },

  async googleLogin(credential) {
    const data = await apiFetch('/auth/google', {
      method: 'POST',
      body: JSON.stringify({ credential }),
    });
    setTokens(data.accessToken, data.refreshToken);
    return data;
  },

  async recover(email) {
    return apiFetch('/auth/recover', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  },

  async resetPassword({ token, senha }) {
    return apiFetch('/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, senha }),
    });
  },

  async logout() {
    try {
      await apiFetch('/auth/logout', {
        method: 'POST',
        body: JSON.stringify({ refreshToken: _refreshToken }),
      });
    } finally {
      clearTokens();
      window.location.href = '/finvault-login.html';
    }
  },

  isAuthenticated() { return !!_accessToken || !!_refreshToken; },
};

// ══════════════════════════════════════════════
// USER API
// ══════════════════════════════════════════════
const User = {
  me:         ()         => apiFetch('/user/me'),
  update:     (data)     => apiFetch('/user/me', { method: 'PUT', body: JSON.stringify(data) }),
  exportData: ()         => apiFetch('/user/data-export'),
  delete:     ()         => apiFetch('/user/me', { method: 'DELETE' }),
};

// ══════════════════════════════════════════════
// TRANSACTIONS API
// ══════════════════════════════════════════════
const Transactions = {
  list:   (params = {}) => apiFetch('/transactions?' + new URLSearchParams(params)),
  create: (body)        => apiFetch('/transactions',      { method: 'POST',   body: JSON.stringify(body) }),
  update: (id, body)    => apiFetch(`/transactions/${id}`,{ method: 'PUT',    body: JSON.stringify(body) }),
  delete: (id)          => apiFetch(`/transactions/${id}`,{ method: 'DELETE' }),
};

// ══════════════════════════════════════════════
// ACCOUNTS API
// ══════════════════════════════════════════════
const Accounts = {
  list:   ()          => apiFetch('/accounts'),
  create: (body)      => apiFetch('/accounts',      { method: 'POST',   body: JSON.stringify(body) }),
  update: (id, body)  => apiFetch(`/accounts/${id}`,{ method: 'PUT',    body: JSON.stringify(body) }),
  delete: (id)        => apiFetch(`/accounts/${id}`,{ method: 'DELETE' }),
};

// ══════════════════════════════════════════════
// OTHER APIs
// ══════════════════════════════════════════════
const Budgets = {
  list:   ()         => apiFetch('/budgets'),
  create: (body)     => apiFetch('/budgets',      { method: 'POST',   body: JSON.stringify(body) }),
  update: (id, body) => apiFetch(`/budgets/${id}`,{ method: 'PUT',    body: JSON.stringify(body) }),
  delete: (id)       => apiFetch(`/budgets/${id}`,{ method: 'DELETE' }),
};

const Goals = {
  list:   ()         => apiFetch('/goals'),
  create: (body)     => apiFetch('/goals',      { method: 'POST',   body: JSON.stringify(body) }),
  update: (id, body) => apiFetch(`/goals/${id}`,{ method: 'PUT',    body: JSON.stringify(body) }),
  delete: (id)       => apiFetch(`/goals/${id}`,{ method: 'DELETE' }),
};

const Categories = {
  list:   ()     => apiFetch('/categories'),
  create: (body) => apiFetch('/categories', { method: 'POST', body: JSON.stringify(body) }),
};

const Reports = {
  summary:   (month, year) => apiFetch(`/reports/summary?month=${month}&year=${year}`),
  cashflow:  (months = 12) => apiFetch(`/reports/cashflow?months=${months}`),
};

const Notifications = {
  list:    ()   => apiFetch('/notifications'),
  read:    (id) => apiFetch(`/notifications/${id}/read`, { method: 'PATCH' }),
  readAll: ()   => apiFetch('/notifications/read-all',   { method: 'PATCH' }),
};

// ══════════════════════════════════════════════
// DEVICE FINGERPRINT (para rastreio de sessão)
// ══════════════════════════════════════════════
async function getDeviceFingerprint() {
  const data = [
    navigator.userAgent,
    navigator.language,
    screen.width + 'x' + screen.height,
    new Date().getTimezoneOffset(),
    navigator.hardwareConcurrency,
  ].join('|');
  const buffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2,'0')).join('').slice(0,32);
}

// ══════════════════════════════════════════════
// PROTEÇÃO DE ROTA
// ══════════════════════════════════════════════
async function requireLogin() {
  if (!Auth.isAuthenticated()) {
    window.location.href = '/finvault-login.html';
    return false;
  }
  try {
    // Validar token tentando buscar o user
    const user = await User.me();
    window._currentUser = user;
    return true;
  } catch (e) {
    if (e.status === 401) {
      clearTokens();
      window.location.href = '/finvault-login.html';
    }
    return false;
  }
}

// Exportar globalmente
window.FV = { Auth, User, Transactions, Accounts, Budgets, Goals, Categories, Reports, Notifications, requireLogin, getDeviceFingerprint };
