import crypto from "crypto";

export const activeLogins = new Map();

const inactiveLoginTtlMs = 5 * 60 * 60 * 1000;

export function normalizeUsername(username) {
  return String(username ?? "").trim().toLowerCase();
}

export function clearInactiveLogins(now = Date.now()) {
  for (const [username, logins] of activeLogins.entries()) {
    for (const [loginId, login] of logins.entries()) {
      if (now - Date.parse(login.lastActivity) >= inactiveLoginTtlMs) {
        logins.delete(loginId);
      }
    }
    if (logins.size === 0) activeLogins.delete(username);
  }
}

const inactiveLoginCleanup = setInterval(clearInactiveLogins, 60 * 60 * 1000);
inactiveLoginCleanup.unref();

export function detectBrowser(userAgent = "") {
  const ua = String(userAgent || "").toLowerCase();

  if (ua.includes("edg")) return "Edge";
  if (ua.includes("opr") || ua.includes("opera")) return "Opera";
  if (ua.includes("firefox")) return "Firefox";
  if (ua.includes("chrome") && !ua.includes("version/")) return "Chrome";
  if (ua.includes("safari")) return "Safari";
  return "Unknown";
}

export function detectDevice(userAgent = "") {
  const ua = String(userAgent || "").toLowerCase();

  if (/(ipad|tablet|playbook|silk)/.test(ua)) return "Tablet";
  if (/(android|iphone|ipod|mobile)/.test(ua)) return "Mobile";
  return "Desktop";
}

export function resolveClientIp(req = {}) {
  const forwarded = req.headers?.["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim();
  }
  if (Array.isArray(forwarded) && forwarded[0]) {
    return String(forwarded[0]).trim();
  }

  const realIp = req.headers?.["x-real-ip"];
  if (typeof realIp === "string" && realIp.trim()) {
    return realIp.trim();
  }

  return req.ip || req.socket?.remoteAddress || "unknown";
}

function createLoginRecord({
  username,
  loginId,
  browserId,
  role,
  device,
  browser,
  ip,
  socketId = null,
}) {
  const now = new Date();

  return {
    username: normalizeUsername(username),
    loginId,
    role,
    browserId: browserId ?? null,
    device: device ?? "Unknown",
    browser: browser ?? "Unknown",
    ip: ip ?? null,
    loginTime: now.toISOString(),
    lastActivity: now.toISOString(),
    socketId,
  };
}

export function getLogin(username, loginId = null) {
  clearInactiveLogins();
  const normalizedUsername = normalizeUsername(username);
  const logins = activeLogins.get(normalizedUsername);
  if (!logins) return null;
  if (loginId) {
    return logins.get(loginId) ?? null;
  }
  return logins.values().next().value ?? null;
}

export function getAllLogins() {
  clearInactiveLogins();
  return Array.from(activeLogins.values()).flatMap((logins) =>
    Array.from(logins.values())
  );
}

export function createLogin({
  username,
  loginId = crypto.randomUUID(),
  browserId,
  role,
  device,
  browser,
  ip,
  socketId = null,
}) {
  const key = normalizeUsername(username);
  const login = createLoginRecord({
    username: key,
    loginId,
    browserId,
    role,
    device,
    browser,
    ip,
    socketId,
  });

  let userLogins = activeLogins.get(key);
  if (!userLogins) {
    userLogins = new Map();
    activeLogins.set(key, userLogins);
  }
  userLogins.set(login.loginId, login);
  return login;
}

export function isLoginValid(username, loginId) {
  return !!getLogin(username, loginId);
}

export function updateActivity(username, loginId = null) {
  clearInactiveLogins();
  const activeLogin = getLogin(username, loginId);
  if (!activeLogin) return null;

  activeLogin.lastActivity = new Date().toISOString();
  return activeLogin;
}

export function attachSocket(username, loginId, socketId) {
  const activeLogin = getLogin(username, loginId);
  if (!activeLogin) return null;

  activeLogin.socketId = socketId;
  return activeLogin;
}

export function detachSocket(socketId) {
  for (const logins of activeLogins.values()) {
    for (const activeLogin of logins.values()) {
      if (activeLogin.socketId === socketId) {
        activeLogin.socketId = null;
        return { username: activeLogin.username, activeLogin };
      }
    }
  }

  return null;
}

export function removeLogin(username, loginId = null) {
  const normalizedUsername = normalizeUsername(username);
  const userLogins = activeLogins.get(normalizedUsername);
  if (!userLogins) return null;
  if (loginId) {
    const activeLogin = getLogin(normalizedUsername, loginId);
    if (!activeLogin) return null;
    userLogins.delete(loginId);
    if (userLogins.size === 0) activeLogins.delete(normalizedUsername);
    return activeLogin;
  }

  const firstLogin = userLogins.values().next().value ?? null;
  activeLogins.delete(normalizedUsername);
  return firstLogin;
}

export function forceLogout(username) {
  return removeLogin(username);
}

export function logoutAll() {
  const sessions = getAllLogins();
  activeLogins.clear();
  return sessions;
}

export default {
  activeLogins,
  normalizeUsername,
  getLogin,
  getAllLogins,
  createLogin,
  isLoginValid,
  updateActivity,
  attachSocket,
  detachSocket,
  removeLogin,
  forceLogout,
  logoutAll,
};
