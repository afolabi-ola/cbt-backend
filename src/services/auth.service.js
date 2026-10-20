import crypto from "crypto";
import prisma from "../config/prisma.js";
import bcrypt from "bcryptjs";
import { signToken, verifyToken } from "../utils/jwt.js";
import { getIo } from "../utils/socket.js";
import {
  attachSocket,
  createLogin,
  detectBrowser,
  detectDevice,
  getLogin,
  getAllLogins,
  normalizeUsername,
  removeLogin,
} from "../utils/loginManager.js";

export async function register({
  firstname,
  lastname,
  username,
  password,
  role,
  classId,
}) {
  username = username.toLowerCase();
  const existing = await prisma.user.findUnique({ where: { username } });
  if (existing) throw new Error("username exists");
  const hash = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: {
      firstname,
      lastname,
      username,
      password: hash,
      role,
      classId,
    },
  });

  return {
    user: {
      id: user.id,
      firstname: user.firstname,
      lastname: user.lastname,
      username: user.username,
      role: user.role,
      classId: user.classId,
      isActive: user.isActive,
    },
  };
}
export async function login({
  username,
  password,
  browserId,
  requestInfo = {},
}) {
  try {
    const normalizedUsername = normalizeUsername(username);
    const userAgent = requestInfo.userAgent || "";
    const browser = detectBrowser(userAgent);
    const device = detectDevice(userAgent);
    const ip = requestInfo.ip || "unknown";

    // console.log(`Login attempt: username=${normalizedUsername}, device=${device}, browser=${browser}, ip=${ip}`
    // );

    const user = await prisma.user.findUnique({ where: { username: normalizedUsername } });
    if (!user) {
      const error = new Error("unable to login");
      error.status = 401;
      error.details = "invalid credentials";
      throw error;
    }
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      const error = new Error("unable to login");
      error.details = "invalid credentials";
      error.status = 401;
      throw error;
    }

    if (!user.isActive) {
      const error = new Error("Your account has been disabled.");
      error.status = 403;
      error.code = "ACCOUNT_DISABLED";
      throw error;
    }

    const existingLogin = getLogin(normalizedUsername);
    if (
      user.role !== "ADMIN" &&
      existingLogin &&
      existingLogin.browserId !== browserId
    ) {
      const error = new Error("You are already logged in on another system.");
      error.status = 409;
      error.code = "ALREADY_LOGGED_IN";
      error.login = {
        device: existingLogin.device,
        browser: existingLogin.browser,
        ip: existingLogin.ip,
        loginTime: existingLogin.loginTime,
      };
      throw error;
    }
    if (existingLogin?.browserId === browserId) {
      removeLogin(normalizedUsername, existingLogin.loginId);
    }

    for (const login of getAllLogins()) {
      if (login.username !== normalizedUsername && login.browserId === browserId) {
        removeLogin(login.username, login.loginId);
      }
    }

    const loginId = crypto.randomUUID();
    const activeLogin = createLogin({
      username: user.username,
      loginId,
      browserId,
      role: user.role,
      device,
      browser,
      ip,
    });

    const token = signToken({
      id: user.id,
      role: user.role,
      username: user.username,
      loginId,
    });

    return {
      user: {
        id: user.id,
        firstname: user.firstname,
        lastname: user.lastname,
        username: user.username,
        role: user.role,
        isActive: user.isActive,
      },
      token,
    };
  } catch (error) {
    throw error;
  }
}

export function authenticateSocket(socketId) {
  const socket = getIo().sockets.sockets.get(socketId);
  if (!socket) throw new Error("Socket connection not found");

  const cookieHeader = socket.request.headers.cookie || "";
  const tokenCookie = cookieHeader
    .split(";")
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith("reqtoken="));
  const token = tokenCookie?.slice("reqtoken=".length);
  if (!token) return null;

  const payload = verifyToken(token);
  if (!payload?.username || !payload?.loginId) {
    throw new Error("Invalid login token");
  }

  const username = normalizeUsername(payload.username);
  const activeLogin = getLogin(username, payload.loginId);
  if (!activeLogin || activeLogin.loginId !== payload.loginId) {
    throw new Error("No active login session");
  }

  const attachedLogin = attachSocket(username, payload.loginId, socket.id);
  if (!attachedLogin) return null;

  const adminSocketIds = getAllLogins()
    .filter(
      (login) =>
        String(login.role ?? "").trim().toUpperCase() === "ADMIN" &&
        login.socketId,
    )
    .map((login) => login.socketId);

  for (const adminSocketId of adminSocketIds) {
    try {
      getIo()
        .to(adminSocketId)
        .emit("login_session_connected", { username: attachedLogin.username });
    } catch (error) {
      console.error(
        `Failed to notify admin socket ${adminSocketId} about a new login:`,
        error,
      );
    }
  }

  return attachedLogin;
}

export async function changeUserPassword(id, newPassword) {
  try {
    const userId = parseInt(id, 10);

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        firstname: true,
        lastname: true,
        username: true,
        role: true,
      },
    });

    if (!user) {
      const error = new Error("User not found");
      error.status = 404;
      throw error;
    }

    // Hash the new password
    const hash = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { id: userId },
      data: { password: hash },
    });

    return {
      user,
    };
  } catch (error) {
    throw error;
  }
}

export async function deleteUser(currentUser, id) {
  try {
    const userId = parseInt(id, 10);

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        firstname: true,
        lastname: true,
        username: true,
        role: true,
      },
    });

    if (!user) {
      const error = new Error("unable to delete user");
      error.status = 404;
      error.details = "User not found";
      throw error;
    }

    //admin cannot delete current account for safety
    if (currentUser === id) {
      const error = new Error("unable to delete user");
      error.status = 500;
      error.details = "You cannot Delete your current account";
      throw error;
    }

    await prisma.user.delete({
      where: { id: userId },
    });

    return {
      user,
    };
  } catch (error) {
    throw error;
  }
}

export async function updateUserStatus(id, isActive, currentUserId) {
  const userId = parseInt(id, 10);
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      firstname: true,
      lastname: true,
      username: true,
      role: true,
    },
  });

  if (!user) {
    const error = new Error("User not found");
    error.status = 404;
    throw error;
  }

  if (userId === currentUserId && !isActive) {
    const error = new Error("You cannot disable your own admin account.");
    error.status = 403;
    throw error;
  }

  const updatedUser = await prisma.user.update({
    where: { id: userId },
    data: { isActive },
    select: {
      id: true,
      firstname: true,
      lastname: true,
      username: true,
      role: true,
      isActive: true,
    },
  });

  return { user: updatedUser };
}
