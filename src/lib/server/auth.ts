import argon2 from "argon2";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { NextRequest, NextResponse } from "next/server";
import { ApiError } from "@/lib/server/api";
import { db, findUserById, toPublicUser } from "@/lib/server/db";
import type { PublicUser } from "@/lib/types";

export const SESSION_COOKIE = "ciphervault_session";
const SESSION_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
const ARGON_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 65_536,
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
} as const;

const DUMMY_HASH =
  "$argon2id$v=19$m=65536,p=1,t=3$mHwmj/vV7Us15f+RMK1SiQ$fzERfI2hyP/u97ghSxn7CdaCe0DJVtCm+lqxnIkkfXs";

function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

function requestIp(request: NextRequest): string {
  if (process.env.TRUST_PROXY === "true") {
    return request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  }
  return "untrusted-network";
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function createUser(email: string, passwordHash: string): PublicUser {
  const id = randomUUID();
  const createdAt = Date.now();
  db.prepare(
    "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
  ).run(id, email, passwordHash, createdAt);
  return { id, email, createdAt };
}

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, ARGON_OPTIONS);
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

export async function verifyPasswordWithFallback(
  hash: string | undefined,
  password: string,
): Promise<boolean> {
  const valid = await verifyPassword(hash ?? DUMMY_HASH, password);
  return Boolean(hash) && valid;
}

export function createSession(userId: string, request: NextRequest): string {
  const token = randomBytes(32).toString("base64url");
  const now = Date.now();
  db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(now);
  db.prepare(
    `INSERT INTO sessions (
      token_hash, user_id, expires_at, created_at, user_agent, ip_address
    ) VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(
    hashToken(token),
    userId,
    now + SESSION_LIFETIME_MS,
    now,
    request.headers.get("user-agent")?.slice(0, 255) ?? null,
    requestIp(request),
  );
  return token;
}

export function setSessionCookie(response: NextResponse, token: string): void {
  response.cookies.set(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: SESSION_LIFETIME_MS / 1000,
    priority: "high",
  });
}

export function clearSession(response: NextResponse): void {
  response.cookies.set(SESSION_COOKIE, "", {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 0,
  });
}

export function deleteSession(token: string): void {
  db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(hashToken(token));
}

export function getUserBySessionToken(token: string | undefined): PublicUser | null {
  if (!token) return null;
  const row = db
    .prepare("SELECT user_id FROM sessions WHERE token_hash = ? AND expires_at > ?")
    .get(hashToken(token), Date.now()) as { user_id: string } | undefined;
  if (!row) return null;
  const user = findUserById(row.user_id);
  return user ? toPublicUser(user) : null;
}

export function requireUser(request: NextRequest): PublicUser {
  const user = getUserBySessionToken(request.cookies.get(SESSION_COOKIE)?.value);
  if (!user) throw new ApiError(401, "Authentication required");
  return user;
}

export function checkLoginRateLimit(lookupKey: string): void {
  const now = Date.now();
  const row = db
    .prepare("SELECT * FROM login_attempts WHERE lookup_key = ?")
    .get(lookupKey) as
    | { attempts: number; window_started: number; blocked_until: number }
    | undefined;

  if (row && row.blocked_until > now) {
    throw new ApiError(429, "Login temporarily restricted. Try again later.");
  }
  if (row && now - row.window_started > 15 * 60 * 1000) {
    db.prepare("DELETE FROM login_attempts WHERE lookup_key = ?").run(lookupKey);
  }
}

export function loginLookupKey(request: NextRequest, email: string): string {
  return hashToken(`${requestIp(request)}|${email}`);
}

export function recordLoginFailure(lookupKey: string): void {
  const now = Date.now();
  const row = db
    .prepare("SELECT attempts, window_started FROM login_attempts WHERE lookup_key = ?")
    .get(lookupKey) as { attempts: number; window_started: number } | undefined;
  const withinWindow = row && now - row.window_started <= 15 * 60 * 1000;
  const attempts = withinWindow ? row.attempts + 1 : 1;
  const windowStarted = withinWindow ? row.window_started : now;
  const penalty = attempts >= 5 ? Math.min(60_000 * 2 ** Math.min(attempts - 5, 6), 3_600_000) : 0;

  db.prepare(
    `INSERT INTO login_attempts (lookup_key, attempts, window_started, blocked_until)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(lookup_key) DO UPDATE SET
      attempts=excluded.attempts,
      window_started=excluded.window_started,
      blocked_until=excluded.blocked_until`,
  ).run(lookupKey, attempts, windowStarted, now + penalty);
}

export function clearLoginFailures(lookupKey: string): void {
  db.prepare("DELETE FROM login_attempts WHERE lookup_key = ?").run(lookupKey);
}
