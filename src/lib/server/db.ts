import Database, { type Database as DatabaseType } from "better-sqlite3";
import { chmodSync, closeSync, mkdirSync, openSync } from "node:fs";
import path from "node:path";
import type { EncryptedFileRecord, PublicUser, VaultConfig } from "@/lib/types";

const databasePath = path.resolve(/* turbopackIgnore: true */
  process.cwd(),
  process.env.DATABASE_PATH ?? ".data/ciphervault.db",
);

const globalDb = globalThis as typeof globalThis & {
  ciphervaultDb?: DatabaseType;
};

function createDatabase(): DatabaseType {
  mkdirSync(path.dirname(databasePath), { recursive: true, mode: 0o700 });
  const descriptor = openSync(databasePath, "a", 0o600);
  closeSync(descriptor);
  chmodSync(databasePath, 0o600);
  const database = new Database(databasePath);
  database.pragma("busy_timeout = 5000");
  database.pragma("foreign_keys = ON");
  database.pragma("journal_mode = WAL");
  database.exec(
    `
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        vault_data TEXT,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        user_agent TEXT,
        ip_address TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS encrypted_files (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        encrypted_name TEXT NOT NULL,
        name_nonce TEXT NOT NULL,
        wrapped_key TEXT NOT NULL,
        key_nonce TEXT NOT NULL,
        crypto_version INTEGER NOT NULL,
        encrypted_size INTEGER NOT NULL,
        plain_size INTEGER NOT NULL,
        checksum TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS login_attempts (
        lookup_key TEXT PRIMARY KEY,
        attempts INTEGER NOT NULL,
        window_started INTEGER NOT NULL,
        blocked_until INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS sessions_user_id_idx
        ON sessions(user_id);
      CREATE INDEX IF NOT EXISTS sessions_expires_at_idx
        ON sessions(expires_at);
      CREATE INDEX IF NOT EXISTS encrypted_files_user_created_idx
        ON encrypted_files(user_id, created_at DESC);
    `,
  );
  return database;
}

export const db = globalDb.ciphervaultDb ?? createDatabase();

if (process.env.NODE_ENV !== "production") {
  globalDb.ciphervaultDb = db;
}

type UserRow = {
  id: string;
  email: string;
  password_hash: string;
  vault_data: string | null;
  created_at: number;
};

type FileRow = {
  id: string;
  encrypted_name: string;
  name_nonce: string;
  wrapped_key: string;
  key_nonce: string;
  crypto_version: number;
  encrypted_size: number;
  plain_size: number;
  checksum: string;
  created_at: number;
};

export function toPublicUser(row: Pick<UserRow, "id" | "email" | "created_at">): PublicUser {
  return { id: row.id, email: row.email, createdAt: row.created_at };
}

export function findUserByEmail(email: string): UserRow | undefined {
  return db
    .prepare("SELECT * FROM users WHERE email = ?")
    .get(email) as UserRow | undefined;
}

export function findUserById(id: string): UserRow | undefined {
  return db.prepare("SELECT * FROM users WHERE id = ?").get(id) as UserRow | undefined;
}

export function getVaultConfig(userId: string): VaultConfig | null {
  const row = db
    .prepare("SELECT vault_data FROM users WHERE id = ?")
    .get(userId) as { vault_data: string | null } | undefined;
  return row?.vault_data ? (JSON.parse(row.vault_data) as VaultConfig) : null;
}

export function listFiles(userId: string): EncryptedFileRecord[] {
  const rows = db
    .prepare(
      `SELECT id, encrypted_name, name_nonce, wrapped_key, key_nonce,
        crypto_version, encrypted_size, plain_size, checksum, created_at
       FROM encrypted_files
       WHERE user_id = ?
       ORDER BY created_at DESC`,
    )
    .all(userId) as FileRow[];

  return rows.map((row) => ({
    id: row.id,
    encryptedName: row.encrypted_name,
    nameNonce: row.name_nonce,
    wrappedKey: row.wrapped_key,
    keyNonce: row.key_nonce,
    cryptoVersion: 1,
    encryptedSize: row.encrypted_size,
    plainSize: row.plain_size,
    checksum: row.checksum,
    createdAt: row.created_at,
  }));
}

export function findFile(userId: string, fileId: string): EncryptedFileRecord | null {
  const row = db
    .prepare(
      `SELECT id, encrypted_name, name_nonce, wrapped_key, key_nonce,
        crypto_version, encrypted_size, plain_size, checksum, created_at
       FROM encrypted_files
       WHERE user_id = ? AND id = ?`,
    )
    .get(userId, fileId) as FileRow | undefined;

  if (!row) return null;
  return {
    id: row.id,
    encryptedName: row.encrypted_name,
    nameNonce: row.name_nonce,
    wrappedKey: row.wrapped_key,
    keyNonce: row.key_nonce,
    cryptoVersion: 1,
    encryptedSize: row.encrypted_size,
    plainSize: row.plain_size,
    checksum: row.checksum,
    createdAt: row.created_at,
  };
}
