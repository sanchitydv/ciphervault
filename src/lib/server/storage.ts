import { createHash, randomUUID } from "node:crypto";
import { link, mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import path from "node:path";

const storageRoot = path.resolve(/* turbopackIgnore: true */
  process.cwd(),
  process.env.STORAGE_PATH ?? ".data/encrypted-files",
);

export const maxUploadBytes = Number.parseInt(
  process.env.MAX_UPLOAD_BYTES ?? String(60 * 1024 * 1024),
  10,
);

function userDirectory(userId: string): string {
  return path.join(/* turbopackIgnore: true */ storageRoot, userId);
}

function filePath(userId: string, fileId: string): string {
  return path.join(userDirectory(userId), `${fileId}.cvlt`);
}

export async function storeEncryptedFile(
  userId: string,
  fileId: string,
  bytes: Uint8Array,
): Promise<string> {
  const directory = userDirectory(userId);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const destination = filePath(userId, fileId);
  const temporary = path.join(directory, `.${fileId}.${randomUUID()}.tmp`);
  await writeFile(temporary, bytes, { flag: "wx", mode: 0o600 });
  try {
    // A hard link makes publication atomic without overwriting an existing ID.
    await link(temporary, destination);
    await unlink(temporary);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
  return createHash("sha256").update(bytes).digest("hex");
}

export async function readEncryptedFile(userId: string, fileId: string): Promise<Buffer> {
  return readFile(filePath(userId, fileId));
}

export async function removeEncryptedFile(userId: string, fileId: string): Promise<void> {
  await unlink(filePath(userId, fileId)).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
  });
}
