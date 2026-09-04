import type { NextRequest } from "next/server";
import { ApiError, noStoreJson, requireSameOrigin, responseForError } from "@/lib/server/api";
import { requireUser } from "@/lib/server/auth";
import { db, findFile, getVaultConfig, listFiles } from "@/lib/server/db";
import { fileMetadataSchema } from "@/lib/server/schemas";
import { maxUploadBytes, removeEncryptedFile, storeEncryptedFile } from "@/lib/server/storage";

export async function GET(request: NextRequest) {
  try {
    const user = requireUser(request);
    return noStoreJson({ files: listFiles(user.id) });
  } catch (error) {
    return responseForError(error);
  }
}

export async function POST(request: NextRequest) {
  try {
    requireSameOrigin(request);
    const user = requireUser(request);
    if (!getVaultConfig(user.id)) throw new ApiError(409, "Initialize the vault first");

    const declaredLength = Number.parseInt(request.headers.get("content-length") ?? "0", 10);
    if (declaredLength > maxUploadBytes) throw new ApiError(413, "Encrypted upload is too large");

    const form = await request.formData();
    const content = form.get("content");
    if (!(content instanceof Blob)) throw new ApiError(400, "Encrypted file content is required");
    if (content.size === 0 || content.size > maxUploadBytes) {
      throw new ApiError(413, "Encrypted upload is empty or too large");
    }

    const metadata = fileMetadataSchema.parse({
      id: form.get("id"),
      encryptedName: form.get("encryptedName"),
      nameNonce: form.get("nameNonce"),
      wrappedKey: form.get("wrappedKey"),
      keyNonce: form.get("keyNonce"),
      cryptoVersion: Number(form.get("cryptoVersion")),
      plainSize: Number(form.get("plainSize")),
    });

    if (findFile(user.id, metadata.id)) throw new ApiError(409, "File identifier already exists");
    const bytes = new Uint8Array(await content.arrayBuffer());
    const checksum = await storeEncryptedFile(user.id, metadata.id, bytes);
    const createdAt = Date.now();

    try {
      db.prepare(
        `INSERT INTO encrypted_files (
          id, user_id, encrypted_name, name_nonce, wrapped_key, key_nonce,
          crypto_version, encrypted_size, plain_size, checksum, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        metadata.id,
        user.id,
        metadata.encryptedName,
        metadata.nameNonce,
        metadata.wrappedKey,
        metadata.keyNonce,
        metadata.cryptoVersion,
        bytes.byteLength,
        metadata.plainSize,
        checksum,
        createdAt,
      );
    } catch (error) {
      await removeEncryptedFile(user.id, metadata.id);
      throw error;
    }

    const file = findFile(user.id, metadata.id);
    if (!file) throw new ApiError(500, "Encrypted file metadata was not saved");
    return noStoreJson({ file }, 201);
  } catch (error) {
    return responseForError(error);
  }
}
