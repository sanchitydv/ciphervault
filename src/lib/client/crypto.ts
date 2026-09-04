import type { EncryptedFileRecord, VaultConfig } from "@/lib/types";

type SodiumModule = typeof import("libsodium-wrappers-sumo");
type Sodium = SodiumModule["default"];

const MASTER_KEY_AAD = "ciphervault:master-key:v1";
const MAGIC = new Uint8Array([0x43, 0x56, 0x4c, 0x54]); // CVLT
const CONTAINER_VERSION = 1;
const DEFAULT_CHUNK_SIZE = 1024 * 1024;
const MAX_CHUNK_SIZE = 8 * 1024 * 1024;
const PREAMBLE_SIZE = 10;
const KDF_OPS_LIMIT = 3;
const KDF_MEM_LIMIT = 64 * 1024 * 1024;

let sodiumPromise: Promise<Sodium> | undefined;

export async function getSodium(): Promise<Sodium> {
  sodiumPromise ??= import("libsodium-wrappers-sumo").then(async (module) => {
    await module.default.ready;
    return module.default;
  });
  return sodiumPromise;
}

function asBlobPart(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

function encode(sodium: Sodium, bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}

function decode(sodium: Sodium, value: string): Uint8Array {
  return sodium.from_base64(value, sodium.base64_variants.ORIGINAL);
}

function keyAad(fileId: string): string {
  return `ciphervault:file-key:${fileId}:v1`;
}

function nameAad(fileId: string): string {
  return `ciphervault:filename:${fileId}:v1`;
}

function deriveWrappingKey(sodium: Sodium, passphrase: string, config: VaultConfig): Uint8Array {
  return sodium.crypto_pwhash(
    sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    passphrase.normalize("NFC"),
    decode(sodium, config.salt),
    config.kdf.opsLimit,
    config.kdf.memLimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}

function wrapMasterKey(
  sodium: Sodium,
  masterKey: Uint8Array,
  passphrase: string,
): VaultConfig {
  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const config: VaultConfig = {
    formatVersion: 1,
    wrappedMasterKey: "pending",
    salt: encode(sodium, salt),
    nonce: "pending",
    kdf: {
      name: "argon2id",
      version: 1,
      opsLimit: KDF_OPS_LIMIT,
      memLimit: KDF_MEM_LIMIT,
    },
  };
  const wrappingKey = deriveWrappingKey(sodium, passphrase, config);
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

  try {
    const wrapped = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      masterKey,
      MASTER_KEY_AAD,
      null,
      nonce,
      wrappingKey,
    );
    return {
      ...config,
      wrappedMasterKey: encode(sodium, wrapped),
      nonce: encode(sodium, nonce),
    };
  } finally {
    sodium.memzero(wrappingKey);
  }
}

export async function createVault(passphrase: string): Promise<{
  config: VaultConfig;
  masterKey: Uint8Array;
}> {
  const sodium = await getSodium();
  const masterKey = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  return { config: wrapMasterKey(sodium, masterKey, passphrase), masterKey };
}

export async function unlockVault(
  config: VaultConfig,
  passphrase: string,
): Promise<Uint8Array> {
  const sodium = await getSodium();
  const wrappingKey = deriveWrappingKey(sodium, passphrase, config);
  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      decode(sodium, config.wrappedMasterKey),
      MASTER_KEY_AAD,
      decode(sodium, config.nonce),
      wrappingKey,
    );
  } catch {
    throw new Error("The vault passphrase is incorrect or the key data was modified");
  } finally {
    sodium.memzero(wrappingKey);
  }
}

export async function rewrapVault(
  masterKey: Uint8Array,
  newPassphrase: string,
): Promise<VaultConfig> {
  const sodium = await getSodium();
  return wrapMasterKey(sodium, masterKey, newPassphrase);
}

export async function lockKey(key: Uint8Array | null): Promise<void> {
  if (!key) return;
  const sodium = await getSodium();
  sodium.memzero(key);
}

export type PreparedUpload = {
  metadata: Omit<EncryptedFileRecord, "encryptedSize" | "checksum" | "createdAt">;
  encryptedContent: Blob;
};

export async function prepareUpload(
  file: File,
  fileId: string,
  masterKey: Uint8Array,
  onProgress?: (progress: number) => void,
): Promise<PreparedUpload> {
  const sodium = await getSodium();
  const fileKey = sodium.randombytes_buf(sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES);
  const keyNonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const nameNonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

  try {
    const wrappedKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      fileKey,
      keyAad(fileId),
      null,
      keyNonce,
      masterKey,
    );
    const encryptedName = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      sodium.from_string(file.name),
      nameAad(fileId),
      null,
      nameNonce,
      fileKey,
    );
    const encryptedContent = await encryptFile(file, fileKey, onProgress);
    return {
      metadata: {
        id: fileId,
        encryptedName: encode(sodium, encryptedName),
        nameNonce: encode(sodium, nameNonce),
        wrappedKey: encode(sodium, wrappedKey),
        keyNonce: encode(sodium, keyNonce),
        cryptoVersion: 1,
        plainSize: file.size,
      },
      encryptedContent,
    };
  } finally {
    sodium.memzero(fileKey);
  }
}

export async function openFileKey(
  record: EncryptedFileRecord,
  masterKey: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium();
  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      decode(sodium, record.wrappedKey),
      keyAad(record.id),
      decode(sodium, record.keyNonce),
      masterKey,
    );
  } catch {
    throw new Error("The file key is invalid or belongs to a different record");
  }
}

export async function decryptFilename(
  record: EncryptedFileRecord,
  masterKey: Uint8Array,
): Promise<string> {
  const sodium = await getSodium();
  const fileKey = await openFileKey(record, masterKey);
  try {
    const name = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      decode(sodium, record.encryptedName),
      nameAad(record.id),
      decode(sodium, record.nameNonce),
      fileKey,
    );
    return sodium.to_string(name);
  } catch {
    throw new Error("The encrypted filename failed authentication");
  } finally {
    sodium.memzero(fileKey);
  }
}

function frameLength(length: number): Uint8Array {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, length, false);
  return result;
}

function makePreamble(chunkSize: number): Uint8Array {
  const bytes = new Uint8Array(PREAMBLE_SIZE);
  bytes.set(MAGIC, 0);
  bytes[4] = CONTAINER_VERSION;
  bytes[5] = 0;
  new DataView(bytes.buffer).setUint32(6, chunkSize, false);
  return bytes;
}

export async function encryptFile(
  file: Blob,
  fileKey: Uint8Array,
  onProgress?: (progress: number) => void,
): Promise<Blob> {
  const sodium = await getSodium();
  const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(fileKey);
  const parts: BlobPart[] = [
    asBlobPart(makePreamble(DEFAULT_CHUNK_SIZE)),
    asBlobPart(header),
  ];
  let offset = 0;

  do {
    const end = Math.min(offset + DEFAULT_CHUNK_SIZE, file.size);
    const message = new Uint8Array(await file.slice(offset, end).arrayBuffer());
    const final = end === file.size;
    const cipher = sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      message,
      null,
      final
        ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    );
    parts.push(asBlobPart(frameLength(cipher.byteLength)), asBlobPart(cipher));
    offset = end;
    onProgress?.(file.size === 0 ? 1 : offset / file.size);
  } while (offset < file.size);

  return new Blob(parts, { type: "application/vnd.ciphervault.encrypted" });
}

async function readRange(blob: Blob, start: number, length: number): Promise<Uint8Array> {
  if (start < 0 || length < 0 || start + length > blob.size) {
    throw new Error("Encrypted file is truncated");
  }
  return new Uint8Array(await blob.slice(start, start + length).arrayBuffer());
}

function parsePreamble(bytes: Uint8Array): number {
  if (bytes.byteLength !== PREAMBLE_SIZE || !MAGIC.every((value, index) => bytes[index] === value)) {
    throw new Error("This is not a CipherVault file");
  }
  if (bytes[4] !== CONTAINER_VERSION || bytes[5] !== 0) {
    throw new Error("Unsupported CipherVault file format");
  }
  const chunkSize = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(6, false);
  if (chunkSize < 1024 || chunkSize > MAX_CHUNK_SIZE) {
    throw new Error("Encrypted file uses an invalid chunk size");
  }
  return chunkSize;
}

export async function decryptFile(
  encrypted: Blob,
  fileKey: Uint8Array,
  onProgress?: (progress: number) => void,
): Promise<Blob> {
  const sodium = await getSodium();
  parsePreamble(await readRange(encrypted, 0, PREAMBLE_SIZE));
  let cursor = PREAMBLE_SIZE;
  const headerLength = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
  const header = await readRange(encrypted, cursor, headerLength);
  cursor += headerLength;
  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, fileKey);
  const output: BlobPart[] = [];
  let sawFinal = false;

  while (cursor < encrypted.size) {
    if (sawFinal) throw new Error("Encrypted file contains data after its final chunk");
    const lengthBytes = await readRange(encrypted, cursor, 4);
    cursor += 4;
    const cipherLength = new DataView(
      lengthBytes.buffer,
      lengthBytes.byteOffset,
      lengthBytes.byteLength,
    ).getUint32(0, false);
    if (
      cipherLength < sodium.crypto_secretstream_xchacha20poly1305_ABYTES ||
      cipherLength > MAX_CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES
    ) {
      throw new Error("Encrypted file contains an invalid chunk");
    }

    const cipher = await readRange(encrypted, cursor, cipherLength);
    cursor += cipherLength;
    const result = sodium.crypto_secretstream_xchacha20poly1305_pull(state, cipher, null);
    if (!result) throw new Error("Encrypted file failed authentication");
    output.push(asBlobPart(result.message));
    sawFinal = result.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    onProgress?.(cursor / encrypted.size);
  }

  if (!sawFinal) throw new Error("Encrypted file is truncated or missing its final tag");
  return new Blob(output, { type: "application/octet-stream" });
}
