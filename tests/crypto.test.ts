import { beforeAll, describe, expect, it } from "vitest";
import {
  createVault,
  decryptFile,
  decryptFilename,
  getSodium,
  openFileKey,
  prepareUpload,
  rewrapVault,
  unlockVault,
} from "@/lib/client/crypto";
import type { EncryptedFileRecord, VaultConfig } from "@/lib/types";

const passphrase = "correct horse battery staple for vault";
let config: VaultConfig;
let masterKey: Uint8Array;

beforeAll(async () => {
  const created = await createVault(passphrase);
  config = created.config;
  masterKey = created.masterKey;
});

describe("vault key hierarchy", () => {
  it("unwraps the same random master key with the correct passphrase", async () => {
    const unlocked = await unlockVault(config, passphrase);
    expect(unlocked).toEqual(masterKey);
  });

  it("rejects an incorrect passphrase", async () => {
    await expect(unlockVault(config, "this is definitely the wrong passphrase")).rejects.toThrow(
      /incorrect|modified/,
    );
  });

  it("changes the passphrase by rewrapping rather than changing the master key", async () => {
    const nextPassphrase = "an even longer replacement vault passphrase";
    const rewrapped = await rewrapVault(masterKey, nextPassphrase);
    await expect(unlockVault(rewrapped, passphrase)).rejects.toThrow();
    expect(await unlockVault(rewrapped, nextPassphrase)).toEqual(masterKey);
  });
});

describe("encrypted file container", () => {
  it("round-trips content and an encrypted filename", async () => {
    const fileId = crypto.randomUUID();
    const plaintext = "CipherVault test content\nwith multiple lines.";
    const file = new File([plaintext], "private-notes.txt", { type: "text/plain" });
    const prepared = await prepareUpload(file, fileId, masterKey);
    const record: EncryptedFileRecord = {
      ...prepared.metadata,
      encryptedSize: prepared.encryptedContent.size,
      checksum: "test-checksum",
      createdAt: Date.now(),
    };

    expect(await decryptFilename(record, masterKey)).toBe("private-notes.txt");
    const fileKey = await openFileKey(record, masterKey);
    const decrypted = await decryptFile(prepared.encryptedContent, fileKey);
    expect(await decrypted.text()).toBe(plaintext);
  });

  it("rejects a one-byte ciphertext modification", async () => {
    const fileId = crypto.randomUUID();
    const file = new File(["tamper-evident content"], "evidence.txt");
    const prepared = await prepareUpload(file, fileId, masterKey);
    const record: EncryptedFileRecord = {
      ...prepared.metadata,
      encryptedSize: prepared.encryptedContent.size,
      checksum: "test-checksum",
      createdAt: Date.now(),
    };
    const fileKey = await openFileKey(record, masterKey);
    const bytes = new Uint8Array(await prepared.encryptedContent.arrayBuffer());
    bytes[bytes.length - 1] ^= 1;

    await expect(decryptFile(new Blob([bytes]), fileKey)).rejects.toThrow(/authentication/);
  });

  it("rejects a file key moved to a different record ID", async () => {
    const fileId = crypto.randomUUID();
    const file = new File(["bound to metadata"], "bound.txt");
    const prepared = await prepareUpload(file, fileId, masterKey);
    const movedRecord: EncryptedFileRecord = {
      ...prepared.metadata,
      id: crypto.randomUUID(),
      encryptedSize: prepared.encryptedContent.size,
      checksum: "test-checksum",
      createdAt: Date.now(),
    };

    await expect(openFileKey(movedRecord, masterKey)).rejects.toThrow(/different record/);
  });

  it("uses distinct ciphertext for identical inputs", async () => {
    const file = new File(["same content"], "same.txt");
    const first = await prepareUpload(file, crypto.randomUUID(), masterKey);
    const second = await prepareUpload(file, crypto.randomUUID(), masterKey);
    const sodium = await getSodium();
    const firstBytes = new Uint8Array(await first.encryptedContent.arrayBuffer());
    const secondBytes = new Uint8Array(await second.encryptedContent.arrayBuffer());

    expect(sodium.to_hex(firstBytes)).not.toBe(sodium.to_hex(secondBytes));
  });
});
