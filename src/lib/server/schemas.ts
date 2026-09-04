import { z } from "zod";

const encodedBytes = (label: string, maxLength: number) =>
  z
    .string()
    .min(1, `${label} is required`)
    .max(maxLength, `${label} is too large`)
    .regex(/^[A-Za-z0-9+/_=-]+$/, `${label} is not valid base64`);

export const credentialsSchema = z.object({
  email: z.email("Enter a valid email address").max(254).transform((value) => value.trim().toLowerCase()),
  password: z
    .string()
    .min(15, "Use at least 15 characters")
    .max(128, "Password must be at most 128 characters"),
});

export const vaultConfigSchema = z.object({
  formatVersion: z.literal(1),
  wrappedMasterKey: encodedBytes("Wrapped master key", 256),
  salt: encodedBytes("Salt", 128),
  nonce: encodedBytes("Nonce", 128),
  kdf: z.object({
    name: z.literal("argon2id"),
    version: z.literal(1),
    opsLimit: z.number().int().min(2).max(10),
    memLimit: z.number().int().min(19 * 1024 * 1024).max(1024 * 1024 * 1024),
  }),
});

export const fileMetadataSchema = z.object({
  id: z.uuid(),
  encryptedName: encodedBytes("Encrypted filename", 4096),
  nameNonce: encodedBytes("Filename nonce", 128),
  wrappedKey: encodedBytes("Wrapped file key", 256),
  keyNonce: encodedBytes("File-key nonce", 128),
  cryptoVersion: z.literal(1),
  plainSize: z.number().int().min(0).max(50 * 1024 * 1024),
});
