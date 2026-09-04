export type PublicUser = {
  id: string;
  email: string;
  createdAt: number;
};

export type VaultKdf = {
  name: "argon2id";
  version: 1;
  opsLimit: number;
  memLimit: number;
};

export type VaultConfig = {
  formatVersion: 1;
  wrappedMasterKey: string;
  salt: string;
  nonce: string;
  kdf: VaultKdf;
};

export type EncryptedFileRecord = {
  id: string;
  encryptedName: string;
  nameNonce: string;
  wrappedKey: string;
  keyNonce: string;
  cryptoVersion: 1;
  encryptedSize: number;
  plainSize: number;
  checksum: string;
  createdAt: number;
};

export type ApiErrorBody = {
  error: string;
};
