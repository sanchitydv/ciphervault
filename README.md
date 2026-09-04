# CipherVault

CipherVault is a full-stack, zero-knowledge-style encrypted file vault. Files and filenames are encrypted in the browser before upload; the server stores only ciphertext, wrapped keys, authentication metadata, account identifiers, sizes, and timestamps.

> This is a portfolio and learning project, not an independently audited cryptographic product. Do not use it as the only copy of irreplaceable data.

## Highlights

- Client-side streaming encryption with XChaCha20-Poly1305
- Memory-hard Argon2id password hashing and vault-key derivation
- Three-level key hierarchy: passphrase key → vault master key → per-file key
- Authenticated filenames and record-bound key wrapping
- Opaque file storage with server-side SHA-256 corruption checks
- Random, hashed, revocable database sessions
- Login throttling, same-origin mutation checks, secure cookies, and security headers
- Versioned ciphertext format and negative cryptographic tests
- Responsive UI, Docker packaging, SQLite persistence, and documented threat model

## Quick start

Requirements: Node.js 22 or newer and npm 10 or newer.

```bash
cp .env.example .env.local
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000), create an account, and then create a separate vault passphrase. Local application data is created under `.data/` and ignored by Git.

```bash
npm run check      # lint, TypeScript, and cryptographic tests
npm run build      # optimized production build
npm start          # run the production build
```

## Encryption architecture

```text
Vault passphrase
       └─ Argon2id(passphrase, random salt, saved cost parameters)
                         │
                         ▼
                 Key Encryption Key
                         │ decrypts
                         ▼
              random Vault Master Key
                         │ decrypts
                         ▼
                random per-file key
                         │
              ┌──────────┴───────────┐
              ▼                      ▼
      encrypted filename     encrypted file chunks
```

The **account password** is sent over TLS and verified by the server with Argon2id. The **vault passphrase** never leaves the browser; Argon2id derives a key that unwraps the random vault master key. Changing the vault passphrase only rewraps that key and does not re-encrypt every file.

Every file gets a random 256-bit key. The key and filename use XChaCha20-Poly1305. The file body uses libsodium `secretstream` in 1 MiB chunks to detect modification, truncation, duplication, and reordering. File identifiers are authenticated when wrapping file keys and names, so moving metadata to another record fails verification.

See [the container specification](docs/FORMAT.md) and [security model](SECURITY.md) for exact boundaries.

## Structure

```text
src/
├── app/api/                 authenticated route handlers
├── components/              authentication and vault UI
└── lib/
    ├── client/crypto.ts     browser cryptographic operations
    └── server/              auth, SQLite, validation, storage
```

## API

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/api/auth/register` | Create account and session |
| `POST` | `/api/auth/login` | Verify account credentials |
| `POST` | `/api/auth/logout` | Revoke current session |
| `GET` | `/api/auth/me` | Return authenticated user |
| `GET/POST/PUT` | `/api/vault` | Read, create, or rewrap vault metadata |
| `GET/POST` | `/api/files` | List metadata or store encrypted content |
| `GET` | `/api/files/:id/content` | Download opaque ciphertext |
| `DELETE` | `/api/files/:id` | Delete an owned encrypted object |

Every vault and file handler authenticates inside the route. File queries always include the current user ID, so knowing another UUID is insufficient for access.

## Docker

```bash
docker compose up --build
```

SQLite and encrypted files are stored in a named volume at `/data`. Terminate TLS at a trusted reverse proxy in public deployments.

## Deliberate scope

Version 1 supports account-password authentication, single-device passphrase entry, files up to 50 MiB, encrypted upload/download, deletion, and passphrase changes.

Future work includes WebAuthn, multi-device enrollment, public-key sharing, recovery, object-storage adapters, and audited dependency pinning. Do not represent those as completed features.

## Suggested resume entry

> **CipherVault — End-to-End Encrypted File Storage**<br>
> Built a full-stack encrypted file vault using Argon2id and XChaCha20-Poly1305, implementing browser-side chunk encryption, hierarchical key wrapping, encrypted filenames, authenticated metadata, secure database sessions, tamper tests, and containerized deployment.
