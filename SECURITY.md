# Security model

CipherVault is a portfolio implementation, not an audited security product. It uses libsodium and Argon2 rather than custom algorithms, but the application and protocol have not received independent review.

## Protected assets and properties

Protected assets include file contents and names, vault and file keys, account passwords, session tokens, and object ownership.

When the browser application is trusted, a database and file-storage dump does not contain plaintext files, filenames, vault passphrases, vault master keys, or per-file keys. The format detects modified, truncated, removed, reordered, or appended encrypted chunks and encrypted metadata moved to another record.

## Observable metadata

The server can observe account email addresses, login times, network metadata, file identifiers, encrypted sizes, approximate original sizes, upload times, file counts, and access patterns. “Zero knowledge” here refers to file plaintext and vault key material—not the absence of all metadata.

## Outside the threat model

- Malicious JavaScript served by a compromised deployment
- Browser extensions, keyloggers, screen capture, or client malware
- Plaintext copied after a legitimate download
- Weak or reused passphrases
- Availability attacks, server deletion, or loss of the only copy
- Traffic analysis based on size and timing

There is no password reset or cryptographic recovery. Losing the vault passphrase means losing access to vault data.

## Cryptographic choices

- Account passwords: Argon2id, 64 MiB, three iterations, parallelism one
- Vault KDF: Argon2id, 64 MiB and three operations, with a random salt
- Key and filename wrapping: XChaCha20-Poly1305 with random 192-bit nonces
- File bodies: `crypto_secretstream_xchacha20poly1305` with final-tag verification
- Sessions: random 256-bit values; only SHA-256 hashes are stored
- Ciphertext checksum: SHA-256 for operational corruption detection, not authenticity

All parameters and formats are versioned. Every file has a unique random key.

## Deployment requirements

- Serve only through HTTPS in production.
- Keep dependencies patched and back up the database and encrypted files together.
- Restrict `/data` to the application identity.
- Set `TRUST_PROXY=true` only behind a trusted proxy that removes client forwarding headers.
- Never log plaintext, passwords, cookies, vault keys, or request bodies.
- Add external rate limiting before public exposure; SQLite throttling is a single-instance safeguard.
- Revisit the Content Security Policy whenever scripts or workers change.

Report vulnerabilities privately to the repository owner with reproduction steps, affected version, and impact. Never include real secrets.
