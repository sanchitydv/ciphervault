# Encrypted container format v1

All integers are unsigned and big-endian. The server treats the container as opaque bytes.

| Offset | Size | Meaning |
| --- | ---: | --- |
| `0` | 4 | ASCII magic `CVLT` |
| `4` | 1 | Version (`1`) |
| `5` | 1 | Flags (`0`) |
| `6` | 4 | Plaintext chunk size (`1,048,576`) |
| `10` | 24 | libsodium secretstream header |
| `34` | repeated | Framed encrypted chunks |

Each frame is `4-byte ciphertext length | ciphertext and authentication tag`. The final frame must authenticate with `TAG_FINAL`. The decoder rejects unknown versions, unreasonable sizes, truncation, malformed frames, failed tags, missing final tags, or bytes after the final frame. An empty file contains one authenticated empty final frame.

## Authenticated contexts

```text
ciphervault:file-key:<file UUID>:v1
ciphervault:filename:<file UUID>:v1
ciphervault:master-key:v1
```

These are protocol constants. Changing one requires a new version and migration path.
