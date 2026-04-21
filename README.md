# roxifyapi

To install dependencies:

```bash
bun install
```

To run:

```bash
bun run src/index.ts
```

## API

Base URL: `http://localhost:3000`

### Health

```bash
curl http://localhost:3000/health
```

Expected response:

```json
{
  "status": "ok"
}
```

### Encode Without AES

```bash
curl -X POST http://localhost:3000/encode/no-aes \
	-F "file=@test.txt" \
	-o output_no_aes.png
```

### Encode With AES

```bash
curl -X POST http://localhost:3000/encode/aes \
	-F "file=@test.txt" \
	-F "passphrase=mysecretpass123" \
	-o output_aes.png
```

### Decode Without AES

```bash
curl -X POST http://localhost:3000/decode/no-aes \
	-F "file=@output_no_aes.png" \
	-o decoded_no_aes.txt
```

### Decode With AES

```bash
curl -X POST http://localhost:3000/decode/aes \
	-F "file=@output_aes.png" \
	-F "passphrase=mysecretpass123" \
	-o decoded_aes.txt
```

### Inspect AES Protection

```bash
curl -X POST http://localhost:3000/inspect/aes \
	-F "file=@output_aes.png"
```

Expected encrypted response:

```json
{
  "encrypted": true,
  "encryptedAes": true,
  "note": "Passphrase protection detected (Roxify AES flow in this API)."
}
```
