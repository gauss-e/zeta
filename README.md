# Zeta

A high-performance passthrough proxy service:
- Clients call `/proxy` with an encrypted query parameter (default name: `u`).
- The server decrypts the parameter to get the full upstream third-party URL.
- It forwards the original request method, headers, and body to that upstream URL.
- It returns the upstream response status, headers, and body back to the client as-is (except hop-by-hop headers).

## Run

```bash
cp .env.example .env
# Set DECRYPT_KEY_B64 in .env
cargo run
```

## Configuration

- `LISTEN_ADDR`: listening address, default `0.0.0.0:8080`
- `DECRYPT_KEY_B64`: 32-byte AES-256-GCM key in base64url (no padding)
- `URL_PARAM_NAME`: encrypted URL query parameter name, default `u`
- `REQUEST_TIMEOUT_SECS`: upstream request timeout in seconds, default `30`

## Encryption Format

The `u` value format is:

`base64url_no_pad(nonce(12 bytes) || ciphertext_and_tag)`

The plaintext is a full URL, for example:

```text
https://httpbin.org/anything?x=1
```

Use the same `DECRYPT_KEY_B64` as the server. Encrypt with AES-256-GCM, then concatenate `nonce + ciphertext + tag`, and finally encode with base64url (no padding).

## Utility Module

This project includes a `UrlCrypto` utility in `src/crypto.rs`:
- `decrypt_to_url`: decrypts `u` into the upstream URL (used by the main request flow)
- `encrypt_url`: encrypts a plaintext URL into a `u` value (for internal reuse)

The project now has only one binary target (the proxy service).

## Example Request

```bash
curl -i "http://127.0.0.1:8080/proxy?u=<encrypted>" \
  -H 'x-test: 1' \
  -d '{"hello":"world"}'
```
