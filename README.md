# Zeta

A high-performance passthrough proxy service:
- Clients call `/data` with an encrypted query parameter (default name: `oeid`).
- The server decrypts the parameter to get the full upstream third-party URL.
- It forwards the original request method, headers, and body to that upstream URL.
- It returns the upstream response status, headers, and body back to the client as-is (except hop-by-hop headers).

## Run

## Configuration

The service loads environment variables from a `config` file in the project root.

- `LISTEN_ADDR`: listening address, default `0.0.0.0:8080`
- `AES_PASSWORD`: password for AES decryption (used to derive a key)
- `URL_PARAM_NAME`: encrypted URL query parameter name, default `oeid`
- `REQUEST_TIMEOUT_SECS`: upstream request timeout in seconds, default `30`

## Encryption Format

The `u` value format includes a prefix that selects the decode path:

- `{BASE64}<payload>`: payload is base64 (standard or url-safe, padding optional) of the plaintext URL.
- `{AES}<payload>`: payload is base64 (standard or url-safe, padding optional) of AES-ECB ciphertext with PKCS7 padding.

The plaintext is a full URL, for example:

```text
https://httpbin.org/anything?x=1
```

For `{AES}`, the AES-128 key is `MD5(AES_PASSWORD UTF-8 bytes)` to match `SecretKeySpec` derivation in Java. Encrypt with AES-ECB/PKCS7 and base64-encode the ciphertext.

## Utility Module

This project includes a `UrlCrypto` utility in `src/crypto.rs`:
- `decrypt_to_url`: decrypts `u` into the upstream URL (used by the main request flow)
- `encrypt_url`: encrypts a plaintext URL into a `u` value (for internal reuse)

The project now has only one binary target (the proxy service).

## Example Request

```bash
curl -i "http://127.0.0.1:8080/data?oeid=<encrypted>" \
  -H 'x-test: 1' \
  -d '{"hello":"world"}'
```
