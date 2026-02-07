# passthrough-proxy

高性能透传代理服务：
- Client 发送请求到 `/proxy`，query 带加密参数（默认参数名 `u`）。
- 服务端解密得到第三方完整 URL。
- 使用原请求 method/header/body 发起上游请求。
- 上游返回后，status/header/body 原样透传给 client（去除 hop-by-hop 头）。

## 运行

```bash
cp .env.example .env
# 填写 DECRYPT_KEY_B64
cargo run
```

## 配置项

- `LISTEN_ADDR`：监听地址，默认 `0.0.0.0:8080`
- `DECRYPT_KEY_B64`：32字节 AES-256-GCM 密钥（base64url，无 padding）
- `URL_PARAM_NAME`：加密 URL 的 query 参数名，默认 `u`
- `REQUEST_TIMEOUT_SECS`：上游请求超时秒数，默认 `30`

## 加密格式

`u` 的值是 `base64url_no_pad(nonce(12 bytes) || ciphertext_and_tag)`。
明文内容是完整 URL，例如：

```text
https://httpbin.org/anything?x=1
```

使用和服务端一致的 `DECRYPT_KEY_B64`，按 AES-256-GCM 加密后拼接 nonce+ciphertext+tag，再做 base64url 编码。

## 工具模块

项目内置了 `UrlCrypto` 工具（`src/crypto.rs`），提供：
- `decrypt_to_url`：解密 `u` 参数得到目标 URL（服务主流程使用）
- `encrypt_url`：将明文 URL 加密为 `u` 参数值（便于你在业务代码中复用）

当前项目只保留一个二进制目标（主服务），不再包含独立的 `encrypt_url` 可执行文件。

## 接口示例

```bash
curl -i "http://127.0.0.1:8080/proxy?u=<encrypted>" \
  -H 'x-test: 1' \
  -d '{"hello":"world"}'
```
