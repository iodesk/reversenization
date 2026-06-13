# Changelog

## [1.0.1] � 2026-06-13

### Security

- Fix auth middleware X-User-ID header producing garbage via `string(rune(id))` ? `strconv.Itoa`.
- Add per-app trusted proxy CIDR configuration (`AdvancedConfig.TrustedProxies`) with right-to-left X-Forwarded-For walking.
- Close IP spoofing on dashboard API rate limiter via `TRUSTED_PROXIES` env var.
- Remove insecure inline IP extraction in challenge validator; now uses `ctx.ClientIP`.
- Fix race condition in `.env` write during setup (mutex + `0600` permissions).
- Remove trivially-reversible XOR obfuscation from slider challenge; trajectory analysis unchanged.
- Use full 256-bit HMAC signature in challenge cookies with 32-char backward compat.
- Set session cookie `SameSite=Lax`.
- Cap regex cache at 500 entries with LRU eviction.
- Raise default bcrypt cost 10?12, fix `BCRYPT_COST` parsing bug.

### Changed

- Challenge cookie format check now accepts 2-part and 3-part cookies.
- `handleWAFVerify` IP extraction prioritises `CF-Connecting-IP`.
- Health endpoint returns version and identifies as `VibesWAF`.
- Frontend: Trusted Proxies section (textarea, one CIDR per line) in Advanced tab.
- Fix bug auto migrate

### Internal

- `ExtractClientIP()` / `ExtractClientIPStatic()` on `app.App`.
- `const Version = "1.0.1"` in `internal/config/app_config.go`.