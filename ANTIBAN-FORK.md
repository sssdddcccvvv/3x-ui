# AntiBan fork — notes for the operator

This fork adds a single panel switch, **Settings → General → 🛡 AntiBan**, that turns the
3x-ui primitives for DPI-resistant REALITY into one enforced profile.

Everything here is built on stock 3x-ui features (REALITY, Vision flow, SNI pools, the
`cs` fingerprint pin, the Mihomo X25519 switch). AntiBan only *composes* them — it does not
introduce a new wire protocol and it does not claim to make a tunnel invisible.

## What the toggle does

With **AntiBan** enabled the panel changes three places:

| Where | What happens |
| --- | --- |
| Saving an inbound (`AddInbound` / `UpdateInbound` / client add+update) | VLESS + REALITY over TCP inbounds get a hardened profile: every client without a flow gets `xtls-rprx-vision`, an empty `shortIds` list gets a random 8-char lowercase hex id, and an empty `serverNames` list gets the SNI derived from the REALITY target host. |
| Generating share links / subscriptions (`internal/sub`) | The same profile is applied to the inbound copy used for link generation, so a client that was created *before* the toggle still gets `flow=xtls-rprx-vision` in a freshly generated `vless://` link and in the JSON subscription outbounds. |
| Clash/Mihomo subscriptions and links | The `support-x25519mlkem768` hint is dropped **only** when the serving Xray core is older than 26.9.8 (see below). |

Only VLESS over TCP+REALITY is touched. Plain-TLS VLESS, Trojan, VMess, shadowsocks,
Hysteria, TUIC, MASQUE, WireGuard/AmneziaWG and every non-REALITY transport are left exactly
as they were. The toggle is **off by default** and, while off, the panel behaves byte-for-byte
like upstream 3x-ui.

### The ML-KEM rule (important)

Xray core 26.9.8+ *rejects* REALITY handshakes that do not carry an ML-KEM key share, while
many DPI systems (TSPU among them) blackhole exactly that two-segment post-quantum key
share. So the two requirements conflict:

* core **older than 26.9.8** → the panel drops the ML-KEM hint (plain X25519 hello),
* core **26.9.8 or newer** → the panel keeps it, because dropping it would break the tunnel.

The panel reads the version of the core it is running, so the switch is automatic. If you
upgrade the core, the hybrid key share comes back on its own.

## What it does *not* promise

* No 100 % invisibility guarantee. AntiBan removes the cheapest detectors (TLS-in-TLS
  nesting, an empty flow, a shared default SNI/destination, a stale static fingerprint),
  not the expensive ones (active probing, statistical fingerprinting of your IP, timing).
* It does not rewrite links that were already exported. **After enabling the toggle every
  client must re-import its subscription** so the new `flow`/SNI/shortId reach the device.
* It does not touch inbounds that were saved before, until they are saved again.

## SNI / destination / port guidance

AntiBan can only harden what you give it. The rules that matter:

1. **Port 443 only.** Anything else is trivially classified by the DPI.
2. **Destination = a real site served from the same datacenter/ASN as your server.** The
   REALITY handshake is proxied to that site, so the TLS fingerprint of the target must look
   like the fingerprint of the site itself.
3. The destination must support **TLS 1.3 + HTTP/2 + X25519** and present a valid
   certificate for the SNI you advertise.
4. **Do not use the shared default candidate list verbatim.** The panel ships
   `www.cloudflare.com, www.microsoft.com, www.amazon.com, …` as scan candidates; thousands
   of installs share them, which is exactly what group fingerprinting looks like. AntiBan
   warns in the log when a destination comes from that list — pick your own.
5. **Keep the `chrome` uTLS fingerprint.** It is the most widely deployed; do not invent a
   custom one. If you pin cipher suites with the `cs` parameter, remember that Xray drops
   the cipher-suite list under every uTLS fingerprint, so `cs` is a pin, not an override.
6. Fragmented ClientHello (`tlshello` fragment presets) is a client-side option; use it when
   your DPI still kills the tunnel after the profile above.

## Building this fork

```bash
# server side (Debian/Ubuntu)
git clone <your-fork> 3x-ui && cd 3x-ui
cd frontend && npm ci && npm run build && cd ..
go build -o x-ui ./            # requires Go >= 1.27 and CGO (sqlite3)
```

The web panel is embedded from `frontend/dist`, so `npm run build` must run **before**
`go build`, otherwise the build fails with `pattern all:dist: no matching files found`.

Enable the switch in the panel: **Settings → General → 🛡 AntiBan**, then save the settings
and re-import every subscription.

## Branches

* `main` — upstream 3x-ui (unmodified).
* `antiban` — this fork: AntiBan toggle, enforcement in the inbound/client save path and in
  the link/subscription generation path, Mihomo ML-KEM handling, the settings switch, and the
  "AntiBan is active" hint in the inbound editor.

## Tests

```bash
go test -p 1 ./internal/sub/        # link generation + ML-KEM behaviour
go test ./internal/web/service/     # setting + save-path enforcement
cd frontend && npx vitest run src/test/antiban-settings-toggle.test.tsx src/test/antiban-active-hint.test.tsx
```
