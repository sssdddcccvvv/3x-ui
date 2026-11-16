# AntiBan — hardened TSPU-stealth profile for 3x-ui

Date: 2026-11-16
Base: MHSanaei/3x-ui @ main (5297fd3c-era dev clone), fork by owner-operator.

## Intent and why

The operator runs a personal 3x-ui server whose users connect from Russia through
TSPU (Roskomnadzor DPI). TSPU no longer blocks only by SNI: it flags
TLS-in-TLS tunnels, post-quantum ML-KEM key shares, overused REALITY
SNI/dest combos (shared default lists), static xhttp fingerprints, and
non-443 TLS ports. The panel already ships every needed primitive
(SNI pools #6923, ML-KEM drop switch #6803, `cs` cipher-suite/fingerprint pin
#6825, fragment presets, ECH helper, noise masks, xhttp blank-default policy #5141)
but nothing composes them, and the panel's own defaults actively weaken setups
(VLESS clients default to `flow=''` — no Vision, the #1 TLS-in-TLS detector).

**AntiBan = one master toggle in panel settings.** When ON, the panel enforces a
hardened, legitimate-looking profile on new/edited VLESS+REALITY inbounds, on
new/edited clients, and on every generated share link / subscription. Goal:
traffic that behaves like ordinary TLS to a legitimate site, not "detectably a VPN".

## Goals

- One toggle (`antibanEnable`, default **off**; opt-in, never changes behavior silently on upgrade).
- When ON:
  1. **Clients**: every VLESS client gets `flow=xtls-rprx-vision` unless already set (also fixes the panel's `''` default while toggle is ON).
  2. **REALITY inbounds**: `serverNames` and `shortIds` must be non-empty (random shortIds auto-filled if blank); blank `dest`/`target` auto-filled by the panel's existing random target+SNI generator; admin warned (not blocked) if `dest`/SNI is on the shared default candidate list.
  3. **Share links / subscriptions** (internal/sub): VLESS links get fingerprint pinned via existing `cs`-param machinery, mux stripped, ML-KEM advertised as dropped (reuse existing `support-x25519mlkem768` handling), xhttp params left blank (xray defaults) per #5141.
  4. **UI**: settings toggle + one-line description; inbound editor shows a small "AntiBan active" hint when the toggle is on.
- Non-breaking: toggle OFF → byte-identical behavior to upstream.

## Non-goals / anti-goals

- No 100%-invisibility claim: TSPU behavioral detection can never be fully defeated by config; this feature maximizes mimicry.
- No new wire protocol (would require an Xray-core fork).
- Do not rewrite existing exported links; users re-import subscriptions after enabling (banner explains this).
- Do not silently edit inbounds the admin already validated — enforcement happens at save time and at link-generation time, with the existing inbound_push_guard untouched.

## Approaches considered

1. **Global settings toggle (chosen)** — one switch, enforced at save + link-generation time. Matches user request ("при включении её впн работал как обычно"), minimal UI, composable with existing features.
2. Per-inbound stealth button — finer control but N places to maintain and the user wanted one switch.
3. New protocol in-panel — impossible without forking Xray-core; rejected.

## SNI / dest / port guidance (shipped as panel copy + docs)

- **Port: 443 only.** TLS to foreign IPs on 443 is normal traffic; 8443/2053-style alt ports are VPN-shaped by themselves (panel web port 2053 is unrelated to proxy ports).
- **dest/SNI: pick a real site hosted at the same datacenter/hosting provider as your server** (REALITY proxies probe-traffic to dest; same-ASN dest makes SNI-IP correlation plausible to TSPU which increasingly binds SNI↔IP ranges).
- dest must support TLS 1.3 + HTTP/2 + X25519 key share, serve a valid cert for the SNI, and not redirect-kill probe paths.
- Avoid the shared default list verbatim (`www.cloudflare.com:443` is the single most abused REALITY dest and is likely clustered by TSPU); use the built-in scanner (`realityScanCandidates`) and pick a per-server candidate, prefer non-Cloudflare-hosted, non-blocked-in-RU, high-uptime sites.
- Keep uTLS fingerprint `chrome` (dropping ML-KEM, per #6803, is what makes chrome-like ClientHello survivable where TSPU blackholes PQ key shares).
- Fragmentation presets are a client-side fallback, enabled only when the operator opts in; Happ/Hiddify support them, but Vision+REALITY on 443 usually makes fragments unnecessary.

## Constraints

- Windows dev machine; deliverable is a git fork/branch + build instructions (user builds on their Linux server, standard `./build-all.sh`-style flow already in repo).
- `entity.AllSetting` changes must stay consistent with settings storage (`defaultValueMap`), frontend settings model, and (if checked-in) generated openapi/types artifacts.
- Translation: new UI strings added to en + ru locales minimum; other locales fall back.

## Left to the builder

- Exact insertion points for enforcement hooks (AddInbound/UpdateInbound ≈ lines 1297/2025 of internal/web/service/inbound.go; AddInboundClient/UpdateInboundClient in client_inbound_apply.go; sub generation in internal/sub/service.go + endpoint.go + clash_service.go reuse of mlkem/cs plumbing).
- Test coverage: toggle-off invariance, flow enforcement, shortIds autofill, link generation diff when on/off.
- Whether openapi.json / frontend/src/generated are build-generated or checked-in (check scripts, regenerate or hand-patch accordingly).
