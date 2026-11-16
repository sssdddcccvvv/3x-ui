package sub

import (
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

// antiBanVisionFlow is the XTLS flow AntiBan requires on vless+reality
// links. Without it the tunnel carries a plain TLS handshake inside the
// outer handshake — the TLS-in-TLS shape TSPU looks for.
const antiBanVisionFlow = "xtls-rprx-vision"

// antiBanEnabled reports whether the panel's AntiBan toggle is on. A missing
// database or an unreadable setting means "off": AntiBan must never engage
// because of a storage problem.
func antiBanEnabled() bool {
	return (&service.SettingService{}).GetAntiBanEnable()
}

// antiBanHardenedInbound returns the inbound with AntiBan's hardened profile
// applied. The original inbound is returned untouched when the toggle is off,
// when the protocol is not vless/reality/tcp, or when nothing had to change.
func antiBanHardenedInbound(inbound *model.Inbound) *model.Inbound {
	if inbound == nil {
		return inbound
	}
	hardened, changed, err := service.ApplyAntiBan(inbound)
	if err != nil || !changed || hardened == nil {
		return inbound
	}
	return hardened
}

// antiBanForcedFlow returns the flow AntiBan requires for the given stream,
// or an empty string when the stream needs none. Only tcp+reality is
// hardened — a flow on any other transport produces an outbound xray refuses
// to start.
func antiBanForcedFlow(network, security string) string {
	if network != "tcp" || security != "reality" {
		return ""
	}
	if !antiBanEnabled() {
		return ""
	}
	return antiBanVisionFlow
}
