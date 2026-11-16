package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

const (
	// antiBanVisionFlow is the only XTLS flow a REALITY inbound should use.
	// Without it the inner TLS handshake stays a plain TLS record inside the
	// outer TLS record, which is exactly the TLS-in-TLS pattern a DPI looks
	// for when it fingerprints a tunnel.
	antiBanVisionFlow = "xtls-rprx-vision"
	// antiBanShortIDBytes is the number of random bytes behind a REALITY
	// shortId; 4 bytes render as 8 lowercase hex characters, the format
	// Xray expects.
	antiBanShortIDBytes = 4
	// antiBanMLKEMDropCoreVersion is the first Xray core that refuses a
	// REALITY handshake without an ML-KEM key share. Only cores older than
	// this can be told to send a plain X25519 hello.
	antiBanMLKEMDropCoreVersion = "26.9.8"
)

// AntiBanCoreOlderThan reports whether the given Xray core version predates
// antiBanMLKEMDropCoreVersion, i.e. the core still accepts a plain X25519
// hello and the client may be told to drop the post-quantum key share.
//
// An unknown or unparsable version answers false: AntiBan never risks
// breaking a handshake on a version it cannot read.
func AntiBanCoreOlderThan(version string) bool {
	cmp, ok := compareXrayCoreVersions(version, antiBanMLKEMDropCoreVersion)
	if !ok {
		return false
	}
	return cmp < 0
}

// ApplyAntiBan hardens a VLESS + REALITY(TCP) inbound so the connection it
// produces is indistinguishable from a browser talking to the REALITY target.
//
// It rewrites three things, and only when they are missing:
//   - the client flow becomes xtls-rprx-vision, so the tunnel no longer
//     carries a detectable TLS-in-TLS handshake;
//   - realitySettings.shortIds gets a random 8 hex character id, so probes
//     cannot guess it;
//   - realitySettings.serverNames is derived from the REALITY target when the
//     admin left it empty.
//
// The returned inbound is a copy; the input is never mutated. When the toggle
// is off, or the inbound is not a VLESS + REALITY + TCP inbound, the input is
// returned unchanged together with changed=false. A malformed inbound is
// logged and left alone: AntiBan must never block a save.
func ApplyAntiBan(inbound *model.Inbound) (*model.Inbound, bool, error) {
	if inbound == nil {
		return nil, false, nil
	}
	if !(&SettingService{}).GetAntiBanEnable() {
		return inbound, false, nil
	}
	if string(inbound.Protocol) != "vless" {
		return inbound, false, nil
	}

	var stream map[string]any
	if err := json.Unmarshal([]byte(inbound.StreamSettings), &stream); err != nil {
		logger.Warningf("AntiBan: inbound %d has malformed stream settings, leaving it untouched: %v", inbound.Id, err)
		return inbound, false, nil
	}
	if network, _ := stream["network"].(string); network != "tcp" {
		return inbound, false, nil
	}
	if security, _ := stream["security"].(string); security != "reality" {
		return inbound, false, nil
	}
	reality, ok := stream["realitySettings"].(map[string]any)
	if !ok || reality == nil {
		return inbound, false, nil
	}

	destHost := antiBanTargetHost(reality)
	serverNames := antiBanStringSlice(reality["serverNames"])
	filledServerNames := false
	if len(serverNames) == 0 {
		if destHost == "" {
			logger.Warningf("AntiBan: inbound %d has no serverNames and no usable REALITY target, leaving it untouched", inbound.Id)
			return inbound, false, nil
		}
		serverNames = []string{destHost}
		filledServerNames = true
	}

	shortIds := antiBanStringSlice(reality["shortIds"])
	filledShortIds := false
	if len(shortIds) == 0 {
		shortId, err := antiBanRandomShortID()
		if err != nil {
			logger.Warningf("AntiBan: inbound %d cannot generate a shortId, leaving it untouched: %v", inbound.Id, err)
			return inbound, false, nil
		}
		shortIds = []string{shortId}
		filledShortIds = true
	}

	if destHost != "" && antiBanIsSharedScanTarget(destHost) {
		logger.Warningf("AntiBan: inbound %d uses the shared default REALITY target %q, pick a target from your own provider so the SNI is not a group fingerprint", inbound.Id, destHost)
	}

	settings := map[string]any{}
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		logger.Warningf("AntiBan: inbound %d has malformed client settings, leaving it untouched: %v", inbound.Id, err)
		return inbound, false, nil
	}
	flowChanged := false
	if !inbound.DisableFlow {
		if clients, ok := settings["clients"].([]any); ok {
			for _, entry := range clients {
				client, ok := entry.(map[string]any)
				if !ok {
					continue
				}
				if flow, _ := client["flow"].(string); flow == "" {
					client["flow"] = antiBanVisionFlow
					flowChanged = true
				}
			}
		}
	}

	if !flowChanged && !filledServerNames && !filledShortIds {
		return inbound, false, nil
	}

	hardened := *inbound
	if filledServerNames || filledShortIds {
		newReality := make(map[string]any, len(reality)+2)
		for key, value := range reality {
			newReality[key] = value
		}
		newReality["serverNames"] = serverNames
		newReality["shortIds"] = shortIds
		stream["realitySettings"] = newReality
		encoded, err := json.Marshal(stream)
		if err != nil {
			logger.Warningf("AntiBan: inbound %d cannot be re-encoded, leaving it untouched: %v", inbound.Id, err)
			return inbound, false, nil
		}
		hardened.StreamSettings = string(encoded)
	}
	if flowChanged {
		encoded, err := json.Marshal(settings)
		if err != nil {
			logger.Warningf("AntiBan: inbound %d cannot be re-encoded, leaving it untouched: %v", inbound.Id, err)
			return inbound, false, nil
		}
		hardened.Settings = string(encoded)
	}
	return &hardened, true, nil
}

// antiBanStringSlice reads a JSON array of strings, tolerating both the
// []any shape produced by encoding/json and a typed []string.
func antiBanStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, entry := range typed {
			if text, ok := entry.(string); ok && text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

// antiBanTargetHost extracts the host of the REALITY target (dest, or its
// target alias) and returns an empty string when it cannot be trusted.
func antiBanTargetHost(reality map[string]any) string {
	raw, _ := reality["dest"].(string)
	if strings.TrimSpace(raw) == "" {
		raw, _ = reality["target"].(string)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	host := raw
	if splitHost, port, err := net.SplitHostPort(raw); err == nil {
		number, convErr := strconv.Atoi(port)
		if convErr != nil || number < 1 || number > 65535 {
			return ""
		}
		host = splitHost
	}
	host = strings.TrimSpace(host)
	if host == "" || !antiBanValidHost(host) {
		return ""
	}
	return host
}

// antiBanValidHost accepts the shape of a DNS name (optionally a wildcard)
// and rejects anything that cannot be a real SNI.
func antiBanValidHost(host string) bool {
	for _, char := range host {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '-' || char == '.' || char == '_' || char == '*':
		default:
			return false
		}
	}
	return true
}

// antiBanIsSharedScanTarget reports whether the target host is one of the
// shipped default candidates. Thousands of panels use them, which makes the
// SNI itself a group fingerprint.
func antiBanIsSharedScanTarget(host string) bool {
	for _, candidate := range defaultRealityScanCandidates {
		candidateHost, _, err := net.SplitHostPort(candidate)
		if err != nil {
			candidateHost = candidate
		}
		if strings.EqualFold(candidateHost, host) {
			return true
		}
	}
	return false
}

// antiBanRandomShortID returns a random 8 character lowercase hex shortId.
func antiBanRandomShortID() (string, error) {
	buf := make([]byte, antiBanShortIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
