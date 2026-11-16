package service

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

// enableAntiBan turns the panel-wide AntiBan toggle on for a test.
func enableAntiBan(t *testing.T) {
	t.Helper()
	setupSettingTestDB(t)
	s := &SettingService{}
	if err := s.setBool("antibanEnable", true); err != nil {
		t.Fatalf("enable antiban: %v", err)
	}
	if !s.GetAntiBanEnable() {
		t.Fatal("antibanEnable did not persist")
	}
}

func antibanInbound(settings, stream string) *model.Inbound {
	return &model.Inbound{
		Protocol:       "vless",
		Port:           443,
		Settings:       settings,
		StreamSettings: stream,
	}
}

func antibanRealityStream(dest string, serverNames, shortIds []string) string {
	raw := map[string]any{
		"network":  "tcp",
		"security": "reality",
		"realitySettings": map[string]any{
			"dest":        dest,
			"serverNames": serverNames,
			"shortIds":    shortIds,
			"settings": map[string]any{
				"publicKey":   "PBK",
				"fingerprint": "chrome",
			},
		},
	}
	out, _ := json.Marshal(raw)
	return string(out)
}

func clientFlows(t *testing.T, settings string) []string {
	t.Helper()
	var parsed struct {
		Clients []struct {
			Flow string `json:"flow"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(settings), &parsed); err != nil {
		t.Fatalf("client settings json: %v", err)
	}
	flows := make([]string, 0, len(parsed.Clients))
	for _, c := range parsed.Clients {
		flows = append(flows, c.Flow)
	}
	return flows
}

func realityShortIds(t *testing.T, stream string) []string {
	t.Helper()
	var parsed struct {
		RealitySettings struct {
			ShortIds []string `json:"shortIds"`
		} `json:"realitySettings"`
	}
	if err := json.Unmarshal([]byte(stream), &parsed); err != nil {
		t.Fatalf("stream json: %v", err)
	}
	return parsed.RealitySettings.ShortIds
}

func realityServerNames(t *testing.T, stream string) []string {
	t.Helper()
	var parsed struct {
		RealitySettings struct {
			ServerNames []string `json:"serverNames"`
		} `json:"realitySettings"`
	}
	if err := json.Unmarshal([]byte(stream), &parsed); err != nil {
		t.Fatalf("stream json: %v", err)
	}
	return parsed.RealitySettings.ServerNames
}

func TestApplyAntiBanForcesVisionFlow(t *testing.T) {
	enableAntiBan(t)
	in := antibanInbound(`{"clients":[{"id":"uuid-1","email":"a@b.c","flow":""}]}`, antibanRealityStream("www.example.com:443", []string{"www.example.com"}, []string{"ab12cd34"}))

	out, changed, err := ApplyAntiBan(in)
	if err != nil {
		t.Fatalf("ApplyAntiBan: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	flows := clientFlows(t, out.Settings)
	if len(flows) != 1 || flows[0] != "xtls-rprx-vision" {
		t.Fatalf("client flows = %v, want [xtls-rprx-vision]", flows)
	}
}

func TestApplyAntiBanRespectsDisableFlow(t *testing.T) {
	enableAntiBan(t)
	in := antibanInbound(`{"clients":[{"id":"uuid-1","email":"a@b.c","flow":""}]}`, antibanRealityStream("www.example.com:443", []string{"www.example.com"}, []string{"ab12cd34"}))
	in.DisableFlow = true

	out, changed, err := ApplyAntiBan(in)
	if err != nil {
		t.Fatalf("ApplyAntiBan: %v", err)
	}
	if changed {
		t.Fatal("changed = true, want false for a DisableFlow inbound")
	}
	flows := clientFlows(t, out.Settings)
	if len(flows) != 1 || flows[0] != "" {
		t.Fatalf("client flows = %v, want [\"\"]", flows)
	}
}

func TestApplyAntiBanIgnoresNonRealityAndOtherProtocols(t *testing.T) {
	enableAntiBan(t)

	tlsInbound := antibanInbound(`{"clients":[{"id":"uuid-1","email":"a@b.c","flow":""}]}`, `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"www.example.com"}}`)
	out, changed, err := ApplyAntiBan(tlsInbound)
	if err != nil {
		t.Fatalf("ApplyAntiBan(tls): %v", err)
	}
	if changed {
		t.Fatal("plain TLS inbound was changed")
	}
	if flows := clientFlows(t, out.Settings); len(flows) != 1 || flows[0] != "" {
		t.Fatalf("plain TLS client flows = %v, want [\"\"]", flows)
	}

	vmessInbound := antibanInbound(`{"clients":[{"id":"uuid-1","email":"a@b.c"}]}`, antibanRealityStream("www.example.com:443", []string{"www.example.com"}, []string{"ab12cd34"}))
	vmessInbound.Protocol = "vmess"
	out, changed, err = ApplyAntiBan(vmessInbound)
	if err != nil {
		t.Fatalf("ApplyAntiBan(vmess): %v", err)
	}
	if changed {
		t.Fatal("vmess inbound was changed")
	}
}

func TestApplyAntiBanFillsShortIdsAndServerNames(t *testing.T) {
	enableAntiBan(t)
	in := antibanInbound(`{"clients":[{"id":"uuid-1","email":"a@b.c","flow":"xtls-rprx-vision"}]}`, antibanRealityStream("www.example.com:443", nil, nil))

	out, changed, err := ApplyAntiBan(in)
	if err != nil {
		t.Fatalf("ApplyAntiBan: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}

	ids := realityShortIds(t, out.StreamSettings)
	if len(ids) != 1 {
		t.Fatalf("shortIds = %v, want exactly one entry", ids)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(ids[0]) {
		t.Fatalf("shortId = %q, want 8 lowercase hex characters", ids[0])
	}

	names := realityServerNames(t, out.StreamSettings)
	if len(names) != 1 || names[0] != "www.example.com" {
		t.Fatalf("serverNames = %v, want [www.example.com]", names)
	}
}

func TestApplyAntiBanToggleOffLeavesInboundUntouched(t *testing.T) {
	setupSettingTestDB(t)
	in := antibanInbound(`{"clients":[{"id":"uuid-1","email":"a@b.c","flow":""}]}`, antibanRealityStream("www.example.com:443", nil, nil))

	out, changed, err := ApplyAntiBan(in)
	if err != nil {
		t.Fatalf("ApplyAntiBan: %v", err)
	}
	if changed {
		t.Fatal("changed = true, want false with the toggle off")
	}
	if out != in {
		t.Fatal("returned a clone with the toggle off")
	}
	if out.Settings != in.Settings || out.StreamSettings != in.StreamSettings {
		t.Fatal("inbound bytes changed with the toggle off")
	}
}

func TestApplyAntiBanMalformedStreamJSON(t *testing.T) {
	enableAntiBan(t)
	in := antibanInbound(`{"clients":[{"id":"uuid-1","email":"a@b.c","flow":""}]}`, `{"network":"tcp","security":"reality"`)

	out, changed, err := ApplyAntiBan(in)
	if err != nil {
		t.Fatalf("ApplyAntiBan returned an error for malformed JSON: %v", err)
	}
	if changed {
		t.Fatal("changed = true, want false for malformed stream settings")
	}
	if out != in {
		t.Fatal("returned a clone for malformed stream settings")
	}
}

func TestApplyAntiBanSkipsInboundWithoutDerivableServerName(t *testing.T) {
	enableAntiBan(t)
	in := antibanInbound(`{"clients":[{"id":"uuid-1","email":"a@b.c","flow":""}]}`, `{"network":"tcp","security":"reality","realitySettings":{"dest":"not a host:port","serverNames":[],"shortIds":[]}}`)

	out, changed, err := ApplyAntiBan(in)
	if err != nil {
		t.Fatalf("ApplyAntiBan returned an error for an underivable server name: %v", err)
	}
	if changed {
		t.Fatal("changed = true, want false when no server name can be derived")
	}
	if out != in {
		t.Fatal("returned a clone when no server name can be derived")
	}
}
