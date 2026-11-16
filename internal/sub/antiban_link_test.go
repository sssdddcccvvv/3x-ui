package sub

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/dbtest"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

// AntiBan link-generation tests.
//
// The panel's AntiBan toggle must make a generated VLESS share link look like
// a REALITY client that a browser would produce: the Vision flow is present,
// the SNI and the short id come from the REALITY target, and nothing changes
// while the toggle is off.
//
// The first test runs without a database on purpose: the link path asks the
// settings service for the toggle, and the settings service must answer "off"
// instead of panicking when no database is initialized yet.

const antiBanTestClient = `{"id":"11111111-2222-4333-8444-555555555555","email":"user"}`

// antiBanTestInbound builds a VLESS inbound with one client "user".
func antiBanTestInbound(stream string) *model.Inbound {
	return &model.Inbound{
		Listen:         "203.0.113.1",
		Port:           443,
		Protocol:       model.VLESS,
		Remark:         "antiban",
		Settings:       `{"clients":[` + antiBanTestClient + `],"decryption":"none","encryption":"none"}`,
		StreamSettings: stream,
	}
}

// antiBanSetToggle writes the antibanEnable setting.
func antiBanSetToggle(t *testing.T, enabled bool) {
	t.Helper()
	value := "false"
	if enabled {
		value = "true"
	}
	if err := database.GetDB().Create(&model.Setting{Key: "antibanEnable", Value: value}).Error; err != nil {
		t.Fatalf("cannot store the antibanEnable setting: %v", err)
	}
}

const antiBanRealityStream = `{
	"network":"tcp","security":"reality",
	"tcpSettings":{"header":{"type":"none"}},
	"realitySettings":{"serverNames":["reality.example.com"],"shortIds":["ab12cd"],"settings":{"publicKey":"PBKvalue","fingerprint":"chrome"}}
}`

// Without a database the settings service cannot read the toggle; the link
// path must not panic and must behave as if the toggle were off.
func TestAntiBanVlessLinkWithoutDatabaseDoesNotPanic(t *testing.T) {
	s := &SubService{}
	got := s.genVlessLink(antiBanTestInbound(antiBanRealityStream), "user")
	if got == "" {
		t.Fatal("expected a share link, got an empty string")
	}
	if strings.Contains(got, "flow=") {
		t.Fatalf("the toggle must read as off without a database, got %q", got)
	}
}

// With the toggle on, a REALITY link must carry the Vision flow.
func TestAntiBanVlessLinkForcesVisionFlow(t *testing.T) {
	dbtest.InitDB(t, filepath.Join(t.TempDir(), "x-ui.db"))
	antiBanSetToggle(t, true)

	s := &SubService{}
	got := s.genVlessLink(antiBanTestInbound(antiBanRealityStream), "user")
	if !strings.Contains(got, "flow=xtls-rprx-vision") {
		t.Fatalf("expected flow=xtls-rprx-vision in %q", got)
	}
}

// With the toggle off the link must stay exactly as it was before.
func TestAntiBanVlessLinkToggleOffHasNoFlow(t *testing.T) {
	dbtest.InitDB(t, filepath.Join(t.TempDir(), "x-ui.db"))
	antiBanSetToggle(t, false)

	s := &SubService{}
	got := s.genVlessLink(antiBanTestInbound(antiBanRealityStream), "user")
	if strings.Contains(got, "flow=") {
		t.Fatalf("the toggle is off, the link must not carry a flow: %q", got)
	}
	if !strings.Contains(got, "sni=reality.example.com") {
		t.Fatalf("expected the configured SNI in %q", got)
	}
}

// An inbound saved before the toggle existed has no serverNames and no
// shortIds; the link must carry an SNI derived from the REALITY target and a
// random short id.
func TestAntiBanVlessLinkDerivesSniAndShortId(t *testing.T) {
	dbtest.InitDB(t, filepath.Join(t.TempDir(), "x-ui.db"))
	antiBanSetToggle(t, true)

	stream := `{
		"network":"tcp","security":"reality",
		"tcpSettings":{"header":{"type":"none"}},
		"realitySettings":{"dest":"www.example.com:443","settings":{"publicKey":"PBKvalue","fingerprint":"chrome"}}
	}`
	s := &SubService{}
	got := s.genVlessLink(antiBanTestInbound(stream), "user")
	if !strings.Contains(got, "sni=www.example.com") {
		t.Fatalf("expected sni=www.example.com in %q", got)
	}
	if !regexp.MustCompile(`sid=[0-9a-f]{8}`).MatchString(got) {
		t.Fatalf("expected an 8 character hex short id in %q", got)
	}
}

// Plain TLS is not a REALITY handshake: the toggle must not add a flow to it.
func TestAntiBanVlessLinkPlainTlsHasNoFlow(t *testing.T) {
	dbtest.InitDB(t, filepath.Join(t.TempDir(), "x-ui.db"))
	antiBanSetToggle(t, true)

	stream := `{
		"network":"tcp","security":"tls",
		"tcpSettings":{"header":{"type":"none"}},
		"tlsSettings":{"serverName":"www.example.com","alpn":["h2"],"settings":{"fingerprint":"chrome"}}
	}`
	s := &SubService{}
	got := s.genVlessLink(antiBanTestInbound(stream), "user")
	if strings.Contains(got, "flow=") {
		t.Fatalf("a plain TLS inbound must not get a flow: %q", got)
	}
}
