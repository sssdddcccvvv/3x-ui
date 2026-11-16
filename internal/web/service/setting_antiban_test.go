package service

import "testing"

func TestGetAntiBanEnableDefaultsFalse(t *testing.T) {
	setupSettingTestDB(t)
	s := &SettingService{}

	if got := s.GetAntiBanEnable(); got {
		t.Fatalf("missing setting = %t; want false", got)
	}
	settings, err := s.GetAllSetting()
	if err != nil {
		t.Fatal(err)
	}
	if settings.AntiBanEnable {
		t.Fatal("GetAllSetting returned true for a missing setting")
	}
}

func TestAntiBanEnableRoundTrip(t *testing.T) {
	setupSettingTestDB(t)
	s := &SettingService{}

	settings, err := s.GetAllSetting()
	if err != nil {
		t.Fatal(err)
	}
	settings.AntiBanEnable = true
	if err := s.UpdateAllSetting(settings, SecretClears{}); err != nil {
		t.Fatal(err)
	}
	if got := s.GetAntiBanEnable(); !got {
		t.Fatal("persisted setting = false; want true")
	}

	settings, err = s.GetAllSetting()
	if err != nil {
		t.Fatal(err)
	}
	if !settings.AntiBanEnable {
		t.Fatal("GetAllSetting lost the persisted true value")
	}

	settings.AntiBanEnable = false
	if err := s.UpdateAllSetting(settings, SecretClears{}); err != nil {
		t.Fatal(err)
	}
	if got := s.GetAntiBanEnable(); got {
		t.Fatal("persisted setting = true; want false")
	}
}
