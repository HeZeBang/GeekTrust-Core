package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyShanghaiTechConfig(t *testing.T) {
	for _, body := range []string{
		"keystore = 'synthetic.keystore'\n",
		"keystore = 'synthetic.keystore'\ndevice_id = '0123456789ABCDEF0123456789ABCDEF'\nclient_type = 'client'\ngateways = ['gateway.example']\ndns = ['10.0.0.53']\n",
	} {
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if c.AppID != DefaultAppID || c.LoginDomain != DefaultLoginDomain || c.GatewayServerName() != "vpn.shanghaitech.edu.cn" {
			t.Fatalf("legacy defaults lost: app=%s login=%s", c.AppID, c.LoginDomain)
		}
		after, err := os.ReadFile(path)
		if err != nil || string(after) != body {
			t.Fatal("loading changed the original configuration")
		}
	}
}

func TestControllerDefaultsAreScoped(t *testing.T) {
	c := &Config{BaseURL: DefaultBaseURL, AppID: "custom-app", LoginDomain: "custom-domain"}
	c.ApplyControllerDefaults()
	if c.AppID != "custom-app" || c.LoginDomain != "custom-domain" {
		t.Fatal("explicit settings were overwritten")
	}
	for _, base := range []string{"https://vpn.ecnu.edu.cn", "https://vpn.shanghaitech.edu.cn.invalid"} {
		c = &Config{BaseURL: base}
		c.ApplyControllerDefaults()
		if c.AppID != "" || c.LoginDomain != "" || c.GatewayServerName() != "" {
			t.Fatal("ShanghaiTech defaults leaked to another controller")
		}
	}
}
