package repo

import "testing"

func TestNormalizeDockerHost(t *testing.T) {
	for in, want := range map[string]string{
		"hub.entrepot.example.com": "hub.entrepot.example.com",
		" Hub.Example.COM. ":       "hub.example.com",
		"localhost":                "localhost",
		"a-b.c1.example":           "a-b.c1.example",
	} {
		got, err := NormalizeDockerHost(in)
		if err != nil || got != want {
			t.Errorf("NormalizeDockerHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "https://hub.example.com", "hub.example.com:5000", "hub.example.com/v2",
		"10.0.0.1", "::1", "-hub.example.com", "hub-.example.com", "hub_x.example.com", "hub..example.com",
		"user@hub.example.com", string(make([]byte, 254))} {
		if got, err := NormalizeDockerHost(bad); err == nil {
			t.Errorf("NormalizeDockerHost(%q) = %q, want an error", bad, got)
		}
	}
}
