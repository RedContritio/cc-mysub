package auth

import (
	"net/http"
	"testing"
)

func TestExtractTokenBearer(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer abc123")
	if got := ExtractToken(r); got != "abc123" {
		t.Errorf("got %q", got)
	}
}

func TestExtractTokenXApiKeyFallback(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Api-Key", "key456")
	if got := ExtractToken(r); got != "key456" {
		t.Errorf("got %q", got)
	}
}

func TestHashTokenStable(t *testing.T) {
	// echo -n "abc123" | shasum -a 256
	want := "6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090"
	if got := HashToken("abc123"); got != want {
		t.Errorf("HashToken = %q want %q", got, want)
	}
}

func TestCertFingerprint_LowercaseHex64(t *testing.T) {
	fp := CertFingerprint([]byte("hello"))
	if len(fp) != 64 {
		t.Fatalf("len=%d want 64", len(fp))
	}
	for _, c := range fp {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			t.Fatalf("non-lowercase-hex byte %q in %s", c, fp)
		}
	}
	// sha256("hello")
	if fp != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("fp=%s", fp)
	}
}

func TestCanonicalFingerprint(t *testing.T) {
	good := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	for _, bad := range []string{"", "abcd", good[:63], good + "0", "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824"} {
		if CanonicalFingerprint(bad) {
			t.Errorf("CanonicalFingerprint(%q)=true want false", bad)
		}
	}
	if !CanonicalFingerprint(good) {
		t.Errorf("CanonicalFingerprint(good)=false")
	}
}

func TestHasInboundCredential(t *testing.T) {
	cases := []struct {
		name, authz, xapi string
		want              bool
	}{
		{"none", "", "", false},
		{"bearer", "Bearer abc", "", true},
		{"bearer-empty", "Bearer ", "", false},
		{"xapikey", "", "sk-xxx", true},
		{"both", "Bearer abc", "sk-xxx", true},
		{"non-bearer-authz", "Basic abc", "", false},
	}
	for _, c := range cases {
		r, _ := http.NewRequest("POST", "/", nil)
		if c.authz != "" {
			r.Header.Set("Authorization", c.authz)
		}
		if c.xapi != "" {
			r.Header.Set("X-Api-Key", c.xapi)
		}
		if got := HasInboundCredential(r); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
