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
