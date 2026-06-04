package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

func ExtractToken(r *http.Request) string {
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimSpace(a[len("Bearer "):])
	}
	return strings.TrimSpace(r.Header.Get("X-Api-Key"))
}

func HashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}
