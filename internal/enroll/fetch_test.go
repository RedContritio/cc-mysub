package enroll

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchManifestSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/acme/cc-mysub/releases/download/v1.0.0/SHA256SUMS" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, validSums())
	}))
	defer srv.Close()
	t.Setenv("CC_MYSUB_RELEASE_BASE_URL", srv.URL)

	m, err := fetchManifest(srv.Client(), "acme/cc-mysub", "v1.0.0")
	if err != nil {
		t.Fatalf("fetchManifest: %v", err)
	}
	if len(m) != 4 {
		t.Errorf("want 4 platforms, got %d", len(m))
	}
}

func TestFetchManifestNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // 任何路径 404（模拟 typo'd tag）
	}))
	defer srv.Close()
	t.Setenv("CC_MYSUB_RELEASE_BASE_URL", srv.URL)

	_, err := fetchManifest(srv.Client(), "acme/cc-mysub", "vnope")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
	// 须是清晰的「not found」错误，而非下游「missing platform」误报。
	if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("error should surface release-not-found, got: %v", err)
	}
}

func TestFetchManifestEmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 200 但空 body → 下游 ParseManifest 应报缺平台
	}))
	defer srv.Close()
	t.Setenv("CC_MYSUB_RELEASE_BASE_URL", srv.URL)

	if _, err := fetchManifest(srv.Client(), "acme/cc-mysub", "v1.0.0"); err == nil {
		t.Fatal("expected error for empty SHA256SUMS body, got nil")
	}
}

// TestReleaseBaseURLFallback 直接覆盖 releaseBaseURL 的默认回退分支(env 空 → github.com),
// 该分支被其余测试的 t.Setenv 注入旁路、无直接覆盖。一并钉死 releaseDownloadBase 的完整拼接形态。
func TestReleaseBaseURLFallback(t *testing.T) {
	t.Setenv("CC_MYSUB_RELEASE_BASE_URL", "") // 显式置空 → 走默认
	if got := releaseBaseURL(); got != "https://github.com" {
		t.Errorf("releaseBaseURL() default = %q, want https://github.com", got)
	}
	if got := releaseDownloadBase("owner/repo", "v1"); got != "https://github.com/owner/repo/releases/download/v1" {
		t.Errorf("releaseDownloadBase = %q, want https://github.com/owner/repo/releases/download/v1", got)
	}
}
