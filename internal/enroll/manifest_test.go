package enroll

import (
	"strings"
	"testing"
)

// validSums 是一份合法的 4 平台 SHA256SUMS 文本，供本包多个测试复用
// （TestRunEndToEnd / rotate 测试也用它喂 httptest）。两空格分隔为 sha256sum 文本模式格式。
func validSums() string {
	return strings.Join([]string{
		strings.Repeat("a", 64) + "  cc-mysub-linux-amd64",
		strings.Repeat("b", 64) + "  cc-mysub-linux-arm64",
		strings.Repeat("c", 64) + "  cc-mysub-darwin-amd64",
		strings.Repeat("d", 64) + "  cc-mysub-darwin-arm64",
		"",
	}, "\n")
}

func TestParseManifestValid(t *testing.T) {
	m, err := ParseManifest(validSums())
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if len(m) != 4 {
		t.Fatalf("want 4 platforms, got %d: %v", len(m), m)
	}
	if m["darwin-arm64"] != strings.Repeat("d", 64) {
		t.Errorf("darwin-arm64 hash = %q", m["darwin-arm64"])
	}
}

func TestParseManifestIgnoresForeignAssets(t *testing.T) {
	text := validSums() +
		strings.Repeat("e", 64) + "  cc-mysub-windows-amd64\n" +
		strings.Repeat("f", 64) + "  cc-mysub-darwin-arm64.minisig\n" +
		strings.Repeat("9", 40) + "  SHA256SUMS\n" + // 自条目（hash 长度异常也应被忽略，因 filename 不匹配）
		"\n"
	m, err := ParseManifest(text)
	if err != nil {
		t.Fatalf("ParseManifest with foreign assets: %v", err)
	}
	if len(m) != 4 {
		t.Errorf("foreign assets not ignored; want 4 keys got %d: %v", len(m), m)
	}
}

func TestParseManifestBinaryModeStar(t *testing.T) {
	// sha256sum 二进制模式 filename 带 '*' 前缀，须容错。
	text := strings.Join([]string{
		strings.Repeat("a", 64) + " *cc-mysub-linux-amd64",
		strings.Repeat("b", 64) + " *cc-mysub-linux-arm64",
		strings.Repeat("c", 64) + " *cc-mysub-darwin-amd64",
		strings.Repeat("d", 64) + " *cc-mysub-darwin-arm64",
		"",
	}, "\n")
	m, err := ParseManifest(text)
	if err != nil {
		t.Fatalf("ParseManifest binary-mode: %v", err)
	}
	if len(m) != 4 {
		t.Errorf("binary-mode '*' prefix not stripped; got %d keys: %v", len(m), m)
	}
}

func TestParseManifestMissingPlatform(t *testing.T) {
	text := strings.Join([]string{
		strings.Repeat("a", 64) + "  cc-mysub-linux-amd64",
		strings.Repeat("b", 64) + "  cc-mysub-linux-arm64",
		strings.Repeat("c", 64) + "  cc-mysub-darwin-amd64",
		// darwin-arm64 缺失
		"",
	}, "\n")
	if _, err := ParseManifest(text); err == nil {
		t.Fatal("expected error for missing platform, got nil")
	}
}

func TestParseManifestNonHexHash(t *testing.T) {
	text := strings.Join([]string{
		"xyz  cc-mysub-linux-amd64", // 匹配平台但 hash 非 64-hex
		strings.Repeat("b", 64) + "  cc-mysub-linux-arm64",
		strings.Repeat("c", 64) + "  cc-mysub-darwin-amd64",
		strings.Repeat("d", 64) + "  cc-mysub-darwin-arm64",
		"",
	}, "\n")
	if _, err := ParseManifest(text); err == nil {
		t.Fatal("expected error for non-64-hex hash, got nil")
	}
}

func TestParseManifestDuplicatePlatform(t *testing.T) {
	text := validSums() + strings.Repeat("e", 64) + "  cc-mysub-linux-amd64\n"
	if _, err := ParseManifest(text); err == nil {
		t.Fatal("expected error for duplicate platform, got nil")
	}
}

func TestParseManifestEmpty(t *testing.T) {
	if _, err := ParseManifest(""); err == nil {
		t.Fatal("expected error for empty manifest, got nil")
	}
}

// TestParseManifestRejectsSpacedForeignFilename 验证含内部空白的 foreign 行不被按「末 token」错分类。
// 构造：darwin-arm64 真行缺失，但有一行 `<hash>  evil cc-mysub-darwin-arm64`（3 字段，带空格）。
// 严格化后该行（!=2 字段）被跳过 → darwin-arm64 缺失 → fail-closed 报错，绝不静默吸收 foreign hash。
func TestParseManifestRejectsSpacedForeignFilename(t *testing.T) {
	text := strings.Join([]string{
		strings.Repeat("a", 64) + "  cc-mysub-linux-amd64",
		strings.Repeat("b", 64) + "  cc-mysub-linux-arm64",
		strings.Repeat("c", 64) + "  cc-mysub-darwin-amd64",
		strings.Repeat("e", 64) + "  evil cc-mysub-darwin-arm64", // 末 token 命中平台但带空格 → 须跳过
		"",
	}, "\n")
	if _, err := ParseManifest(text); err == nil {
		t.Fatal("spaced foreign line must not be classified as darwin-arm64; expected missing-platform error")
	}
}

// TestParseManifestHashLengthBoundary 验证 hash 长度严格 64：63/65 位均报错（hexRE 长度契约）。
func TestParseManifestHashLengthBoundary(t *testing.T) {
	for _, h := range []string{strings.Repeat("a", 63), strings.Repeat("a", 65)} {
		text := strings.Join([]string{
			h + "  cc-mysub-linux-amd64",
			strings.Repeat("b", 64) + "  cc-mysub-linux-arm64",
			strings.Repeat("c", 64) + "  cc-mysub-darwin-amd64",
			strings.Repeat("d", 64) + "  cc-mysub-darwin-arm64",
			"",
		}, "\n")
		if _, err := ParseManifest(text); err == nil {
			t.Errorf("expected error for %d-char hash, got nil", len(h))
		}
	}
}

// TestParseManifestUppercaseHashRejected 验证 64 位大写 hex（字符集非法）被拒——契约要求小写、不静默归一化。
func TestParseManifestUppercaseHashRejected(t *testing.T) {
	text := strings.Join([]string{
		strings.Repeat("A", 64) + "  cc-mysub-linux-amd64",
		strings.Repeat("b", 64) + "  cc-mysub-linux-arm64",
		strings.Repeat("c", 64) + "  cc-mysub-darwin-amd64",
		strings.Repeat("d", 64) + "  cc-mysub-darwin-arm64",
		"",
	}, "\n")
	if _, err := ParseManifest(text); err == nil {
		t.Fatal("expected error for uppercase hash (lowercase-only contract), got nil")
	}
}
