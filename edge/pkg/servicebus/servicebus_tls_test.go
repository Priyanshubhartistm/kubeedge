/*
Copyright 2026 The KubeEdge Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package servicebus

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crypto/rand"
	"crypto/rsa"
)

// generateSelfSignedCert writes a self-signed TLS certificate and private key
// to the given directory and returns the paths to both files.
func generateSelfSignedCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "servicebus-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")

	cf, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("failed to create cert file: %v", err)
	}
	defer cf.Close()
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("failed to PEM-encode cert: %v", err)
	}

	kf, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	defer kf.Close()
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: privDER}); err != nil {
		t.Fatalf("failed to PEM-encode key: %v", err)
	}

	return certFile, keyFile
}

// TestBuildTLSConfigNoPaths verifies that buildTLSConfig returns nil when
// both certFile and keyFile are empty strings (TLS disabled).
func TestBuildTLSConfigNoPaths(t *testing.T) {
	cfg, err := buildTLSConfig("", "", "")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if cfg != nil {
		t.Error("expected nil TLS config when cert/key paths are empty")
	}
}

// TestBuildTLSConfigValidCert verifies that a valid cert/key pair produces a
// non-nil *tls.Config with the expected settings.
func TestBuildTLSConfigValidCert(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateSelfSignedCert(t, dir)

	cfg, err := buildTLSConfig(certFile, keyFile, "")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion: got %v, want TLS 1.2", cfg.MinVersion)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth: got %v, want NoClientCert", cfg.ClientAuth)
	}
	if cfg.GetCertificate == nil {
		t.Error("GetCertificate callback must not be nil")
	}
}

// TestBuildTLSConfigGetCertificateReloads verifies that the GetCertificate
// callback re-reads the cert from disk, enabling certificate rotation.
func TestBuildTLSConfigGetCertificateReloads(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateSelfSignedCert(t, dir)

	cfg, err := buildTLSConfig(certFile, keyFile, "")
	if err != nil || cfg == nil {
		t.Fatalf("buildTLSConfig: %v, cfg=%v", err, cfg)
	}

	// Calling GetCertificate must return a valid certificate.
	cert, err := cfg.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate returned nil cert")
	}
}

// TestBuildTLSConfigInvalidCertPaths verifies that buildTLSConfig returns an
// error (instead of calling klog.Fatalf) when the cert/key files do not exist.
func TestBuildTLSConfigInvalidCertPaths(t *testing.T) {
	cfg, err := buildTLSConfig("/nonexistent/cert.crt", "/nonexistent/key.key", "")
	if err == nil {
		t.Error("expected an error for missing cert files, got nil")
	}
	if cfg != nil {
		t.Error("expected nil TLS config on error")
	}
}

// TestBuildTLSConfigWithValidCA verifies that a valid CA file results in a
// non-nil ClientCAs pool and that ClientAuth remains NoClientCert.
func TestBuildTLSConfigWithValidCA(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateSelfSignedCert(t, dir)

	// The self-signed cert itself is a valid CA PEM — reuse it as CA file.
	caFile := filepath.Join(dir, "ca.crt")
	if err := copyFile(t, certFile, caFile); err != nil {
		t.Fatalf("copyFile: %v", err)
	}

	cfg, err := buildTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if cfg.ClientCAs == nil {
		t.Error("expected non-nil ClientCAs pool when a valid CA file is provided")
	}
	// ClientAuth must remain NoClientCert even with a CA loaded so that
	// local applications without client certs can still connect.
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth: got %v, want NoClientCert", cfg.ClientAuth)
	}
}

// TestBuildTLSConfigInvalidCAContent verifies that a CA file containing no
// valid PEM certificate blocks does NOT panic or set ClientCAs, and returns
// a non-nil config (server-only TLS still works).
func TestBuildTLSConfigInvalidCAContent(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateSelfSignedCert(t, dir)

	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, []byte("not-a-pem-certificate"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// AppendCertsFromPEM returns false → no ClientCAs, but no crash.
	cfg, err := buildTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil TLS config (server-only TLS should still work)")
	}
	if cfg.ClientCAs != nil {
		t.Error("ClientCAs must be nil when the CA PEM is invalid")
	}
}

// TestBuildTLSConfigMissingCAFile verifies that a missing CA file is treated
// as a warning (not a fatal error) and server-only TLS is still configured.
func TestBuildTLSConfigMissingCAFile(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateSelfSignedCert(t, dir)

	cfg, err := buildTLSConfig(certFile, keyFile, "/nonexistent/ca.crt")
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil TLS config (server-only TLS should still work)")
	}
	if cfg.ClientCAs != nil {
		t.Error("ClientCAs must be nil when the CA file cannot be read")
	}
}

// TestBuildBasicHandlerTLSIntegration starts an httptest.Server using the TLS
// config produced by buildTLSConfig and verifies that a TLS client can
// connect and receive a response.
func TestBuildBasicHandlerTLSIntegration(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateSelfSignedCert(t, dir)

	tlsCfg, err := buildTLSConfig(certFile, keyFile, "")
	if err != nil || tlsCfg == nil {
		t.Fatalf("buildTLSConfig: %v, cfg=%v", err, tlsCfg)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewUnstartedServer(h)
	srv.TLS = tlsCfg
	srv.StartTLS()
	defer srv.Close()

	// httptest.Client() already trusts the test server's certificate.
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("GET %s: %v", srv.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}

// copyFile is a test helper to copy a file.
func copyFile(t *testing.T, src, dst string) error {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0600)
}
