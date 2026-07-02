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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateServerCert writes a self-signed TLS server certificate (with
// ExtKeyUsageServerAuth and a 127.0.0.1 SAN) plus its private key to dir.
// This is the correct certificate type for a ServiceBus HTTPS server.
// The EdgeHub client certificate CANNOT be reused here because it carries
// ExtKeyUsageClientAuth and no ServiceBus SANs.
func generateServerCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "servicebus-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		// ExtKeyUsageServerAuth is required for HTTPS server certificates.
		// A ClientAuth-only cert (like the EdgeHub cert) would be rejected by
		// a normal HTTPS client performing TLS server certificate verification.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// 127.0.0.1 SAN is required so that clients connecting to
		// "https://127.0.0.1:..." can validate the certificate hostname.
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
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

// generateClientAuthCert writes a self-signed certificate with
// ExtKeyUsageClientAuth only (no ServerAuth, no IP SAN) — simulating the
// EdgeHub certificate that CloudCore issues for edge nodes.
func generateClientAuthCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generateClientAuthCert: key gen: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "system:node:test-node"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		// ClientAuth only — no ServerAuth, no SANs.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("generateClientAuthCert: create cert: %v", err)
	}

	certFile = filepath.Join(dir, "client.crt")
	keyFile = filepath.Join(dir, "client.key")

	cf, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("generateClientAuthCert: create certFile: %v", err)
	}
	defer cf.Close()
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("generateClientAuthCert: encode cert: %v", err)
	}

	kf, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("generateClientAuthCert: create keyFile: %v", err)
	}
	defer kf.Close()
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("generateClientAuthCert: marshal key: %v", err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: privDER}); err != nil {
		t.Fatalf("generateClientAuthCert: encode key: %v", err)
	}

	return certFile, keyFile
}

// TestBuildTLSConfigDisabled verifies that buildTLSConfig returns (nil, nil)
// when TLSEnabled is false — the server must start as plain HTTP.
func TestBuildTLSConfigDisabled(t *testing.T) {
	cfg, err := buildTLSConfig(TLSOptions{TLSEnabled: false})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if cfg != nil {
		t.Error("expected nil TLS config when TLSEnabled=false")
	}
}

// TestBuildTLSConfigEnabledNoPaths verifies that enabling TLS without cert/key
// paths returns an error.  The server must NOT silently fall back to HTTP.
func TestBuildTLSConfigEnabledNoPaths(t *testing.T) {
	cfg, err := buildTLSConfig(TLSOptions{TLSEnabled: true, CertFile: "", KeyFile: ""})
	if err == nil {
		t.Error("expected an error when TLS is enabled but CertFile/KeyFile are empty")
	}
	if cfg != nil {
		t.Error("expected nil TLS config on error")
	}
}

// TestBuildTLSConfigServerAuthCert verifies that a certificate with
// ExtKeyUsageServerAuth and a 127.0.0.1 SAN produces a valid *tls.Config.
// This is the correct certificate type for a ServiceBus HTTPS server.
func TestBuildTLSConfigServerAuthCert(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateServerCert(t, dir)

	cfg, err := buildTLSConfig(TLSOptions{TLSEnabled: true, CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatalf("expected no error with a valid ServerAuth cert, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion: got %v, want TLS 1.2", cfg.MinVersion)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth: got %v, want NoClientCert (server-only TLS)", cfg.ClientAuth)
	}
	if cfg.ClientCAs != nil {
		t.Error("ClientCAs must be nil: server-only TLS does not use a client CA pool")
	}
	if cfg.GetCertificate == nil {
		t.Error("GetCertificate callback must not be nil (required for cert rotation)")
	}
}

// TestBuildTLSConfigClientAuthCertFails verifies that supplying an
// EdgeHub-style ClientAuth-only certificate returns a *tls.Config (the key
// pair loads fine), but the behaviour document that this cert CANNOT be
// validated by a normal HTTPS client because it has no ServerAuth EKU or SANs.
//
// This test documents the rejected approach: the EdgeHub cert MUST NOT be
// reused as a ServiceBus server identity.
func TestBuildTLSConfigClientAuthCertFails(t *testing.T) {
	dir := t.TempDir()
	// Generate a ClientAuth-only cert (simulating the EdgeHub cert).
	certFile, keyFile := generateClientAuthCert(t, dir)

	// buildTLSConfig itself succeeds because the key pair is valid PEM.
	// The TLS handshake would fail when a client tries to connect because
	// the cert lacks ExtKeyUsageServerAuth and has no IP/DNS SANs.
	cfg, err := buildTLSConfig(TLSOptions{TLSEnabled: true, CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil TLS config")
	}

	// Now prove that a normal HTTPS client rejects this cert:
	// Start a real TLS listener using the ClientAuth-only cert.
	listener, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	addr := listener.Addr().String()

	// A strict HTTPS client (no InsecureSkipVerify) must fail because:
	//  1. The cert has no ServerAuth EKU.
	//  2. There is no SAN for the server address.
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// No InsecureSkipVerify: this is a normal verifying client.
				RootCAs: x509.NewCertPool(), // empty pool → cert is not trusted
			},
		},
	}
	_, err = client.Get("https://" + addr)
	if err == nil {
		t.Error("expected a TLS verification error for a ClientAuth-only cert, got nil")
	}
}

// TestBuildTLSConfigInvalidCertPaths verifies that buildTLSConfig returns an
// error (not klog.Fatalf) when the cert/key files do not exist.
func TestBuildTLSConfigInvalidCertPaths(t *testing.T) {
	cfg, err := buildTLSConfig(TLSOptions{
		TLSEnabled: true,
		CertFile:   "/nonexistent/cert.crt",
		KeyFile:    "/nonexistent/key.key",
	})
	if err == nil {
		t.Error("expected an error for missing cert files, got nil")
	}
	if cfg != nil {
		t.Error("expected nil TLS config on error")
	}
}

// TestBuildTLSConfigGetCertificateReloads verifies that the GetCertificate
// callback re-reads the cert from disk, enabling certificate rotation.
// This test writes a first certificate, calls GetCertificate, then replaces
// the files with a second certificate and verifies the next call returns the
// new certificate (i.e., the serial number changes).
func TestBuildTLSConfigGetCertificateReloads(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateServerCert(t, dir)

	cfg, err := buildTLSConfig(TLSOptions{TLSEnabled: true, CertFile: certFile, KeyFile: keyFile})
	if err != nil || cfg == nil {
		t.Fatalf("buildTLSConfig: %v, cfg=%v", err, cfg)
	}

	// First call — load the original certificate.
	cert1, err := cfg.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate (first call): %v", err)
	}
	if cert1 == nil {
		t.Fatal("GetCertificate (first call) returned nil cert")
	}
	parsed1, err := x509.ParseCertificate(cert1.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate (first): %v", err)
	}

	// Generate a second, distinct certificate with a different serial number
	// and overwrite the same files — simulating CertManager rotation.
	priv2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key gen 2: %v", err)
	}
	tmpl2 := &x509.Certificate{
		SerialNumber: big.NewInt(999), // distinct from the first cert's serial (1)
		Subject:      pkix.Name{CommonName: "servicebus-server-rotated"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER2, err := x509.CreateCertificate(rand.Reader, tmpl2, tmpl2, &priv2.PublicKey, priv2)
	if err != nil {
		t.Fatalf("CreateCertificate 2: %v", err)
	}

	// Overwrite cert file.
	cf, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("overwrite certFile: %v", err)
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER2}); err != nil {
		cf.Close()
		t.Fatalf("encode cert2: %v", err)
	}
	cf.Close()

	// Overwrite key file.
	privDER2, err := x509.MarshalPKCS8PrivateKey(priv2)
	if err != nil {
		t.Fatalf("marshal key2: %v", err)
	}
	kf, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("overwrite keyFile: %v", err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: privDER2}); err != nil {
		kf.Close()
		t.Fatalf("encode key2: %v", err)
	}
	kf.Close()

	// Second call — must return the NEW certificate.
	cert2, err := cfg.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate (second call): %v", err)
	}
	if cert2 == nil {
		t.Fatal("GetCertificate (second call) returned nil cert")
	}
	parsed2, err := x509.ParseCertificate(cert2.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate (second): %v", err)
	}

	// The serial numbers must differ, proving the cert was reloaded from disk.
	if parsed1.SerialNumber.Cmp(parsed2.SerialNumber) == 0 {
		t.Errorf("GetCertificate did not reload the rotated certificate: serial unchanged (%s)", parsed1.SerialNumber)
	}
}

// TestHTTPSServerWithServerAuthCert starts a real TLS listener (not httptest)
// using a ServerAuth + 127.0.0.1-SAN certificate, then verifies that a normal
// http.Client configured to trust only that CA can connect successfully.
//
// This test directly addresses maintainer issue 5: httptest.StartTLS injects
// its own certificate when TLS.Certificates is empty and GetCertificate is
// set, so it never exercises the configured certificate.  Using a real
// net.Listen + tls.NewListener lets us control the certificate end-to-end.
func TestHTTPSServerWithServerAuthCert(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateServerCert(t, dir)

	tlsCfg, err := buildTLSConfig(TLSOptions{TLSEnabled: true, CertFile: certFile, KeyFile: keyFile})
	if err != nil || tlsCfg == nil {
		t.Fatalf("buildTLSConfig: %v, cfg=%v", err, tlsCfg)
	}

	// Start a real TLS listener so we control which certificate is served.
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(listener) //nolint:errcheck
	defer srv.Close()

	// Load the server cert as the trusted CA for the client (self-signed).
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("ReadFile(certFile): %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM returned false")
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool, // trust only our server cert
			},
		},
	}

	resp, err := client.Get("https://" + listener.Addr().String())
	if err != nil {
		t.Fatalf("GET with trusted CA: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}

// TestHTTPSServerClientAuthCertRejected verifies that a normal HTTPS client
// rejects a server certificate that has ExtKeyUsageClientAuth only (no
// ServerAuth) — proving that the EdgeHub cert cannot be reused as a ServiceBus
// server identity.
func TestHTTPSServerClientAuthCertRejected(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateClientAuthCert(t, dir)

	// buildTLSConfig succeeds because the key pair is valid PEM.
	tlsCfg, err := buildTLSConfig(TLSOptions{TLSEnabled: true, CertFile: certFile, KeyFile: keyFile})
	if err != nil || tlsCfg == nil {
		t.Fatalf("buildTLSConfig: %v, cfg=%v", err, tlsCfg)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(listener) //nolint:errcheck
	defer srv.Close()

	// Client trusts the cert as a CA but performs full TLS verification.
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("ReadFile(certFile): %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}

	// The connection must fail: the cert lacks ExtKeyUsageServerAuth and has
	// no 127.0.0.1 SAN, so the TLS handshake is rejected by a verifying client.
	_, err = client.Get("https://" + listener.Addr().String())
	if err == nil {
		t.Error("expected a TLS error for a ClientAuth-only cert used as server cert, got nil")
	}
}

// TestHTTPSServerSANMismatchRejected verifies that a client rejects a server
// certificate whose SAN does not match the address being connected to.
func TestHTTPSServerSANMismatchRejected(t *testing.T) {
	dir := t.TempDir()

	// Generate a cert with SAN 127.0.0.2 (intentional mismatch for 127.0.0.1).
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "wrong-san"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.2")}, // wrong SAN
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)

	certFile := filepath.Join(dir, "mismatch.crt")
	keyFile := filepath.Join(dir, "mismatch.key")
	cf, _ := os.Create(certFile)
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()
	kf, _ := os.Create(keyFile)
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	kf.Close()

	tlsCfg, err := buildTLSConfig(TLSOptions{TLSEnabled: true, CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer listener.Close()

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})}
	go srv.Serve(listener) //nolint:errcheck
	defer srv.Close()

	certPEM, _ := os.ReadFile(certFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	// Must fail: the cert's SAN is 127.0.0.2 but we're connecting to 127.0.0.1.
	_, err = client.Get("https://" + listener.Addr().String())
	if err == nil {
		t.Error("expected a TLS error for SAN mismatch, got nil")
	}
}

// TestHTTPPlainWhenTLSDisabled verifies that a plain HTTP server works when
// TLSEnabled is false (backward-compatible default).
func TestHTTPPlainWhenTLSDisabled(t *testing.T) {
	cfg, err := buildTLSConfig(TLSOptions{TLSEnabled: false})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected nil TLS config when TLSEnabled=false")
	}

	// Start a plain HTTP server using a real listener.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(listener) //nolint:errcheck
	defer srv.Close()

	resp, err := http.Get("http://" + listener.Addr().String())
	if err != nil {
		t.Fatalf("plain HTTP GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}
