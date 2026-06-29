package posture

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/peer"
)

const testPeerKey = "Cz+J9F8j5kK8q9wXpYvL2mN3oP4rS6tU7vW8xY9zA0c="

// certFixture builds a self-signed CA and a leaf certificate signed by it. The
// leaf carries a netbird:<key> URI SAN unless boundKey is empty, and is valid
// over [notBefore, notAfter]. It returns the CA bundle PEM and the leaf PEM.
func certFixture(t *testing.T, boundKey string, notBefore, notAfter time.Time) (caPEM, leafPEM string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test compliance CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test device"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	if boundKey != "" {
		u, err := url.Parse(certKeyURIScheme + ":" + boundKey)
		require.NoError(t, err)
		leafTmpl.URIs = []*url.URL{u}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	encode := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	return encode(caDER), encode(leafDER)
}

func TestCertificateCheck_Check(t *testing.T) {
	now := time.Now()
	validCA, validLeaf := certFixture(t, testPeerKey, now.Add(-time.Hour), now.Add(time.Hour))
	otherCA, _ := certFixture(t, testPeerKey, now.Add(-time.Hour), now.Add(time.Hour))
	_, expiredLeaf := certFixture(t, testPeerKey, now.Add(-2*time.Hour), now.Add(-time.Hour))
	_, wrongKeyLeaf := certFixture(t, "someOtherPeerKeyAAAAAAAAAAAAAAAAAAAAAAAAAAA=", now.Add(-time.Hour), now.Add(time.Hour))
	_, noSANLeaf := certFixture(t, "", now.Add(-time.Hour), now.Add(time.Hour))

	tests := []struct {
		name    string
		cert    string
		caPEM   string
		wantErr bool
		isValid bool
	}{
		{name: "valid certificate", cert: validLeaf, caPEM: validCA, isValid: true},
		{name: "no certificate", cert: "", caPEM: validCA, wantErr: true},
		{name: "expired certificate", cert: expiredLeaf, caPEM: validCA, wantErr: true},
		{name: "untrusted CA", cert: validLeaf, caPEM: otherCA, wantErr: true},
		{name: "wrong key binding", cert: wrongKeyLeaf, caPEM: validCA, wantErr: true},
		{name: "missing key binding", cert: noSANLeaf, caPEM: validCA, wantErr: true},
		{name: "malformed certificate", cert: "not a pem", caPEM: validCA, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			check := &CertificateCheck{CABundle: tc.caPEM}
			p := peer.Peer{
				Key:  testPeerKey,
				Meta: peer.PeerSystemMeta{Certificate: tc.cert},
			}
			isValid, err := check.Check(context.Background(), p)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.isValid, isValid)
		})
	}
}

func TestCertificateCheck_Validate(t *testing.T) {
	validCA, _ := certFixture(t, testPeerKey, time.Now(), time.Now().Add(time.Hour))

	t.Run("valid CA bundle", func(t *testing.T) {
		require.NoError(t, (&CertificateCheck{CABundle: validCA}).Validate())
	})
	t.Run("empty CA bundle", func(t *testing.T) {
		require.Error(t, (&CertificateCheck{CABundle: ""}).Validate())
	})
	t.Run("garbage CA bundle", func(t *testing.T) {
		require.Error(t, (&CertificateCheck{CABundle: "-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----"}).Validate())
	})
}
