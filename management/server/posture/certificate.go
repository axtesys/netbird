package posture

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

// certKeyURIScheme is the URI-SAN scheme that binds a compliance certificate to a
// peer's WireGuard public key. The certificate carries a SAN of the form
// "netbird:<wg-pubkey>"; the check requires it to match the peer's authenticated
// Key. The binding follows the SPIFFE x509-SVID convention of encoding identity in
// a URI SAN. The WireGuard key is X25519 (DH), so it cannot be the certificate's
// own subject key with a possession proof — it is carried as a claim, and
// NetBird's WireGuard handshake supplies the proof.
const certKeyURIScheme = "netbird"

// CertificateCheck verifies that a peer presents a valid compliance certificate.
// The certificate is a short-lived attestation, issued by an external compliance
// service only while the device is compliant, and is delivered to the management
// server in the peer's system metadata. A peer that presents no certificate, an
// expired one, one that does not chain to the configured CA, or one not bound to
// its own WireGuard key fails the check.
type CertificateCheck struct {
	// CABundle is the PEM-encoded set of CA certificates the peer certificate must
	// chain to.
	CABundle string
}

var _ Check = (*CertificateCheck)(nil)

func (c *CertificateCheck) Check(_ context.Context, peer nbpeer.Peer) (bool, error) {
	if peer.Meta.Certificate == "" {
		return false, errors.New("peer has no compliance certificate")
	}

	chain, err := decodeCertChain(peer.Meta.Certificate)
	if err != nil {
		return false, fmt.Errorf("parse peer certificate: %w", err)
	}
	leaf := chain[0]

	if !certBoundToKey(leaf, peer.Key) {
		return false, fmt.Errorf("certificate is not bound to peer key %s", peer.Key)
	}

	roots, err := parseCertPool(c.CABundle)
	if err != nil {
		return false, fmt.Errorf("parse CA bundle: %w", err)
	}

	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	// Verify chains the leaf to the configured roots and enforces the validity
	// window (NotBefore/NotAfter) against the current time. ExtKeyUsageAny keeps
	// the check agnostic to the certificate's EKU — trust comes from the CA and the
	// key binding, not from a server-auth usage bit.
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return false, fmt.Errorf("verify certificate: %w", err)
	}

	return true, nil
}

func (c *CertificateCheck) Name() string {
	return CertificateCheckName
}

func (c *CertificateCheck) Validate() error {
	if _, err := parseCertPool(c.CABundle); err != nil {
		return fmt.Errorf("certificate check: %w", err)
	}
	return nil
}

// certBoundToKey reports whether the certificate carries a URI SAN binding it to
// the given WireGuard public key. The whole URI string is compared (rather than
// scheme+opaque) so a base64 key is matched verbatim regardless of how url.Parse
// splits it.
func certBoundToKey(cert *x509.Certificate, key string) bool {
	want := certKeyURIScheme + ":" + key
	for _, uri := range cert.URIs {
		if uri.String() == want {
			return true
		}
	}
	return false
}

// decodeCertChain parses a PEM bundle into a certificate chain, leaf first. It
// tolerates non-certificate PEM blocks and requires at least one certificate.
func decodeCertChain(pemData string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate found in PEM data")
	}
	return certs, nil
}

// parseCertPool builds a certificate pool from a PEM bundle, requiring at least
// one valid certificate.
func parseCertPool(pemData string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemData)) {
		return nil, errors.New("no valid CA certificate in bundle")
	}
	return pool, nil
}
