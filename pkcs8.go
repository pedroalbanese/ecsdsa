package ecsdsa

import (
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/pedroalbanese/brainpool"
	"github.com/pedroalbanese/frp256v1"
	"github.com/pedroalbanese/go-nums"
	"github.com/pedroalbanese/tom"
	"github.com/pedroalbanese/secp256k1"
	"github.com/RyuaNerin/elliptic2/nist"
	"golang.org/x/crypto/cryptobyte"
)

const ecPrivKeyVersion = 1

var (
	oidPublicKeyECSDSA = asn1.ObjectIdentifier{1, 0, 14888, 3, 0, 11}

	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	
	oidNamedCurveS256 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	oidANSSIFRP256v1 = asn1.ObjectIdentifier{1, 2, 250, 1, 223, 101, 256, 1}

	oidBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 7}
	oidBrainpoolP256t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 8}
	oidBrainpoolP384r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 11}
	oidBrainpoolP384t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 12}
	oidBrainpoolP512r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 13}
	oidBrainpoolP512t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 1, 1, 14}

	oidNumsp256d1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 1}
	oidNumsp256t1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 2}
	oidNumsp384d1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 3}
	oidNumsp384t1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 4}
	oidNumsp512d1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 5}
	oidNumsp512t1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 6}
	
	oidTom256 = asn1.ObjectIdentifier{1, 2, 999, 1, 1, 1, 1}
	oidTom384 = asn1.ObjectIdentifier{1, 2, 999, 1, 1, 1, 2}

	oidSect283k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 16}
	oidSect283r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 17}
	oidSect409k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 36}
	oidSect409r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 37}
	oidSect571k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 38}
	oidSect571r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 39}
)

func init() {
	AddNamedCurve(elliptic.P224(), oidNamedCurveP224)
	AddNamedCurve(elliptic.P256(), oidNamedCurveP256)
	AddNamedCurve(elliptic.P384(), oidNamedCurveP384)
	AddNamedCurve(elliptic.P521(), oidNamedCurveP521)
	
	AddNamedCurve(secp256k1.S256(), oidNamedCurveS256)
	AddNamedCurve(frp256v1.P256(), oidANSSIFRP256v1)

	AddNamedCurve(brainpool.P256r1(), oidBrainpoolP256r1)
	AddNamedCurve(brainpool.P256t1(), oidBrainpoolP256t1)
	AddNamedCurve(brainpool.P384r1(), oidBrainpoolP384r1)
	AddNamedCurve(brainpool.P384t1(), oidBrainpoolP384t1)
	AddNamedCurve(brainpool.P512r1(), oidBrainpoolP512r1)
	AddNamedCurve(brainpool.P512t1(), oidBrainpoolP512t1)
	
	AddNamedCurve(nums.P256d1(), oidNumsp256d1)
	AddNamedCurve(nums.P256t1(), oidNumsp256t1)
	AddNamedCurve(nums.P384d1(), oidNumsp384d1)
	AddNamedCurve(nums.P384t1(), oidNumsp384t1)
	AddNamedCurve(nums.P512d1(), oidNumsp512d1)
	AddNamedCurve(nums.P512t1(), oidNumsp512t1)
	
	AddNamedCurve(tom.P256(), oidTom256)
	AddNamedCurve(tom.P384(), oidTom384)

	AddNamedCurve(nist.K283(), oidSect283k1)
	AddNamedCurve(nist.B283(), oidSect283r1)
	AddNamedCurve(nist.K409(), oidSect409k1)
	AddNamedCurve(nist.B409(), oidSect409r1)
	AddNamedCurve(nist.K571(), oidSect571k1)
	AddNamedCurve(nist.B571(), oidSect571r1)
}

// Private Key - Wrapping
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	Attributes []asn1.RawValue `asn1:"optional,tag:0"`
}

// Public Key - Wrapping
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

// Public Key Information - Parsing
type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// Wrap Public Key
func MarshalPublicKey(pub *PublicKey) ([]byte, error) {
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	var err error

	oid, ok := OidFromNamedCurve(pub.Curve)
	if !ok {
		return nil, errors.New("ecsdsa: unsupported ecsdsa curve")
	}

	var paramBytes []byte
	paramBytes, err = asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}

	publicKeyAlgorithm.Algorithm = oidPublicKeyECSDSA
	publicKeyAlgorithm.Parameters.FullBytes = paramBytes

	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("ecsdsa: invalid elliptic curve public key")
	}

	publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)

	pkix := pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	}

	return asn1.Marshal(pkix)
}

// Parse Public Key
func ParsePublicKey(derBytes []byte) (pub *PublicKey, err error) {
	var pki publicKeyInfo
	rest, err := asn1.Unmarshal(derBytes, &pki)
	if err != nil {
		return
	} else if len(rest) != 0 {
		err = errors.New("ecsdsa: trailing data after ASN.1 of public-key")
		return
	}

	if len(rest) > 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return
	}

	keyData := &pki

	oid := keyData.Algorithm.Algorithm
	params := keyData.Algorithm.Parameters
	der := cryptobyte.String(keyData.PublicKey.RightAlign())

	if !oid.Equal(oidPublicKeyECSDSA) {
		err = errors.New("ecsdsa: unknown public key algorithm")
		return
	}

	paramsDer := cryptobyte.String(params.FullBytes)
	namedCurveOID := new(asn1.ObjectIdentifier)
	if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
		return nil, errors.New("ecsdsa: invalid parameters")
	}

	namedCurve := NamedCurveFromOid(*namedCurveOID)
	if namedCurve == nil {
		err = errors.New("ecsdsa: unsupported ecsdsa curve")
		return
	}

	x, y := elliptic.Unmarshal(namedCurve, der)
	if x == nil {
		err = errors.New("ecsdsa: failed to unmarshal elliptic curve point")
		return
	}

	pub = &PublicKey{
		Curve: namedCurve,
		X:     x,
		Y:     y,
	}

	return
}

// ====================

// Wrap Private Key
func MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
	var privKey pkcs8

	oid, ok := OidFromNamedCurve(key.Curve)
	if !ok {
		return nil, errors.New("ecsdsa: unsupported ecsdsa curve")
	}

	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		return nil, errors.New("ecsdsa: failed to marshal algo param: " + err.Error())
	}

	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm: oidPublicKeyECSDSA,
		Parameters: asn1.RawValue{
			FullBytes: oidBytes,
		},
	}

	privKey.PrivateKey, err = marshalECPrivateKeyWithOID(key, nil)
	if err != nil {
		return nil, errors.New("ecsdsa: failed to marshal EC private key while building PKCS#8: " + err.Error())
	}

	return asn1.Marshal(privKey)
}

// Parse Private Key
func ParsePrivateKey(derBytes []byte) (*PrivateKey, error) {
	var privKey pkcs8
	var err error

	_, err = asn1.Unmarshal(derBytes, &privKey)
	if err != nil {
		return nil, err
	}

	if !privKey.Algo.Algorithm.Equal(oidPublicKeyECSDSA) {
		err = errors.New("ecsdsa: unknown private key algorithm")
		return nil, err
	}

	bytes := privKey.Algo.Parameters.FullBytes

	namedCurveOID := new(asn1.ObjectIdentifier)
	if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
		namedCurveOID = nil
	}

	key, err := parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
	if err != nil {
		return nil, errors.New("ecsdsa: failed to parse EC private key embedded in PKCS#8: " + err.Error())
	}

	return key, nil
}

// marshalECPrivateKeyWithOID marshals an SM2 private key into ASN.1, DER format and
// sets the curve ID to the given OID, or omits it if OID is nil.
func marshalECPrivateKeyWithOID(key *PrivateKey, oid asn1.ObjectIdentifier) ([]byte, error) {
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("ecsdsa: invalid elliptic key public key")
	}

	privateKey := make([]byte, BitsToBytes(key.D.BitLen()))

	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    key.D.FillBytes(privateKey),
		NamedCurveOID: oid,
		PublicKey: asn1.BitString{
			Bytes: elliptic.Marshal(key.Curve, key.X, key.Y),
		},
	})
}

// parseECPrivateKey parses an ASN.1 Elliptic Curve Private Key Structure.
// The OID for the named curve may be provided from another source (such as
// the PKCS8 container) - if it is provided then use this instead of the OID
// that may exist in the EC private key structure.
func parseECPrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key *PrivateKey, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("ecsdsa: failed to parse EC private key: " + err.Error())
	}

	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("ecsdsa: unknown EC private key version %d", privKey.Version)
	}

	var curve elliptic.Curve
	if namedCurveOID != nil {
		curve = NamedCurveFromOid(*namedCurveOID)
	} else {
		curve = NamedCurveFromOid(privKey.NamedCurveOID)
	}

	if curve == nil {
		return nil, errors.New("ecsdsa: unknown elliptic curve")
	}

	k := new(big.Int).SetBytes(privKey.PrivateKey)

	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("ecsdsa: invalid elliptic curve private key value")
	}

	priv := new(PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("ecsdsa: invalid private key length")
		}

		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)

	d := new(big.Int).SetBytes(privateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(d.Bytes())

	return priv, nil
}

func BitsToBytes(bits int) int {
	return (bits + 7) / 8
}

