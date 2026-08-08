package registry

import (
	"slices"
	"testing"
)

func TestCOSEAuthenticationProfiles(t *testing.T) {
	tests := []struct {
		name       string
		profile    COSEAuthenticationProfile
		algorithms []AuthenticationAlgorithm
	}{
		{
			name:    "P-256",
			profile: COSEAuthenticationProfile{Algorithm: -7, KeyType: 2, Curve: 1, KeySizeBytes: 32},
			algorithms: []AuthenticationAlgorithm{
				AuthenticationAlgorithmSECP256R1ECDSASHA256Raw,
				AuthenticationAlgorithmSECP256R1ECDSASHA256DER,
			},
		},
		{
			name:    "RSA-PSS SHA-256",
			profile: COSEAuthenticationProfile{Algorithm: -37, KeyType: 3, KeySizeBytes: 256},
			algorithms: []AuthenticationAlgorithm{
				AuthenticationAlgorithmRSASSAPSSSHA256Raw,
				AuthenticationAlgorithmRSASSAPSSSHA256DER,
			},
		},
		{
			name:    "secp256k1",
			profile: COSEAuthenticationProfile{Algorithm: -47, KeyType: 2, Curve: 8, KeySizeBytes: 32},
			algorithms: []AuthenticationAlgorithm{
				AuthenticationAlgorithmSECP256K1ECDSASHA256Raw,
				AuthenticationAlgorithmSECP256K1ECDSASHA256DER,
			},
		},
		{
			name:       "RSA-PSS SHA-384",
			profile:    COSEAuthenticationProfile{Algorithm: -38, KeyType: 3, KeySizeBytes: 256},
			algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmRSASSAPSSSHA384Raw},
		},
		{
			name:       "RSA-PSS SHA-512",
			profile:    COSEAuthenticationProfile{Algorithm: -39, KeyType: 3, KeySizeBytes: 256},
			algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmRSASSAPSSSHA512Raw},
		},
		{
			name:       "RSA PKCS1 SHA-256",
			profile:    COSEAuthenticationProfile{Algorithm: -257, KeyType: 3, KeySizeBytes: 256},
			algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmRSASSAPKCSV15SHA256Raw},
		},
		{
			name:       "RSA PKCS1 SHA-384",
			profile:    COSEAuthenticationProfile{Algorithm: -258, KeyType: 3, KeySizeBytes: 256},
			algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmRSASSAPKCSV15SHA384Raw},
		},
		{
			name:       "RSA PKCS1 SHA-512",
			profile:    COSEAuthenticationProfile{Algorithm: -259, KeyType: 3, KeySizeBytes: 256},
			algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmRSASSAPKCSV15SHA512Raw},
		},
		{
			name:       "RSA PKCS1 SHA-1",
			profile:    COSEAuthenticationProfile{Algorithm: -65535, KeyType: 3, KeySizeBytes: 256},
			algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmRSASSAPKCSV15SHA1Raw},
		},
		{
			name:       "P-384",
			profile:    COSEAuthenticationProfile{Algorithm: -35, KeyType: 2, Curve: 2, KeySizeBytes: 48},
			algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmSECP384R1ECDSASHA384Raw},
		},
		{
			name:       "P-521",
			profile:    COSEAuthenticationProfile{Algorithm: -36, KeyType: 2, Curve: 3, KeySizeBytes: 66},
			algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmSECP521R1ECDSASHA512Raw},
		},
		{
			name:       "Ed25519",
			profile:    COSEAuthenticationProfile{Algorithm: -8, KeyType: 1, Curve: 6, KeySizeBytes: 32},
			algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmED25519EdDSASHA512Raw},
		},
		{
			name:       "Ed448",
			profile:    COSEAuthenticationProfile{Algorithm: -8, KeyType: 1, Curve: 7, KeySizeBytes: 57},
			algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmED448EdDSASHA512Raw},
		},
	}

	seenAlgorithms := make(map[AuthenticationAlgorithm]bool)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := LookupCOSEAuthenticationProfile(
				test.profile.Algorithm,
				test.profile.KeyType,
				test.profile.Curve,
			)
			if !ok || got != test.profile {
				t.Fatalf("LookupCOSEAuthenticationProfile() = (%+v, %t), want (%+v, true)", got, ok, test.profile)
			}

			gotAlgorithms, ok := got.AuthenticationAlgorithms()
			if !ok || !slices.Equal(gotAlgorithms, test.algorithms) {
				t.Fatalf("AuthenticationAlgorithms() = (%v, %t), want (%v, true)", gotAlgorithms, ok, test.algorithms)
			}

			for _, algorithm := range test.algorithms {
				seenAlgorithms[algorithm] = true

				got, ok := algorithm.COSEProfile()
				if !ok || got != test.profile {
					t.Errorf("%#04x.COSEProfile() = (%+v, %t), want (%+v, true)", algorithm, got, ok, test.profile)
				}
			}
		})
	}

	for _, algorithm := range authenticationAlgorithms {
		_, ok := algorithm.value.COSEProfile()
		if ok != seenAlgorithms[algorithm.value] {
			t.Errorf("%s.COSEProfile() ok = %t, want %t", algorithm.name, ok, seenAlgorithms[algorithm.value])
		}
	}
}

func TestCOSEAuthenticationProfileRejectsUnknownValues(t *testing.T) {
	for _, algorithm := range []AuthenticationAlgorithm{
		0,
		AuthenticationAlgorithmSM2SM3Raw,
		AuthenticationAlgorithmRSAEMSAPKCS1SHA256Raw,
		AuthenticationAlgorithmRSAEMSAPKCS1SHA256DER,
		0xffff,
	} {
		if got, ok := algorithm.COSEProfile(); ok || got != (COSEAuthenticationProfile{}) {
			t.Errorf("%#04x.COSEProfile() = (%+v, %t), want zero and false", algorithm, got, ok)
		}
	}

	for _, profile := range []COSEAuthenticationProfile{
		{},
		{Algorithm: -8, KeyType: 1},
		{Algorithm: -8, KeyType: 2, Curve: 6},
		{Algorithm: -8, KeyType: 1, Curve: 8},
		{Algorithm: -7, KeyType: 2, Curve: 2},
		{Algorithm: -37, KeyType: 3, Curve: 1},
		{Algorithm: -257, KeyType: 2},
		{Algorithm: 1, KeyType: 1, Curve: 1},
	} {
		got, ok := LookupCOSEAuthenticationProfile(profile.Algorithm, profile.KeyType, profile.Curve)
		if ok || got != (COSEAuthenticationProfile{}) {
			t.Errorf("LookupCOSEAuthenticationProfile(%+v) = (%+v, %t), want zero and false", profile, got, ok)
		}
	}

	profile := COSEAuthenticationProfile{Algorithm: -8, KeyType: 1, Curve: 7, KeySizeBytes: 56}
	if got, ok := profile.AuthenticationAlgorithms(); ok || got != nil {
		t.Errorf("AuthenticationAlgorithms() = (%v, %t), want nil and false", got, ok)
	}
}
