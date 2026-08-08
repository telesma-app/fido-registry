package registry

// COSEAuthenticationProfile describes the COSE key profile associated with
// one or more Registry 2.3 authentication algorithms.
//
// Curve is zero for RSA profiles, which do not have a COSE crv parameter.
// KeySizeBytes is the coordinate length for EC2 keys, the public-key length
// for OKP keys, and the modulus length for RSA keys.
type COSEAuthenticationProfile struct {
	Algorithm    int64
	KeyType      int64
	Curve        int64
	KeySizeBytes int
}

var coseAuthenticationProfiles = []struct {
	profile    COSEAuthenticationProfile
	algorithms []AuthenticationAlgorithm
}{
	{
		profile: COSEAuthenticationProfile{Algorithm: -7, KeyType: 2, Curve: 1, KeySizeBytes: 32},
		algorithms: []AuthenticationAlgorithm{
			AuthenticationAlgorithmSECP256R1ECDSASHA256Raw,
			AuthenticationAlgorithmSECP256R1ECDSASHA256DER,
		},
	},
	{
		profile: COSEAuthenticationProfile{Algorithm: -37, KeyType: 3, KeySizeBytes: 256},
		algorithms: []AuthenticationAlgorithm{
			AuthenticationAlgorithmRSASSAPSSSHA256Raw,
			AuthenticationAlgorithmRSASSAPSSSHA256DER,
		},
	},
	{
		profile: COSEAuthenticationProfile{Algorithm: -47, KeyType: 2, Curve: 8, KeySizeBytes: 32},
		algorithms: []AuthenticationAlgorithm{
			AuthenticationAlgorithmSECP256K1ECDSASHA256Raw,
			AuthenticationAlgorithmSECP256K1ECDSASHA256DER,
		},
	},
	{
		profile:    COSEAuthenticationProfile{Algorithm: -38, KeyType: 3, KeySizeBytes: 256},
		algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmRSASSAPSSSHA384Raw},
	},
	{
		profile:    COSEAuthenticationProfile{Algorithm: -39, KeyType: 3, KeySizeBytes: 256},
		algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmRSASSAPSSSHA512Raw},
	},
	{
		profile:    COSEAuthenticationProfile{Algorithm: -257, KeyType: 3, KeySizeBytes: 256},
		algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmRSASSAPKCSV15SHA256Raw},
	},
	{
		profile:    COSEAuthenticationProfile{Algorithm: -258, KeyType: 3, KeySizeBytes: 256},
		algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmRSASSAPKCSV15SHA384Raw},
	},
	{
		profile:    COSEAuthenticationProfile{Algorithm: -259, KeyType: 3, KeySizeBytes: 256},
		algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmRSASSAPKCSV15SHA512Raw},
	},
	{
		profile:    COSEAuthenticationProfile{Algorithm: -65535, KeyType: 3, KeySizeBytes: 256},
		algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmRSASSAPKCSV15SHA1Raw},
	},
	{
		profile:    COSEAuthenticationProfile{Algorithm: -35, KeyType: 2, Curve: 2, KeySizeBytes: 48},
		algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmSECP384R1ECDSASHA384Raw},
	},
	{
		profile:    COSEAuthenticationProfile{Algorithm: -36, KeyType: 2, Curve: 3, KeySizeBytes: 66},
		algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmSECP521R1ECDSASHA512Raw},
	},
	{
		profile:    COSEAuthenticationProfile{Algorithm: -8, KeyType: 1, Curve: 6, KeySizeBytes: 32},
		algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmED25519EdDSASHA512Raw},
	},
	{
		profile:    COSEAuthenticationProfile{Algorithm: -8, KeyType: 1, Curve: 7, KeySizeBytes: 57},
		algorithms: []AuthenticationAlgorithm{AuthenticationAlgorithmED448EdDSASHA512Raw},
	},
}

// COSEProfile returns the Registry 2.3 COSE key profile suitable for
// algorithm. It reports false when the registered algorithm has no COSE key
// representation or when algorithm is unregistered.
func (algorithm AuthenticationAlgorithm) COSEProfile() (COSEAuthenticationProfile, bool) {
	for _, candidate := range coseAuthenticationProfiles {
		for _, mapped := range candidate.algorithms {
			if algorithm == mapped {
				return candidate.profile, true
			}
		}
	}

	return COSEAuthenticationProfile{}, false
}

// LookupCOSEAuthenticationProfile returns the Registry 2.3 profile matching
// the COSE alg, kty, and crv parameters. curve must be zero for RSA profiles.
func LookupCOSEAuthenticationProfile(algorithm, keyType, curve int64) (COSEAuthenticationProfile, bool) {
	for _, candidate := range coseAuthenticationProfiles {
		profile := candidate.profile
		if profile.Algorithm == algorithm && profile.KeyType == keyType && profile.Curve == curve {
			return profile, true
		}
	}

	return COSEAuthenticationProfile{}, false
}

// AuthenticationAlgorithms returns the Registry 2.3 authentication
// algorithms suitable for profile. Some profiles have both raw and DER
// signature encodings.
func (profile COSEAuthenticationProfile) AuthenticationAlgorithms() ([]AuthenticationAlgorithm, bool) {
	for _, candidate := range coseAuthenticationProfiles {
		if profile == candidate.profile {
			return append([]AuthenticationAlgorithm(nil), candidate.algorithms...), true
		}
	}

	return nil, false
}
