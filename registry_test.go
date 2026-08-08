package registry

import (
	"strings"
	"testing"
)

func TestAuthenticationAlgorithms(t *testing.T) {
	tests := []namedNumber[AuthenticationAlgorithm]{
		{"secp256r1_ecdsa_sha256_raw", AuthenticationAlgorithmSECP256R1ECDSASHA256Raw, 0x0001},
		{"secp256r1_ecdsa_sha256_der", AuthenticationAlgorithmSECP256R1ECDSASHA256DER, 0x0002},
		{"rsassa_pss_sha256_raw", AuthenticationAlgorithmRSASSAPSSSHA256Raw, 0x0003},
		{"rsassa_pss_sha256_der", AuthenticationAlgorithmRSASSAPSSSHA256DER, 0x0004},
		{"secp256k1_ecdsa_sha256_raw", AuthenticationAlgorithmSECP256K1ECDSASHA256Raw, 0x0005},
		{"secp256k1_ecdsa_sha256_der", AuthenticationAlgorithmSECP256K1ECDSASHA256DER, 0x0006},
		{"sm2_sm3_raw", AuthenticationAlgorithmSM2SM3Raw, 0x0007},
		{"rsa_emsa_pkcs1_sha256_raw", AuthenticationAlgorithmRSAEMSAPKCS1SHA256Raw, 0x0008},
		{"rsa_emsa_pkcs1_sha256_der", AuthenticationAlgorithmRSAEMSAPKCS1SHA256DER, 0x0009},
		{"rsassa_pss_sha384_raw", AuthenticationAlgorithmRSASSAPSSSHA384Raw, 0x000a},
		{"rsassa_pss_sha512_raw", AuthenticationAlgorithmRSASSAPSSSHA512Raw, 0x000b},
		{"rsassa_pkcsv15_sha256_raw", AuthenticationAlgorithmRSASSAPKCSV15SHA256Raw, 0x000c},
		{"rsassa_pkcsv15_sha384_raw", AuthenticationAlgorithmRSASSAPKCSV15SHA384Raw, 0x000d},
		{"rsassa_pkcsv15_sha512_raw", AuthenticationAlgorithmRSASSAPKCSV15SHA512Raw, 0x000e},
		{"rsassa_pkcsv15_sha1_raw", AuthenticationAlgorithmRSASSAPKCSV15SHA1Raw, 0x000f},
		{"secp384r1_ecdsa_sha384_raw", AuthenticationAlgorithmSECP384R1ECDSASHA384Raw, 0x0010},
		{"secp521r1_ecdsa_sha512_raw", AuthenticationAlgorithmSECP521R1ECDSASHA512Raw, 0x0011},
		{"ed25519_eddsa_sha512_raw", AuthenticationAlgorithmED25519EdDSASHA512Raw, 0x0012},
		{"ed448_eddsa_sha512_raw", AuthenticationAlgorithmED448EdDSASHA512Raw, 0x0013},
	}

	testNamedNumbers(
		t,
		tests,
		ParseAuthenticationAlgorithm,
		func(value AuthenticationAlgorithm) (string, bool) { return value.Name() },
		func(value AuthenticationAlgorithm) bool { return value.Registered() },
		[]AuthenticationAlgorithm{0, 0x0014, 0xffff},
	)
}

func TestPublicKeyEncodings(t *testing.T) {
	tests := []namedNumber[PublicKeyEncoding]{
		{"ecc_x962_raw", PublicKeyEncodingECCX962Raw, 0x0100},
		{"ecc_x962_der", PublicKeyEncodingECCX962DER, 0x0101},
		{"rsa_2048_raw", PublicKeyEncodingRSA2048Raw, 0x0102},
		{"rsa_2048_der", PublicKeyEncodingRSA2048DER, 0x0103},
		{"cose", PublicKeyEncodingCOSE, 0x0104},
	}

	testNamedNumbers(
		t,
		tests,
		ParsePublicKeyEncoding,
		func(value PublicKeyEncoding) (string, bool) { return value.Name() },
		func(value PublicKeyEncoding) bool { return value.Registered() },
		[]PublicKeyEncoding{0, 0x0105, 0xffff},
	)
}

func TestAttestationTypes(t *testing.T) {
	tests := []namedNumber[AttestationType]{
		{"basic_full", AttestationTypeBasicFull, 0x3e07},
		{"basic_surrogate", AttestationTypeBasicSurrogate, 0x3e08},
		{"ecdaa", AttestationTypeECDAA, 0x3e09},
		{"attca", AttestationTypeAttCA, 0x3e0a},
		{"none", AttestationTypeNone, 0x3e0b},
		{"anonca", AttestationTypeAnonCA, 0x3e0c},
	}

	testNamedNumbers(
		t,
		tests,
		ParseAttestationType,
		func(value AttestationType) (string, bool) { return value.Name() },
		func(value AttestationType) bool { return value.Registered() },
		[]AttestationType{0, 0x3e06, 0x3e0d, 0xffff},
	)
}

func TestUserVerificationMethodRegistry(t *testing.T) {
	values := []namedMaskNumber[UserVerificationMethod]{
		{"presence_internal", UserVerificationPresenceInternal, 0x00000001},
		{"fingerprint_internal", UserVerificationFingerprintInternal, 0x00000002},
		{"passcode_internal", UserVerificationPasscodeInternal, 0x00000004},
		{"voiceprint_internal", UserVerificationVoiceprintInternal, 0x00000008},
		{"faceprint_internal", UserVerificationFaceprintInternal, 0x00000010},
		{"location_internal", UserVerificationLocationInternal, 0x00000020},
		{"eyeprint_internal", UserVerificationEyeprintInternal, 0x00000040},
		{"pattern_internal", UserVerificationPatternInternal, 0x00000080},
		{"handprint_internal", UserVerificationHandprintInternal, 0x00000100},
		{"none", UserVerificationNone, 0x00000200},
		{"all", UserVerificationAll, 0x00000400},
		{"passcode_external", UserVerificationPasscodeExternal, 0x00000800},
		{"pattern_external", UserVerificationPatternExternal, 0x00001000},
	}

	testMaskRegistry(
		t,
		values,
		0x3fff,
		registeredUserVerificationMethods,
		ParseUserVerificationMethod,
		ParseUserVerificationMethods,
		func(value UserVerificationMethod) ([]string, bool) { return value.Names() },
		func(value UserVerificationMethod) bool { return value.Registered() },
	)
}

func TestUserVerificationMethodMetadataPolicy(t *testing.T) {
	tests := []struct {
		name    string
		methods UserVerificationMethod
		want    bool
	}{
		{name: "presence", methods: UserVerificationPresenceInternal, want: true},
		{name: "none", methods: UserVerificationNone, want: true},
		{name: "external passcode", methods: UserVerificationPasscodeExternal, want: true},
		{name: "empty"},
		{name: "all", methods: UserVerificationAll},
		{name: "registered combination", methods: UserVerificationFingerprintInternal | UserVerificationPasscodeInternal},
		{name: "reserved", methods: 0x00002000},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.methods.ValidMetadata(); got != test.want {
				t.Fatalf("UserVerificationMethod(%#x).ValidMetadata() = %t, want %t", test.methods, got, test.want)
			}
		})
	}

	assertPolicyDivergence(
		t,
		[]string{"fingerprint_internal", "passcode_internal"},
		UserVerificationFingerprintInternal|UserVerificationPasscodeInternal,
		ParseUserVerificationMethods,
		func(value UserVerificationMethod) ([]string, bool) { return value.Names() },
		func(value UserVerificationMethod) bool { return value.Registered() },
		func(value UserVerificationMethod) bool { return value.ValidMetadata() },
	)
}

func TestKeyProtectionRegistry(t *testing.T) {
	values := []namedMaskNumber[KeyProtection]{
		{"software", KeyProtectionSoftware, 0x0001},
		{"hardware", KeyProtectionHardware, 0x0002},
		{"tee", KeyProtectionTEE, 0x0004},
		{"secure_element", KeyProtectionSecureElement, 0x0008},
		{"remote_handle", KeyProtectionRemoteHandle, 0x0010},
		{"sync_fabric", KeyProtectionSyncFabric, 0x0020},
	}

	testMaskRegistry(
		t,
		values,
		0x7f,
		registeredKeyProtections,
		ParseKeyProtection,
		ParseKeyProtections,
		func(value KeyProtection) ([]string, bool) { return value.Names() },
		func(value KeyProtection) bool { return value.Registered() },
	)
}

func TestKeyProtectionMetadataPolicy(t *testing.T) {
	tests := []struct {
		name       string
		protection KeyProtection
		want       bool
	}{
		{name: "software", protection: KeyProtectionSoftware, want: true},
		{name: "hardware tee", protection: KeyProtectionHardware | KeyProtectionTEE, want: true},
		{name: "hardware secure element", protection: KeyProtectionHardware | KeyProtectionSecureElement, want: true},
		{name: "tee without recommended hardware", protection: KeyProtectionTEE, want: true},
		{name: "secure element without recommended hardware", protection: KeyProtectionSecureElement, want: true},
		{name: "sync fabric", protection: KeyProtectionSyncFabric, want: true},
		{name: "remote software", protection: KeyProtectionRemoteHandle | KeyProtectionSoftware, want: true},
		{name: "remote hardware", protection: KeyProtectionRemoteHandle | KeyProtectionHardware, want: true},
		{name: "remote sync fabric and tee", protection: KeyProtectionRemoteHandle | KeyProtectionSyncFabric | KeyProtectionTEE, want: true},
		{name: "empty"},
		{name: "reserved", protection: 0x0040},
		{name: "software hardware", protection: KeyProtectionSoftware | KeyProtectionHardware},
		{name: "software tee", protection: KeyProtectionSoftware | KeyProtectionTEE},
		{name: "software secure element", protection: KeyProtectionSoftware | KeyProtectionSecureElement},
		{name: "tee secure element", protection: KeyProtectionTEE | KeyProtectionSecureElement},
		{name: "remote alone", protection: KeyProtectionRemoteHandle},
		{name: "remote sync fabric without local protection", protection: KeyProtectionRemoteHandle | KeyProtectionSyncFabric},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.protection.ValidMetadata(); got != test.want {
				t.Fatalf("KeyProtection(%#x).ValidMetadata() = %t, want %t", test.protection, got, test.want)
			}
		})
	}

	assertPolicyDivergence(
		t,
		[]string{"software", "hardware"},
		KeyProtectionSoftware|KeyProtectionHardware,
		ParseKeyProtections,
		func(value KeyProtection) ([]string, bool) { return value.Names() },
		func(value KeyProtection) bool { return value.Registered() },
		func(value KeyProtection) bool { return value.ValidMetadata() },
	)
	assertPolicyDivergence(
		t,
		[]string{"remote_handle", "sync_fabric"},
		KeyProtectionRemoteHandle|KeyProtectionSyncFabric,
		ParseKeyProtections,
		func(value KeyProtection) ([]string, bool) { return value.Names() },
		func(value KeyProtection) bool { return value.Registered() },
		func(value KeyProtection) bool { return value.ValidMetadata() },
	)
}

func TestMatcherProtectionRegistry(t *testing.T) {
	values := []namedMaskNumber[MatcherProtection]{
		{"software", MatcherProtectionSoftware, 0x0001},
		{"tee", MatcherProtectionTEE, 0x0002},
		{"on_chip", MatcherProtectionOnChip, 0x0004},
	}

	testMaskRegistry(
		t,
		values,
		0x0f,
		registeredMatcherProtections,
		ParseMatcherProtection,
		ParseMatcherProtections,
		func(value MatcherProtection) ([]string, bool) { return value.Names() },
		func(value MatcherProtection) bool { return value.Registered() },
	)
}

func TestMatcherProtectionMetadataPolicy(t *testing.T) {
	tests := []struct {
		name       string
		protection MatcherProtection
		want       bool
	}{
		{name: "software", protection: MatcherProtectionSoftware, want: true},
		{name: "tee", protection: MatcherProtectionTEE, want: true},
		{name: "on chip", protection: MatcherProtectionOnChip, want: true},
		{name: "empty"},
		{name: "registered combination", protection: MatcherProtectionSoftware | MatcherProtectionTEE},
		{name: "reserved", protection: 0x0008},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.protection.ValidMetadata(); got != test.want {
				t.Fatalf("MatcherProtection(%#x).ValidMetadata() = %t, want %t", test.protection, got, test.want)
			}
		})
	}

	assertPolicyDivergence(
		t,
		[]string{"software", "tee"},
		MatcherProtectionSoftware|MatcherProtectionTEE,
		ParseMatcherProtections,
		func(value MatcherProtection) ([]string, bool) { return value.Names() },
		func(value MatcherProtection) bool { return value.Registered() },
		func(value MatcherProtection) bool { return value.ValidMetadata() },
	)
}

func TestAttachmentHintRegistry(t *testing.T) {
	values := []namedMaskNumber[AttachmentHint]{
		{"internal", AttachmentHintInternal, 0x0001},
		{"external", AttachmentHintExternal, 0x0002},
		{"wired", AttachmentHintWired, 0x0004},
		{"wireless", AttachmentHintWireless, 0x0008},
		{"nfc", AttachmentHintNFC, 0x0010},
		{"bluetooth", AttachmentHintBluetooth, 0x0020},
		{"network", AttachmentHintNetwork, 0x0040},
		{"ready", AttachmentHintReady, 0x0080},
		{"wifi_direct", AttachmentHintWiFiDirect, 0x0100},
		{"smart-card", AttachmentHintSmartCard, 0x0200},
	}

	testMaskRegistry(
		t,
		values,
		0x07ff,
		registeredAttachmentHints,
		ParseAttachmentHint,
		ParseAttachmentHints,
		func(value AttachmentHint) ([]string, bool) { return value.Names() },
		func(value AttachmentHint) bool { return value.Registered() },
	)
}

func TestAttachmentHintMetadataPolicy(t *testing.T) {
	tests := []struct {
		name  string
		hints AttachmentHint
		want  bool
	}{
		{name: "internal", hints: AttachmentHintInternal, want: true},
		{name: "external wired", hints: AttachmentHintExternal | AttachmentHintWired, want: true},
		{name: "ready", hints: AttachmentHintReady, want: true},
		{name: "nfc without recommended wireless", hints: AttachmentHintNFC, want: true},
		{name: "bluetooth without recommended wireless", hints: AttachmentHintBluetooth, want: true},
		{name: "wifi direct without recommended wireless", hints: AttachmentHintWiFiDirect, want: true},
		{name: "smart card without recommended wired", hints: AttachmentHintSmartCard, want: true},
		{name: "empty"},
		{name: "reserved", hints: 0x0400},
		{name: "internal combination", hints: AttachmentHintInternal | AttachmentHintReady},
		{name: "external alone", hints: AttachmentHintExternal},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.hints.ValidMetadata(); got != test.want {
				t.Fatalf("AttachmentHint(%#x).ValidMetadata() = %t, want %t", test.hints, got, test.want)
			}
		})
	}

	assertPolicyDivergence(
		t,
		[]string{"internal", "ready"},
		AttachmentHintInternal|AttachmentHintReady,
		ParseAttachmentHints,
		func(value AttachmentHint) ([]string, bool) { return value.Names() },
		func(value AttachmentHint) bool { return value.Registered() },
		func(value AttachmentHint) bool { return value.ValidMetadata() },
	)
}

func TestTransactionConfirmationDisplayRegistry(t *testing.T) {
	values := []namedMaskNumber[TransactionConfirmationDisplay]{
		{"any", TransactionConfirmationDisplayAny, 0x0001},
		{"privileged_software", TransactionConfirmationDisplayPrivilegedSoftware, 0x0002},
		{"tee", TransactionConfirmationDisplayTEE, 0x0004},
		{"hardware", TransactionConfirmationDisplayHardware, 0x0008},
		{"remote", TransactionConfirmationDisplayRemote, 0x0010},
	}

	testMaskRegistry(
		t,
		values,
		0x3f,
		registeredTransactionConfirmationDisplays,
		ParseTransactionConfirmationDisplay,
		ParseTransactionConfirmationDisplays,
		func(value TransactionConfirmationDisplay) ([]string, bool) { return value.Names() },
		func(value TransactionConfirmationDisplay) bool { return value.Registered() },
	)
}

func TestTransactionConfirmationDisplayMetadataPolicy(t *testing.T) {
	tests := []struct {
		name    string
		display TransactionConfirmationDisplay
		want    bool
	}{
		{name: "unsupported", want: true},
		{name: "any", display: TransactionConfirmationDisplayAny, want: true},
		{name: "remote", display: TransactionConfirmationDisplayAny | TransactionConfirmationDisplayRemote, want: true},
		{name: "hardware remote", display: TransactionConfirmationDisplayAny | TransactionConfirmationDisplayHardware | TransactionConfirmationDisplayRemote, want: true},
		{name: "reserved", display: 0x0020},
		{name: "missing any", display: TransactionConfirmationDisplayTEE},
		{name: "remote missing any", display: TransactionConfirmationDisplayRemote},
		{name: "exclusive implementations", display: TransactionConfirmationDisplayAny | TransactionConfirmationDisplayTEE | TransactionConfirmationDisplayHardware},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.display.ValidMetadata(); got != test.want {
				t.Fatalf("TransactionConfirmationDisplay(%#x).ValidMetadata() = %t, want %t", test.display, got, test.want)
			}
		})
	}

	assertPolicyDivergence(
		t,
		[]string{"tee"},
		TransactionConfirmationDisplayTEE,
		ParseTransactionConfirmationDisplays,
		func(value TransactionConfirmationDisplay) ([]string, bool) { return value.Names() },
		func(value TransactionConfirmationDisplay) bool { return value.Registered() },
		func(value TransactionConfirmationDisplay) bool { return value.ValidMetadata() },
	)
	assertPolicyDivergence(
		t,
		[]string{"any", "tee", "hardware"},
		TransactionConfirmationDisplayAny|TransactionConfirmationDisplayTEE|TransactionConfirmationDisplayHardware,
		ParseTransactionConfirmationDisplays,
		func(value TransactionConfirmationDisplay) ([]string, bool) { return value.Names() },
		func(value TransactionConfirmationDisplay) bool { return value.Registered() },
		func(value TransactionConfirmationDisplay) bool { return value.ValidMetadata() },
	)
}

func TestUserVerificationMethodString(t *testing.T) {
	tests := []struct {
		methods UserVerificationMethod
		want    string
	}{
		{want: ""},
		{methods: UserVerificationPresenceInternal | UserVerificationAll, want: "presence_internal,all"},
		{methods: UserVerificationPresenceInternal | 0x2000, want: "presence_internal,unknown(0x2000)"},
	}

	for _, test := range tests {
		if got := test.methods.String(); got != test.want {
			t.Errorf("UserVerificationMethod(%#x).String() = %q, want %q", test.methods, got, test.want)
		}
	}
}

type namedNumber[T ~uint16] struct {
	name   string
	value  T
	number uint16
}

func testNamedNumbers[T ~uint16](
	t *testing.T,
	values []namedNumber[T],
	parse func(string) (T, bool),
	name func(T) (string, bool),
	registered func(T) bool,
	unregistered []T,
) {
	t.Helper()

	wantNames := make(map[T]string, len(values))
	for _, want := range values {
		wantNames[want.value] = want.name

		t.Run(want.name, func(t *testing.T) {
			if got := uint16(want.value); got != want.number {
				t.Fatalf("numeric value = %#04x, want %#04x", got, want.number)
			}

			gotValue, ok := parse(want.name)
			if !ok || gotValue != want.value {
				t.Fatalf("parse(%q) = (%#04x, %t), want (%#04x, true)", want.name, gotValue, ok, want.value)
			}

			gotName, ok := name(want.value)
			if !ok || gotName != want.name {
				t.Fatalf("name(%#04x) = (%q, %t), want (%q, true)", want.value, gotName, ok, want.name)
			}
			if !registered(want.value) {
				t.Fatalf("%#04x is not registered", want.value)
			}

			if _, ok := parse(strings.ToUpper(want.name)); ok {
				t.Fatalf("case-insensitive parse accepted %q", strings.ToUpper(want.name))
			}
		})
	}

	for raw := uint32(0); raw <= 0xffff; raw++ {
		value := T(raw)
		wantName, wantRegistered := wantNames[value]
		if got := registered(value); got != wantRegistered {
			t.Fatalf("Registered(%#04x) = %t, want %t", value, got, wantRegistered)
		}

		gotName, ok := name(value)
		if ok != wantRegistered || gotName != wantName {
			t.Fatalf("Name(%#04x) = (%q, %t), want (%q, %t)", value, gotName, ok, wantName, wantRegistered)
		}
	}

	for _, value := range unregistered {
		if got, ok := name(value); ok || got != "" {
			t.Errorf("name(%#04x) = (%q, %t), want empty and false", value, got, ok)
		}
		if registered(value) {
			t.Errorf("%#04x is registered", value)
		}
	}

	for _, invalid := range []string{"", "reserved"} {
		if _, ok := parse(invalid); ok {
			t.Errorf("parse(%q) succeeded", invalid)
		}
	}
}

type namedMaskNumber[T mask] struct {
	name   string
	value  T
	number uint64
}

func testMaskRegistry[T mask](
	t *testing.T,
	values []namedMaskNumber[T],
	max uint64,
	registeredBits T,
	parseOne func(string) (T, bool),
	parseMany func([]string) (T, bool),
	names func(T) ([]string, bool),
	registered func(T) bool,
) {
	t.Helper()

	for _, want := range values {
		t.Run(want.name, func(t *testing.T) {
			if got := uint64(want.value); got != want.number {
				t.Fatalf("numeric value = %#x, want %#x", got, want.number)
			}

			got, ok := parseOne(want.name)
			if !ok || got != want.value {
				t.Fatalf("single parse(%q) = (%#x, %t), want (%#x, true)", want.name, got, ok, want.value)
			}
			if _, ok := parseOne(strings.ToUpper(want.name)); ok {
				t.Fatalf("case-insensitive parse accepted %q", strings.ToUpper(want.name))
			}
		})
	}

	if got, ok := parseMany(nil); !ok || got != 0 {
		t.Fatalf("empty plural parse = (%#x, %t), want (0, true)", got, ok)
	}
	if _, ok := parseMany([]string{"reserved"}); ok {
		t.Fatal("plural parser accepted an unknown name")
	}
	if _, ok := parseMany([]string{values[0].name, values[0].name}); ok {
		t.Fatal("plural parser accepted a duplicate name")
	}

	for raw := uint64(0); raw <= max; raw++ {
		value := T(raw)
		wantRegistered := value&^registeredBits == 0
		if got := registered(value); got != wantRegistered {
			t.Fatalf("Registered(%#x) = %t, want %t", value, got, wantRegistered)
		}

		gotNames, ok := names(value)
		if ok != wantRegistered {
			t.Fatalf("Names(%#x) ok = %t, want %t", value, ok, wantRegistered)
		}
		if !ok {
			continue
		}

		got, ok := parseMany(gotNames)
		if !ok || got != value {
			t.Fatalf("%#x names round-trip = (%#x, %t)", value, got, ok)
		}
	}
}

func assertPolicyDivergence[T mask](
	t *testing.T,
	names []string,
	want T,
	parse func([]string) (T, bool),
	valueNames func(T) ([]string, bool),
	registered func(T) bool,
	validMetadata func(T) bool,
) {
	t.Helper()

	got, ok := parse(names)
	if !ok || got != want {
		t.Fatalf("registry parser rejected policy combination %v: (%#x, %t)", names, got, ok)
	}
	if !registered(got) {
		t.Fatalf("registered combination %#x reported unregistered", got)
	}
	if validMetadata(got) {
		t.Fatalf("policy combination %#x reported valid metadata", got)
	}

	gotNames, ok := valueNames(got)
	if !ok || strings.Join(gotNames, ",") != strings.Join(names, ",") {
		t.Fatalf("Names(%#x) = (%v, %t), want (%v, true)", got, gotNames, ok, names)
	}
}
