package registry

import (
	"fmt"
	"strings"
)

// Version identifies the FIDO Registry of Predefined Values represented by
// this package.
const Version = "2.3"

// AuthenticationAlgorithm is a FIDO authentication-algorithm identifier.
type AuthenticationAlgorithm uint16

const (
	AuthenticationAlgorithmSECP256R1ECDSASHA256Raw AuthenticationAlgorithm = 0x0001
	AuthenticationAlgorithmSECP256R1ECDSASHA256DER AuthenticationAlgorithm = 0x0002
	AuthenticationAlgorithmRSASSAPSSSHA256Raw      AuthenticationAlgorithm = 0x0003
	AuthenticationAlgorithmRSASSAPSSSHA256DER      AuthenticationAlgorithm = 0x0004
	AuthenticationAlgorithmSECP256K1ECDSASHA256Raw AuthenticationAlgorithm = 0x0005
	AuthenticationAlgorithmSECP256K1ECDSASHA256DER AuthenticationAlgorithm = 0x0006
	AuthenticationAlgorithmSM2SM3Raw               AuthenticationAlgorithm = 0x0007
	AuthenticationAlgorithmRSAEMSAPKCS1SHA256Raw   AuthenticationAlgorithm = 0x0008
	AuthenticationAlgorithmRSAEMSAPKCS1SHA256DER   AuthenticationAlgorithm = 0x0009
	AuthenticationAlgorithmRSASSAPSSSHA384Raw      AuthenticationAlgorithm = 0x000a
	AuthenticationAlgorithmRSASSAPSSSHA512Raw      AuthenticationAlgorithm = 0x000b
	AuthenticationAlgorithmRSASSAPKCSV15SHA256Raw  AuthenticationAlgorithm = 0x000c
	AuthenticationAlgorithmRSASSAPKCSV15SHA384Raw  AuthenticationAlgorithm = 0x000d
	AuthenticationAlgorithmRSASSAPKCSV15SHA512Raw  AuthenticationAlgorithm = 0x000e
	AuthenticationAlgorithmRSASSAPKCSV15SHA1Raw    AuthenticationAlgorithm = 0x000f
	AuthenticationAlgorithmSECP384R1ECDSASHA384Raw AuthenticationAlgorithm = 0x0010
	AuthenticationAlgorithmSECP521R1ECDSASHA512Raw AuthenticationAlgorithm = 0x0011
	AuthenticationAlgorithmED25519EdDSASHA512Raw   AuthenticationAlgorithm = 0x0012
	AuthenticationAlgorithmED448EdDSASHA512Raw     AuthenticationAlgorithm = 0x0013
)

var authenticationAlgorithms = []namedValue[AuthenticationAlgorithm]{
	{AuthenticationAlgorithmSECP256R1ECDSASHA256Raw, "secp256r1_ecdsa_sha256_raw"},
	{AuthenticationAlgorithmSECP256R1ECDSASHA256DER, "secp256r1_ecdsa_sha256_der"},
	{AuthenticationAlgorithmRSASSAPSSSHA256Raw, "rsassa_pss_sha256_raw"},
	{AuthenticationAlgorithmRSASSAPSSSHA256DER, "rsassa_pss_sha256_der"},
	{AuthenticationAlgorithmSECP256K1ECDSASHA256Raw, "secp256k1_ecdsa_sha256_raw"},
	{AuthenticationAlgorithmSECP256K1ECDSASHA256DER, "secp256k1_ecdsa_sha256_der"},
	{AuthenticationAlgorithmSM2SM3Raw, "sm2_sm3_raw"},
	{AuthenticationAlgorithmRSAEMSAPKCS1SHA256Raw, "rsa_emsa_pkcs1_sha256_raw"},
	{AuthenticationAlgorithmRSAEMSAPKCS1SHA256DER, "rsa_emsa_pkcs1_sha256_der"},
	{AuthenticationAlgorithmRSASSAPSSSHA384Raw, "rsassa_pss_sha384_raw"},
	{AuthenticationAlgorithmRSASSAPSSSHA512Raw, "rsassa_pss_sha512_raw"},
	{AuthenticationAlgorithmRSASSAPKCSV15SHA256Raw, "rsassa_pkcsv15_sha256_raw"},
	{AuthenticationAlgorithmRSASSAPKCSV15SHA384Raw, "rsassa_pkcsv15_sha384_raw"},
	{AuthenticationAlgorithmRSASSAPKCSV15SHA512Raw, "rsassa_pkcsv15_sha512_raw"},
	{AuthenticationAlgorithmRSASSAPKCSV15SHA1Raw, "rsassa_pkcsv15_sha1_raw"},
	{AuthenticationAlgorithmSECP384R1ECDSASHA384Raw, "secp384r1_ecdsa_sha384_raw"},
	{AuthenticationAlgorithmSECP521R1ECDSASHA512Raw, "secp521r1_ecdsa_sha512_raw"},
	{AuthenticationAlgorithmED25519EdDSASHA512Raw, "ed25519_eddsa_sha512_raw"},
	{AuthenticationAlgorithmED448EdDSASHA512Raw, "ed448_eddsa_sha512_raw"},
}

// ParseAuthenticationAlgorithm maps a registry name to its typed value.
func ParseAuthenticationAlgorithm(name string) (AuthenticationAlgorithm, bool) {
	return parseValue(name, authenticationAlgorithms)
}

// Name returns algorithm's case-sensitive Registry 2.3 name.
func (algorithm AuthenticationAlgorithm) Name() (string, bool) {
	return valueName(algorithm, authenticationAlgorithms)
}

// Registered reports whether algorithm is assigned by Registry 2.3.
func (algorithm AuthenticationAlgorithm) Registered() bool {
	_, ok := algorithm.Name()

	return ok
}

// PublicKeyEncoding is a FIDO public-key representation format identifier.
type PublicKeyEncoding uint16

const (
	PublicKeyEncodingECCX962Raw PublicKeyEncoding = 0x0100
	PublicKeyEncodingECCX962DER PublicKeyEncoding = 0x0101
	PublicKeyEncodingRSA2048Raw PublicKeyEncoding = 0x0102
	PublicKeyEncodingRSA2048DER PublicKeyEncoding = 0x0103
	PublicKeyEncodingCOSE       PublicKeyEncoding = 0x0104
)

var publicKeyEncodings = []namedValue[PublicKeyEncoding]{
	{PublicKeyEncodingECCX962Raw, "ecc_x962_raw"},
	{PublicKeyEncodingECCX962DER, "ecc_x962_der"},
	{PublicKeyEncodingRSA2048Raw, "rsa_2048_raw"},
	{PublicKeyEncodingRSA2048DER, "rsa_2048_der"},
	{PublicKeyEncodingCOSE, "cose"},
}

// ParsePublicKeyEncoding maps a registry name to its typed value.
func ParsePublicKeyEncoding(name string) (PublicKeyEncoding, bool) {
	return parseValue(name, publicKeyEncodings)
}

// Name returns encoding's case-sensitive Registry 2.3 name.
func (encoding PublicKeyEncoding) Name() (string, bool) {
	return valueName(encoding, publicKeyEncodings)
}

// Registered reports whether encoding is assigned by Registry 2.3.
func (encoding PublicKeyEncoding) Registered() bool {
	_, ok := encoding.Name()

	return ok
}

// AttestationType is a FIDO authenticator-attestation type identifier.
type AttestationType uint16

const (
	AttestationTypeBasicFull      AttestationType = 0x3e07
	AttestationTypeBasicSurrogate AttestationType = 0x3e08
	AttestationTypeECDAA          AttestationType = 0x3e09
	AttestationTypeAttCA          AttestationType = 0x3e0a
	AttestationTypeNone           AttestationType = 0x3e0b
	AttestationTypeAnonCA         AttestationType = 0x3e0c
)

var attestationTypes = []namedValue[AttestationType]{
	{AttestationTypeBasicFull, "basic_full"},
	{AttestationTypeBasicSurrogate, "basic_surrogate"},
	{AttestationTypeECDAA, "ecdaa"},
	{AttestationTypeAttCA, "attca"},
	{AttestationTypeAnonCA, "anonca"},
	{AttestationTypeNone, "none"},
}

// ParseAttestationType maps a registry name to its typed value.
func ParseAttestationType(name string) (AttestationType, bool) {
	return parseValue(name, attestationTypes)
}

// Name returns attestationType's case-sensitive Registry 2.3 name.
func (attestationType AttestationType) Name() (string, bool) {
	return valueName(attestationType, attestationTypes)
}

// Registered reports whether attestationType is assigned by Registry 2.3.
func (attestationType AttestationType) Registered() bool {
	_, ok := attestationType.Name()

	return ok
}

// UserVerificationMethod is a bit mask of registered user-verification
// methods.
type UserVerificationMethod uint32

const (
	UserVerificationPresenceInternal    UserVerificationMethod = 0x00000001
	UserVerificationFingerprintInternal UserVerificationMethod = 0x00000002
	UserVerificationPasscodeInternal    UserVerificationMethod = 0x00000004
	UserVerificationVoiceprintInternal  UserVerificationMethod = 0x00000008
	UserVerificationFaceprintInternal   UserVerificationMethod = 0x00000010
	UserVerificationLocationInternal    UserVerificationMethod = 0x00000020
	UserVerificationEyeprintInternal    UserVerificationMethod = 0x00000040
	UserVerificationPatternInternal     UserVerificationMethod = 0x00000080
	UserVerificationHandprintInternal   UserVerificationMethod = 0x00000100
	UserVerificationNone                UserVerificationMethod = 0x00000200
	UserVerificationAll                 UserVerificationMethod = 0x00000400
	UserVerificationPasscodeExternal    UserVerificationMethod = 0x00000800
	UserVerificationPatternExternal     UserVerificationMethod = 0x00001000
)

const registeredUserVerificationMethods = UserVerificationPresenceInternal |
	UserVerificationFingerprintInternal |
	UserVerificationPasscodeInternal |
	UserVerificationVoiceprintInternal |
	UserVerificationFaceprintInternal |
	UserVerificationLocationInternal |
	UserVerificationEyeprintInternal |
	UserVerificationPatternInternal |
	UserVerificationHandprintInternal |
	UserVerificationNone |
	UserVerificationAll |
	UserVerificationPasscodeExternal |
	UserVerificationPatternExternal

var userVerificationMethods = []namedMask[UserVerificationMethod]{
	{UserVerificationPresenceInternal, "presence_internal"},
	{UserVerificationFingerprintInternal, "fingerprint_internal"},
	{UserVerificationPasscodeInternal, "passcode_internal"},
	{UserVerificationVoiceprintInternal, "voiceprint_internal"},
	{UserVerificationFaceprintInternal, "faceprint_internal"},
	{UserVerificationLocationInternal, "location_internal"},
	{UserVerificationEyeprintInternal, "eyeprint_internal"},
	{UserVerificationPatternInternal, "pattern_internal"},
	{UserVerificationHandprintInternal, "handprint_internal"},
	{UserVerificationNone, "none"},
	{UserVerificationAll, "all"},
	{UserVerificationPasscodeExternal, "passcode_external"},
	{UserVerificationPatternExternal, "pattern_external"},
}

// ParseUserVerificationMethod maps one registry name to its bit value.
func ParseUserVerificationMethod(name string) (UserVerificationMethod, bool) {
	return parseMaskValue(name, userVerificationMethods)
}

// ParseUserVerificationMethods maps distinct registry names to a bit mask.
func ParseUserVerificationMethods(names []string) (UserVerificationMethod, bool) {
	return parseMask(names, userVerificationMethods)
}

// Registered reports whether methods contains only Registry 2.3 bits. The
// zero value is registered because it denotes an empty set of methods.
func (methods UserVerificationMethod) Registered() bool {
	return methods&^registeredUserVerificationMethods == 0
}

// ValidMetadata reports whether methods is one base user-verification method
// permitted in a Metadata Statement VerificationMethodDescriptor.
func (methods UserVerificationMethod) ValidMetadata() bool {
	return methods.Registered() &&
		methods != 0 &&
		methods != UserVerificationAll &&
		methods&(methods-1) == 0
}

// Names returns the registered names in ascending bit order.
func (methods UserVerificationMethod) Names() ([]string, bool) {
	return maskNames(methods, userVerificationMethods, UserVerificationMethod.Registered)
}

// String returns registered names in ascending bit order, separated by
// commas. Reserved bits are preserved as a hexadecimal suffix.
func (methods UserVerificationMethod) String() string {
	if methods == 0 {
		return ""
	}

	parts := make([]string, 0, len(userVerificationMethods)+1)
	for _, named := range userVerificationMethods {
		if methods&named.value != 0 {
			parts = append(parts, named.name)
		}
	}

	if unknown := methods &^ registeredUserVerificationMethods; unknown != 0 {
		parts = append(parts, fmt.Sprintf("unknown(0x%x)", uint32(unknown)))
	}

	return strings.Join(parts, ",")
}

// KeyProtection is a bit mask of registered key-protection methods.
type KeyProtection uint16

const (
	KeyProtectionSoftware      KeyProtection = 0x0001
	KeyProtectionHardware      KeyProtection = 0x0002
	KeyProtectionTEE           KeyProtection = 0x0004
	KeyProtectionSecureElement KeyProtection = 0x0008
	KeyProtectionRemoteHandle  KeyProtection = 0x0010
	KeyProtectionSyncFabric    KeyProtection = 0x0020
)

const registeredKeyProtections = KeyProtectionSoftware |
	KeyProtectionHardware |
	KeyProtectionTEE |
	KeyProtectionSecureElement |
	KeyProtectionRemoteHandle |
	KeyProtectionSyncFabric

var keyProtections = []namedMask[KeyProtection]{
	{KeyProtectionSoftware, "software"},
	{KeyProtectionHardware, "hardware"},
	{KeyProtectionTEE, "tee"},
	{KeyProtectionSecureElement, "secure_element"},
	{KeyProtectionRemoteHandle, "remote_handle"},
	{KeyProtectionSyncFabric, "sync_fabric"},
}

// ParseKeyProtection maps one registry name to its bit value.
func ParseKeyProtection(name string) (KeyProtection, bool) {
	return parseMaskValue(name, keyProtections)
}

// ParseKeyProtections maps distinct registry names to a bit mask.
func ParseKeyProtections(names []string) (KeyProtection, bool) {
	return parseMask(names, keyProtections)
}

// Registered reports whether protection contains only Registry 2.3 bits. The
// zero value is registered because it denotes an empty set of protections.
func (protection KeyProtection) Registered() bool {
	return protection&^registeredKeyProtections == 0
}

// ValidMetadata reports whether protection obeys the Registry 2.3 rules for
// an authenticator Metadata Statement.
func (protection KeyProtection) ValidMetadata() bool {
	if protection == 0 || !protection.Registered() {
		return false
	}
	if protection&KeyProtectionSoftware != 0 &&
		protection&(KeyProtectionHardware|KeyProtectionTEE|KeyProtectionSecureElement) != 0 {
		return false
	}
	if protection&KeyProtectionTEE != 0 && protection&KeyProtectionSecureElement != 0 {
		return false
	}

	const localWrappingProtection = KeyProtectionSoftware |
		KeyProtectionHardware |
		KeyProtectionTEE |
		KeyProtectionSecureElement

	return protection&KeyProtectionRemoteHandle == 0 || protection&localWrappingProtection != 0
}

// Names returns the registered names in ascending bit order.
func (protection KeyProtection) Names() ([]string, bool) {
	return maskNames(protection, keyProtections, KeyProtection.Registered)
}

// MatcherProtection is a bit mask of registered matcher-protection methods.
type MatcherProtection uint16

const (
	MatcherProtectionSoftware MatcherProtection = 0x0001
	MatcherProtectionTEE      MatcherProtection = 0x0002
	MatcherProtectionOnChip   MatcherProtection = 0x0004
)

const registeredMatcherProtections = MatcherProtectionSoftware |
	MatcherProtectionTEE |
	MatcherProtectionOnChip

var matcherProtections = []namedMask[MatcherProtection]{
	{MatcherProtectionSoftware, "software"},
	{MatcherProtectionTEE, "tee"},
	{MatcherProtectionOnChip, "on_chip"},
}

// ParseMatcherProtection maps one registry name to its bit value.
func ParseMatcherProtection(name string) (MatcherProtection, bool) {
	return parseMaskValue(name, matcherProtections)
}

// ParseMatcherProtections maps distinct registry names to a bit mask.
func ParseMatcherProtections(names []string) (MatcherProtection, bool) {
	return parseMask(names, matcherProtections)
}

// Registered reports whether protection contains only Registry 2.3 bits. The
// zero value is registered because it denotes an empty set of protections.
func (protection MatcherProtection) Registered() bool {
	return protection&^registeredMatcherProtections == 0
}

// ValidMetadata reports whether protection is one matcher-protection method
// permitted in authenticator metadata.
func (protection MatcherProtection) ValidMetadata() bool {
	return protection != 0 &&
		protection.Registered() &&
		protection&(protection-1) == 0
}

// Names returns the registered names in ascending bit order.
func (protection MatcherProtection) Names() ([]string, bool) {
	return maskNames(protection, matcherProtections, MatcherProtection.Registered)
}

// AttachmentHint is a bit mask of registered authenticator attachment hints.
type AttachmentHint uint32

const (
	AttachmentHintInternal   AttachmentHint = 0x0001
	AttachmentHintExternal   AttachmentHint = 0x0002
	AttachmentHintWired      AttachmentHint = 0x0004
	AttachmentHintWireless   AttachmentHint = 0x0008
	AttachmentHintNFC        AttachmentHint = 0x0010
	AttachmentHintBluetooth  AttachmentHint = 0x0020
	AttachmentHintNetwork    AttachmentHint = 0x0040
	AttachmentHintReady      AttachmentHint = 0x0080
	AttachmentHintWiFiDirect AttachmentHint = 0x0100
	AttachmentHintSmartCard  AttachmentHint = 0x0200
)

const registeredAttachmentHints = AttachmentHintInternal |
	AttachmentHintExternal |
	AttachmentHintWired |
	AttachmentHintWireless |
	AttachmentHintNFC |
	AttachmentHintBluetooth |
	AttachmentHintNetwork |
	AttachmentHintReady |
	AttachmentHintWiFiDirect |
	AttachmentHintSmartCard

var attachmentHints = []namedMask[AttachmentHint]{
	{AttachmentHintInternal, "internal"},
	{AttachmentHintExternal, "external"},
	{AttachmentHintWired, "wired"},
	{AttachmentHintWireless, "wireless"},
	{AttachmentHintNFC, "nfc"},
	{AttachmentHintBluetooth, "bluetooth"},
	{AttachmentHintNetwork, "network"},
	{AttachmentHintReady, "ready"},
	{AttachmentHintWiFiDirect, "wifi_direct"},
	{AttachmentHintSmartCard, "smart-card"},
}

// ParseAttachmentHint maps one registry name to its bit value.
func ParseAttachmentHint(name string) (AttachmentHint, bool) {
	return parseMaskValue(name, attachmentHints)
}

// ParseAttachmentHints maps distinct registry names to a bit mask.
func ParseAttachmentHints(names []string) (AttachmentHint, bool) {
	return parseMask(names, attachmentHints)
}

// Registered reports whether hints contains only Registry 2.3 bits. The zero
// value is registered because it denotes an empty set of hints.
func (hints AttachmentHint) Registered() bool {
	return hints&^registeredAttachmentHints == 0
}

// ValidMetadata reports whether hints obeys the Registry 2.3 rules for an
// authenticator Metadata Statement.
func (hints AttachmentHint) ValidMetadata() bool {
	if hints == 0 || !hints.Registered() {
		return false
	}
	if hints&AttachmentHintInternal != 0 {
		return hints == AttachmentHintInternal
	}

	return hints&AttachmentHintExternal == 0 || hints != AttachmentHintExternal
}

// Names returns the registered names in ascending bit order.
func (hints AttachmentHint) Names() ([]string, bool) {
	return maskNames(hints, attachmentHints, AttachmentHint.Registered)
}

// TransactionConfirmationDisplay is a bit mask of registered transaction
// confirmation display capabilities.
type TransactionConfirmationDisplay uint16

const (
	TransactionConfirmationDisplayAny                TransactionConfirmationDisplay = 0x0001
	TransactionConfirmationDisplayPrivilegedSoftware TransactionConfirmationDisplay = 0x0002
	TransactionConfirmationDisplayTEE                TransactionConfirmationDisplay = 0x0004
	TransactionConfirmationDisplayHardware           TransactionConfirmationDisplay = 0x0008
	TransactionConfirmationDisplayRemote             TransactionConfirmationDisplay = 0x0010
)

const transactionConfirmationDisplayImplementations = TransactionConfirmationDisplayPrivilegedSoftware |
	TransactionConfirmationDisplayTEE |
	TransactionConfirmationDisplayHardware

const registeredTransactionConfirmationDisplays = TransactionConfirmationDisplayAny |
	transactionConfirmationDisplayImplementations |
	TransactionConfirmationDisplayRemote

var transactionConfirmationDisplays = []namedMask[TransactionConfirmationDisplay]{
	{TransactionConfirmationDisplayAny, "any"},
	{TransactionConfirmationDisplayPrivilegedSoftware, "privileged_software"},
	{TransactionConfirmationDisplayTEE, "tee"},
	{TransactionConfirmationDisplayHardware, "hardware"},
	{TransactionConfirmationDisplayRemote, "remote"},
}

// ParseTransactionConfirmationDisplay maps one registry name to its bit value.
func ParseTransactionConfirmationDisplay(name string) (TransactionConfirmationDisplay, bool) {
	return parseMaskValue(name, transactionConfirmationDisplays)
}

// ParseTransactionConfirmationDisplays maps distinct registry names to a bit
// mask.
func ParseTransactionConfirmationDisplays(names []string) (TransactionConfirmationDisplay, bool) {
	return parseMask(names, transactionConfirmationDisplays)
}

// Registered reports whether display contains only Registry 2.3 bits. The
// zero value is registered because it denotes an empty set of capabilities.
func (display TransactionConfirmationDisplay) Registered() bool {
	return display&^registeredTransactionConfirmationDisplays == 0
}

// ValidMetadata reports whether display obeys the Registry 2.3 rules for an
// authenticator Metadata Statement. Zero is valid and means unsupported.
func (display TransactionConfirmationDisplay) ValidMetadata() bool {
	if !display.Registered() {
		return false
	}
	if display == 0 {
		return true
	}
	if display&TransactionConfirmationDisplayAny == 0 {
		return false
	}

	implementation := display & transactionConfirmationDisplayImplementations

	return implementation&(implementation-1) == 0
}

// Names returns the registered names in ascending bit order.
func (display TransactionConfirmationDisplay) Names() ([]string, bool) {
	return maskNames(display, transactionConfirmationDisplays, TransactionConfirmationDisplay.Registered)
}

type namedValue[T comparable] struct {
	value T
	name  string
}

func parseValue[T comparable](name string, values []namedValue[T]) (T, bool) {
	for _, named := range values {
		if name == named.name {
			return named.value, true
		}
	}

	var zero T

	return zero, false
}

func valueName[T comparable](value T, values []namedValue[T]) (string, bool) {
	for _, named := range values {
		if value == named.value {
			return named.name, true
		}
	}

	return "", false
}

type mask interface {
	~uint16 | ~uint32
}

type namedMask[T mask] struct {
	value T
	name  string
}

func parseMaskValue[T mask](name string, values []namedMask[T]) (T, bool) {
	for _, named := range values {
		if name == named.name {
			return named.value, true
		}
	}

	return 0, false
}

func parseMask[T mask](names []string, values []namedMask[T]) (T, bool) {
	var result T
	for _, name := range names {
		value, ok := parseMaskValue(name, values)
		if !ok || result&value != 0 {
			return 0, false
		}

		result |= value
	}

	return result, true
}

func maskNames[T mask](value T, values []namedMask[T], valid func(T) bool) ([]string, bool) {
	if !valid(value) {
		return nil, false
	}

	names := make([]string, 0, len(values))
	for _, named := range values {
		if value&named.value != 0 {
			names = append(names, named.name)
		}
	}

	return names, true
}
