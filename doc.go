// Package registry provides the numeric values, case-sensitive names, bit
// masks, and Metadata Statement combination rules from sections 3.1 through
// 3.7 of FIDO Registry of Predefined Values 2.3.
//
// Registry membership and name parsing are independent of Metadata Statement
// policy: Registered and plural Parse functions accept every registered
// bit-mask combination, while ValidMetadata applies the metadata-specific
// nonempty and combination requirements. Registry SHOULD pairings remain
// policy decisions for callers.
package registry
