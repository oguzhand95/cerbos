// Code generated by protoc-gen-go-hashpb. DO NOT EDIT.
// protoc-gen-go-hashpb v0.4.2
// Source: cerbos/schema/v1/schema.proto

package schemav1

import (
	hash "hash"
)

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ValidationError) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_schema_v1_ValidationError_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Schema) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_schema_v1_Schema_hashpb_sum(m, hasher, ignore)
	}
}
