// Code generated by protoc-gen-go-hashpb. DO NOT EDIT.
// protoc-gen-go-hashpb v0.3.7
// Source: cerbos/telemetry/v1/telemetry.proto

package telemetryv1

import (
	hash "hash"
)

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerLaunch) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerLaunch_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerLaunch_Cerbos) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerLaunch_Cerbos_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerLaunch_Source) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerLaunch_Source_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerLaunch_Features) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerLaunch_Features_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerLaunch_Features_Audit) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerLaunch_Features_Audit_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerLaunch_Features_Schema) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerLaunch_Features_Schema_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerLaunch_Features_AdminApi) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerLaunch_Features_AdminApi_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerLaunch_Features_Storage) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerLaunch_Features_Storage_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerLaunch_Features_Storage_Disk) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerLaunch_Features_Storage_Disk_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerLaunch_Features_Storage_Git) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerLaunch_Features_Storage_Git_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerLaunch_Features_Storage_Blob) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerLaunch_Features_Storage_Blob_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerLaunch_Features_Storage_Bundle) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerLaunch_Features_Storage_Bundle_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerLaunch_Stats) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerLaunch_Stats_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerLaunch_Stats_Policy) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerLaunch_Stats_Policy_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerLaunch_Stats_Schema) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerLaunch_Stats_Schema_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerStop) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_ServerStop_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Event) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_Event_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Event_CountStat) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_Event_CountStat_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Event_ApiActivity) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_telemetry_v1_Event_ApiActivity_hashpb_sum(m, hasher, ignore)
	}
}
