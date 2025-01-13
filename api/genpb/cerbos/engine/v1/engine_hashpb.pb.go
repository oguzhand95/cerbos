// Code generated by protoc-gen-go-hashpb. Do not edit.
// protoc-gen-go-hashpb v0.3.5
// Source: cerbos/engine/v1/engine.proto

package enginev1

import (
	hash "hash"
)

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlanResourcesInput) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_PlanResourcesInput_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlanResourcesInput_Resource) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_PlanResourcesInput_Resource_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlanResourcesAst) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_PlanResourcesAst_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlanResourcesAst_Node) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_PlanResourcesAst_Node_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlanResourcesAst_LogicalOperation) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_PlanResourcesAst_LogicalOperation_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlanResourcesFilter) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_PlanResourcesFilter_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlanResourcesFilter_Expression) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_PlanResourcesFilter_Expression_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlanResourcesFilter_Expression_Operand) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_PlanResourcesFilter_Expression_Operand_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlanResourcesOutput) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_PlanResourcesOutput_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CheckInput) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_CheckInput_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CheckOutput) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_CheckOutput_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CheckOutput_ActionEffect) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_CheckOutput_ActionEffect_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *OutputEntry) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_OutputEntry_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Resource) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_Resource_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Principal) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_Principal_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *AuxData) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_AuxData_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Trace) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_Trace_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Trace_Component) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_Trace_Component_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Trace_Component_Variable) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_Trace_Component_Variable_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Trace_Event) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_Trace_Event_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Request) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_Request_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Request_Principal) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_Request_Principal_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Request_Resource) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_Request_Resource_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Runtime) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_engine_v1_Runtime_hashpb_sum(m, hasher, ignore)
	}
}
