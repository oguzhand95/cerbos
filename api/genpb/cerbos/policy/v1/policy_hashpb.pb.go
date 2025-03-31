// Code generated by protoc-gen-go-hashpb. DO NOT EDIT.
// protoc-gen-go-hashpb v0.3.7
// Source: cerbos/policy/v1/policy.proto

package policyv1

import (
	hash "hash"
)

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Policy) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_Policy_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *SourceAttributes) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_SourceAttributes_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Metadata) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_Metadata_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ResourcePolicy) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_ResourcePolicy_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ResourceRule) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_ResourceRule_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *RolePolicy) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_RolePolicy_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *RoleRule) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_RoleRule_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PrincipalPolicy) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_PrincipalPolicy_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PrincipalRule) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_PrincipalRule_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PrincipalRule_Action) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_PrincipalRule_Action_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *DerivedRoles) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_DerivedRoles_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *RoleDef) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_RoleDef_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ExportConstants) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_ExportConstants_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Constants) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_Constants_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ExportVariables) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_ExportVariables_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Variables) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_Variables_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Condition) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_Condition_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Match) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_Match_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Match_ExprList) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_Match_ExprList_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Output) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_Output_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Output_When) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_Output_When_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Schemas) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_Schemas_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Schemas_IgnoreWhen) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_Schemas_IgnoreWhen_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Schemas_Schema) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_Schemas_Schema_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestOptions) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestOptions_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestSuite) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestSuite_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestTable) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestTable_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestTable_Input) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestTable_Input_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestTable_OutputExpectations) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestTable_OutputExpectations_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestTable_Expectation) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestTable_Expectation_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Test) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_Test_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Test_TestName) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_Test_TestName_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *Test_OutputEntries) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_Test_OutputEntries_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestResults) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestResults_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestResults_Tally) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestResults_Tally_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestResults_Summary) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestResults_Summary_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestResults_Suite) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestResults_Suite_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestResults_TestCase) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestResults_TestCase_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestResults_Principal) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestResults_Principal_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestResults_Resource) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestResults_Resource_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestResults_Action) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestResults_Action_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestResults_Details) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestResults_Details_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestResults_OutputFailure) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestResults_OutputFailure_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestResults_OutputFailure_MismatchedValue) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestResults_OutputFailure_MismatchedValue_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestResults_OutputFailure_MissingValue) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestResults_OutputFailure_MissingValue_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestResults_Failure) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestResults_Failure_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *TestResults_Success) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_policy_v1_TestResults_Success_hashpb_sum(m, hasher, ignore)
	}
}
