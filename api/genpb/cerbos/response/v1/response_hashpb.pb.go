// Code generated by protoc-gen-go-hashpb. DO NOT EDIT.
// protoc-gen-go-hashpb v0.3.7
// Source: cerbos/response/v1/response.proto

package responsev1

import (
	hash "hash"
)

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlanResourcesResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_PlanResourcesResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlanResourcesResponse_Meta) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_PlanResourcesResponse_Meta_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CheckResourceSetResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_CheckResourceSetResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CheckResourceSetResponse_ActionEffectMap) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_CheckResourceSetResponse_ActionEffectMap_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CheckResourceSetResponse_Meta) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_CheckResourceSetResponse_Meta_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CheckResourceSetResponse_Meta_EffectMeta) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_CheckResourceSetResponse_Meta_EffectMeta_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CheckResourceSetResponse_Meta_ActionMeta) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_CheckResourceSetResponse_Meta_ActionMeta_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CheckResourceBatchResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_CheckResourceBatchResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CheckResourceBatchResponse_ActionEffectMap) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_CheckResourceBatchResponse_ActionEffectMap_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CheckResourcesResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_CheckResourcesResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CheckResourcesResponse_ResultEntry) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_CheckResourcesResponse_ResultEntry_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CheckResourcesResponse_ResultEntry_Resource) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_CheckResourcesResponse_ResultEntry_Resource_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CheckResourcesResponse_ResultEntry_Meta) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_CheckResourcesResponse_ResultEntry_Meta_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *CheckResourcesResponse_ResultEntry_Meta_EffectMeta) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_CheckResourcesResponse_ResultEntry_Meta_EffectMeta_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlaygroundFailure) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_PlaygroundFailure_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlaygroundFailure_ErrorDetails) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_PlaygroundFailure_ErrorDetails_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlaygroundFailure_Error) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_PlaygroundFailure_Error_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlaygroundValidateResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_PlaygroundValidateResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlaygroundTestResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_PlaygroundTestResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlaygroundTestResponse_TestResults) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_PlaygroundTestResponse_TestResults_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlaygroundEvaluateResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_PlaygroundEvaluateResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlaygroundEvaluateResponse_EvalResult) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_PlaygroundEvaluateResponse_EvalResult_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlaygroundEvaluateResponse_EvalResultList) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_PlaygroundEvaluateResponse_EvalResultList_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *PlaygroundProxyResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_PlaygroundProxyResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *AddOrUpdatePolicyResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_AddOrUpdatePolicyResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ListAuditLogEntriesResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_ListAuditLogEntriesResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ServerInfoResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_ServerInfoResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ListPoliciesResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_ListPoliciesResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *GetPolicyResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_GetPolicyResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *DisablePolicyResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_DisablePolicyResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *EnablePolicyResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_EnablePolicyResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *InspectPoliciesResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_InspectPoliciesResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *InspectPoliciesResponse_Attribute) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_InspectPoliciesResponse_Attribute_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *InspectPoliciesResponse_DerivedRole) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_InspectPoliciesResponse_DerivedRole_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *InspectPoliciesResponse_Constant) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_InspectPoliciesResponse_Constant_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *InspectPoliciesResponse_Variable) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_InspectPoliciesResponse_Variable_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *InspectPoliciesResponse_Result) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_InspectPoliciesResponse_Result_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *ListSchemasResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_ListSchemasResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *GetSchemaResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_GetSchemaResponse_hashpb_sum(m, hasher, ignore)
	}
}

// HashPB computes a hash of the message using the given hash function
// The ignore set must contain fully-qualified field names (pkg.msg.field) that should be ignored from the hash
func (m *DeleteSchemaResponse) HashPB(hasher hash.Hash, ignore map[string]struct{}) {
	if m != nil {
		cerbos_response_v1_DeleteSchemaResponse_hashpb_sum(m, hasher, ignore)
	}
}
