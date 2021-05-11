// Copyright 2021 Zenauth Ltd.

package svc

import (
	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	"github.com/cerbos/cerbos/internal/util"
)

func ExtractRequestFields(fullMethod string, req interface{}) map[string]interface{} {
	if req == nil {
		return nil
	}

	switch fullMethod {
	case "/svc.v1.CerbosService/CheckResourceSet":
		crsReq, ok := req.(*requestv1.CheckResourceSetRequest)
		if !ok {
			return nil
		}

		return map[string]interface{}{
			util.AppName: map[string]string{
				"request.id":               crsReq.RequestId,
				"principal.id":             crsReq.Principal.Id,
				"principal.policy_version": crsReq.Principal.PolicyVersion,
			},
		}

	case "/svc.v1.CerbosService/CheckResourceBatch":
		crbReq, ok := req.(*requestv1.CheckResourceBatchRequest)
		if !ok {
			return nil
		}

		return map[string]interface{}{
			util.AppName: map[string]string{
				"request.id":               crbReq.RequestId,
				"principal.id":             crbReq.Principal.Id,
				"principal.policy_version": crbReq.Principal.PolicyVersion,
			},
		}
	default:
		return nil
	}
}
