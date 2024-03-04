// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"io"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/policy"
)

func ReadPolicyWithSourceContextFromReader(src io.Reader) (*policyv1.Policy, parser.SourceCtx, error) {
	return policy.ReadPolicyWithSourceContextFromReader(src)
}
