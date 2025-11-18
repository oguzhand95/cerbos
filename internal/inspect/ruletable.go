// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"fmt"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/ruletable"
)

// RuleTables inspects the given rule table, caches the inspection related information in a struct and returns it.
func RuleTables(ruleTable *ruletable.RuleTable) (*RuleTable, error) {
	rt := &RuleTable{
		results: make(map[string]*responsev1.InspectPoliciesResponse_Result),
	}

	if err := rt.inspect(ruleTable); err != nil {
		return nil, err
	}

	return rt, nil
}

type RuleTable struct {
	results map[string]*responsev1.InspectPoliciesResponse_Result
}

func (rt *RuleTable) inspect(ruleTable *ruletable.RuleTable) error {
	if ruleTable == nil {
		return fmt.Errorf("rule table is nil")
	}

	return nil
}

// Results returns the final inspection results.
func (rt *RuleTable) Results() (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	return rt.results, nil
}
