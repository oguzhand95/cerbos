---
apiVersion: api.cerbos.dev/v1
variables:
  pending_approval: ("PENDING_APPROVAL")
  principal_location: |-
    (P.attr.ip_address.inIPAddrRange("10.20.0.0/16") ? "GB" : "")
resourcePolicy:
  resource: {{ .NameMod "leave_request" }}
  version: "default"
  scope: "acme.hr"
  importDerivedRoles:
    - {{ .NameMod "alpha" }}
    - {{ .NameMod "beta" }}
  rules:
    - actions: ["view:*"]
      derivedRoles:
        - employee_that_owns_the_record
        - direct_manager
      effect: EFFECT_ALLOW

    - actions: ["delete"]
      condition:
        match:
          expr: request.resource.attr.geography == variables.principal_location
      derivedRoles:
        - direct_manager
      effect: EFFECT_ALLOW

    - actions: ["approve"]
      condition:
        match:
          expr: request.resource.attr.status == V.pending_approval
      derivedRoles:
        - direct_manager
      effect: EFFECT_ALLOW

    - actions: ["defer"]
      effect: EFFECT_ALLOW
      roles: ["employee"]
      condition:
        match:
          all:
            of:
              - expr: '"cerbos-jwt-tests" in request.aux_data.jwt.aud'
              - expr: '"A" in request.aux_data.jwt.customArray'
