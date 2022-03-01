---
apiVersion: api.cerbos.dev/v1
variables:
  pending_approval: ("PENDING_APPROVAL")
  principal_location: |-
    (P.attr.ip_address.inIPAddrRange("10.20.0.0/16") ? "GB" : "")
resourcePolicy:
  resource: {{ .NameMod "leave_request" }}
  version: "default"
  scope: "acme.hr.uk"
  importDerivedRoles:
    - {{ .NameMod "alpha" }}
    - {{ .NameMod "beta" }}
  rules:
    - actions: ["delete"]
      condition:
        match:
          expr: request.resource.attr.geography == variables.principal_location
      derivedRoles:
        - direct_manager
        - employee_that_owns_the_record
      effect: EFFECT_ALLOW

    - actions: ["defer"]
      effect: EFFECT_ALLOW
      derivedRoles:
        - direct_manager
        - employee_that_owns_the_record
