---
apiVersion: "api.cerbos.dev/v1"
variables:
  is_dev_record: request.resource.attr.dev_record == true
principalPolicy:
  principal: {{ .NameMod "donald_duck" }}
  version: "20210210"
  rules:
    - resource: leave_request
      actions:
        - action: "*"
          condition:
            match:
              expr: variables.is_dev_record
          effect: EFFECT_ALLOW
          name: dev_admin

    - resource: salary_record
      actions:
        - action: "*"
          effect: EFFECT_DENY
