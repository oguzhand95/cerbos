---
apiVersion: "api.cerbos.dev/v1"
derivedRoles:
  name: {{ .NameMod "alpha" }}
  definitions:
    - name: admin
      parentRoles: ["admin"]

    - name: tester
      parentRoles: ["dev", "qa"]

    - name: employee_that_owns_the_record
      parentRoles: ["employee"]
      condition:
        match:
          expr: R.attr.owner == P.id
