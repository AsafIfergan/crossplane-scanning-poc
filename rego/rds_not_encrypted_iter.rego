package wiz

import data.generic.common as common_lib
import data.generic.crossplane as cp_lib

# DEMO of the iterator-based rule pattern (uses cp_lib.getResources).
# Equivalent in behavior to rds_not_encrypted_walk.rego (which uses walk()).
# The iterator yields exactly the right candidates — standalone resources or
# composed resources from Composition.spec.resources[].base — without surfacing
# every subtree of the input.
#
# Compare to the walk version: rule body is structurally identical, except:
#   walk(doc, [path, value]) + isAWSX(value)
#       becomes
#   doc := input.document[i]
#   r := cp_lib.getResources(doc)[_]
#   resource := r.resource
#   isAWSX(resource)

# Block 1 — storageEncrypted is missing entirely (MissingAttribute).
WizPolicy[result] {
	doc := input.document[i]
	r := cp_lib.getResources(doc)[_]
	resource := r.resource
	isAWSRDSDatabase(resource)
	spec := cp_lib.mergedSpec(resource)
	not common_lib.valid_key(spec, "storageEncrypted")
	section := cp_lib.fieldLocation(resource, "storageEncrypted")

	result := {
		"documentId": doc.id,
		"resourceType": resource.kind,
		"resourceName": resource.metadata.name,
		"searchKey": cp_lib.getPath(r.walkPath, section, ""),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "storageEncrypted should be defined and set to true",
		"keyActualValue": "storageEncrypted is not defined",
	}
}

# Block 2 — storageEncrypted is present but explicitly false (IncorrectValue).
# Mutually exclusive with Block 1 via the valid_key check.
WizPolicy[result] {
	doc := input.document[i]
	r := cp_lib.getResources(doc)[_]
	resource := r.resource
	isAWSRDSDatabase(resource)
	spec := cp_lib.mergedSpec(resource)
	common_lib.valid_key(spec, "storageEncrypted")
	spec.storageEncrypted == false
	section := cp_lib.fieldLocation(resource, "storageEncrypted")

	result := {
		"documentId": doc.id,
		"resourceType": resource.kind,
		"resourceName": resource.metadata.name,
		"searchKey": cp_lib.getPath(r.walkPath, section, "storageEncrypted"),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "storageEncrypted should be set to true",
		"keyActualValue": "storageEncrypted is set to false",
	}
}

# --- Local predicates ---

# isAWSRDSDatabase matches the AWS RDS database resource in either provider family.
# Legacy: kind "RDSInstance" is unique to crossplane-contrib/provider-aws.
# Upbound: kind "Instance" collides with EC2 — apiVersion narrows it.
isAWSRDSDatabase(resource) {
	resource.kind == "RDSInstance"
}{
	resource.kind == "Instance"
	startswith(resource.apiVersion, "rds.aws.upbound.io/")
}
