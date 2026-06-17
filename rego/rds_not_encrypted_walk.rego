package wiz

import data.generic.common as common_lib
import data.generic.crossplane as cp_lib

# DEMO of the walk-based two-block pattern (one block per issueType, mutually
# exclusive conditions). Equivalent in behavior to the original two-block
# standalone+composed rds_not_encrypted.rego, but collapses both shapes into
# a single walk per block via getPath. Self-contained result fields, no
# helpers for issueType/keyActualValue branching.
#
# To compare: run wiz_eval_crossplane against every fixture in
# testdata/rds_not_encrypted/{pass,fail}/* with each rule file; verdicts and
# searchKeys must match across the board.

# Block 1 — storageEncrypted is missing entirely (MissingAttribute).
WizPolicy[result] {
	doc := input.document[i]
	walk(doc, [path, value])
	isAWSRDSDatabase(value)
	spec := cp_lib.mergedSpec(value)
	not common_lib.valid_key(spec, "storageEncrypted")
	section := cp_lib.fieldLocation(value, "storageEncrypted")

	result := {
		"documentId": doc.id,
		"resourceType": value.kind,
		"resourceName": value.metadata.name,
		"searchKey": cp_lib.getPath(path, section, ""),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "storageEncrypted should be defined and set to true",
		"keyActualValue": "storageEncrypted is not defined",
	}
}

# Block 2 — storageEncrypted is present but explicitly false (IncorrectValue).
# Mutually exclusive with Block 1 via the valid_key check.
WizPolicy[result] {
	doc := input.document[i]
	walk(doc, [path, value])
	isAWSRDSDatabase(value)
	spec := cp_lib.mergedSpec(value)
	common_lib.valid_key(spec, "storageEncrypted")
	spec.storageEncrypted == false
	section := cp_lib.fieldLocation(value, "storageEncrypted")

	result := {
		"documentId": doc.id,
		"resourceType": value.kind,
		"resourceName": value.metadata.name,
		"searchKey": cp_lib.getPath(path, section, "storageEncrypted"),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "storageEncrypted should be set to true",
		"keyActualValue": "storageEncrypted is set to false",
	}
}

# --- Local predicates ---

# isAWSRDSDatabase matches the AWS RDS database resource in either provider family.
# Legacy: kind "RDSInstance" is unique to crossplane-contrib/provider-aws.
# Upbound: kind "Instance" collides with EC2 — apiVersion narrows it.
isAWSRDSDatabase(r) {
	r.kind == "RDSInstance"
}{
	r.kind == "Instance"
	startswith(r.apiVersion, "rds.aws.upbound.io/")
}
