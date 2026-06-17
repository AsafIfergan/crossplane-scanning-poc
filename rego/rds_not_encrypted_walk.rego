package wiz

import data.generic.common as common_lib
import data.generic.crossplane as cp_lib

# DEMO of the walk-based one-block pattern. Equivalent in behavior to
# rds_not_encrypted.rego (which uses the two-block standalone+composed pattern)
# but collapses both shapes into a single WizPolicy block via walk + getPath.
#
# To compare: run wiz_eval_crossplane against every fixture in
# testdata/rds_not_encrypted/{pass,fail}/* with each rule file; verdicts and
# searchKeys must match across the board.

WizPolicy[result] {
	doc := input.document[i]
	walk(doc, [path, value])
	isAWSRDSDatabase(value)
	spec := cp_lib.mergedSpec(value)
	storageEncryptedNotTrue(spec)
	section := cp_lib.fieldLocation(value, "storageEncrypted")

	result := {
		"documentId": doc.id,
		"resourceType": value.kind,
		"resourceName": value.metadata.name,
		"searchKey": cp_lib.specPath(path, section, "storageEncrypted"),
		"issueType": rdsIssueType(spec),
		"keyExpectedValue": "storageEncrypted should be defined and set to true",
		"keyActualValue": rdsActualValue(spec),
	}
}

# --- Local predicates (unchanged from the two-block version) ---

isAWSRDSDatabase(r) {
	r.kind == "RDSInstance"
}{
	r.kind == "Instance"
	startswith(r.apiVersion, "rds.aws.upbound.io/")
}

storageEncryptedNotTrue(spec) {
	not common_lib.valid_key(spec, "storageEncrypted")
}{
	spec.storageEncrypted == false
}

rdsIssueType(spec) = "MissingAttribute" {
	not common_lib.valid_key(spec, "storageEncrypted")
} else = "IncorrectValue" {
	true
}

rdsActualValue(spec) = "storageEncrypted is not defined" {
	not common_lib.valid_key(spec, "storageEncrypted")
} else = "storageEncrypted is set to false" {
	true
}
