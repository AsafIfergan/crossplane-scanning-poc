package wiz

import data.generic.common as common_lib
import data.generic.crossplane as cp_lib

# The field path (spec.forProvider.storageEncrypted) is identical for both the
# legacy crossplane-contrib RDSInstance and the Upbound provider-aws-rds Instance,
# so one block per shape (standalone, composed) covers both families. The
# isAWSRDSDatabase predicate enumerates which kinds count as "an AWS RDS database."

# Standalone — either family
WizPolicy[result] {
	doc := input.document[i]
	isAWSRDSDatabase(doc)
	spec := cp_lib.mergedSpec(doc)
	storageEncryptedNotTrue(spec)
	section := cp_lib.fieldLocation(doc, "storageEncrypted")

	result := {
		"documentId": doc.id,
		"resourceType": doc.kind,
		"resourceName": doc.metadata.name,
		"searchKey": sprintf("spec.%s.storageEncrypted", [section]),
		"issueType": rdsIssueType(spec),
		"keyExpectedValue": "storageEncrypted should be defined and set to true",
		"keyActualValue": rdsActualValue(spec),
	}
}

# Composed — either family
WizPolicy[result] {
	doc := input.document[i]
	doc.kind == "Composition"
	base := doc.spec.resources[j].base
	isAWSRDSDatabase(base)
	spec := cp_lib.mergedSpec(base)
	storageEncryptedNotTrue(spec)
	section := cp_lib.fieldLocation(base, "storageEncrypted")

	result := {
		"documentId": doc.id,
		"resourceType": base.kind,
		"resourceName": base.metadata.name,
		"searchKey": sprintf("spec.resources[%d].base.spec.%s.storageEncrypted", [j, section]),
		"issueType": rdsIssueType(spec),
		"keyExpectedValue": "storageEncrypted should be defined and set to true",
		"keyActualValue": rdsActualValue(spec),
	}
}

# --- Local predicates ---

# isAWSRDSDatabase matches the AWS RDS database resource in either provider family.
# Legacy: kind "RDSInstance" is unique to crossplane-contrib/provider-aws.
# Upbound: kind "Instance" collides with EC2 / GCP Compute — apiVersion narrows it.
isAWSRDSDatabase(r) {
	r.kind == "RDSInstance"
}{
	r.kind == "Instance"
	startswith(r.apiVersion, "rds.aws.upbound.io/")
}

# storageEncryptedNotTrue fires when the field is missing or explicitly false.
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
