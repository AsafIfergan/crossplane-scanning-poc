package wiz

import data.generic.crossplane as cp_lib

# DEMO: walk-based equivalent of subnet_without_vpc_ref.rego.
#
# The Subnet kind is shared with Azure's network.azure.upbound.io VNet Subnets,
# so an apiVersion prefix check is needed to scope to AWS EC2. The "ec2.aws."
# prefix matches both ec2.aws.crossplane.io/ (legacy) and ec2.aws.upbound.io/
# (Upbound), so a single isAWSSubnet predicate covers both families.
#
# vpcExists also uses walk now — covers standalone and composed VPCs in one body.

WizPolicy[result] {
	doc := input.document[i]
	walk(doc, [path, value])
	isAWSSubnet(value)
	spec := cp_lib.mergedSpec(value)
	vpcRefName := spec.vpcIdRef.name

	not vpcExists(vpcRefName)
	section := cp_lib.fieldLocation(value, "vpcIdRef")

	result := {
		"documentId": doc.id,
		"resourceType": "Subnet",
		"resourceName": value.metadata.name,
		"searchKey": sprintf("%sspec.%s.vpcIdRef.name", [cp_lib.getPath(path), section]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("referenced VPC '%s' should exist in the same file", [vpcRefName]),
		"keyActualValue": sprintf("referenced VPC '%s' is not defined in the same file", [vpcRefName]),
	}
}

# --- Local predicates ---

isAWSSubnet(r) {
	r.kind == "Subnet"
	startswith(r.apiVersion, "ec2.aws.")
}

isAWSVPC(r) {
	r.kind == "VPC"
	startswith(r.apiVersion, "ec2.aws.")
}

# vpcExists: walk any doc in the file, return true if a matching AWS VPC
# (standalone OR nested in a Composition) has the requested name.
vpcExists(name) {
	doc := input.document[_]
	walk(doc, [_, value])
	isAWSVPC(value)
	value.metadata.name == name
}
