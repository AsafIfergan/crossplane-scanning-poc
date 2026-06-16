package wiz

import data.generic.crossplane as cp_lib

# Subnet kind is shared with Azure's network.azure.upbound.io VNet Subnets,
# so an apiVersion prefix check is needed to scope to AWS EC2. The "ec2.aws."
# prefix matches both ec2.aws.crossplane.io/ (legacy) and ec2.aws.upbound.io/
# (Upbound), so one set of blocks covers both families.
#
# VPC existence is checked within the same file (the scanner's document
# boundary). Iterating input.document[_] is within-file because the engine
# evaluates one file at a time.

# Standalone Subnet
WizPolicy[result] {
	doc := input.document[i]
	isAWSSubnet(doc)
	spec := cp_lib.mergedSpec(doc)
	vpcRefName := spec.vpcIdRef.name

	not vpcExists(vpcRefName)
	section := cp_lib.fieldLocation(doc, "vpcIdRef")

	result := {
		"documentId": doc.id,
		"resourceType": "Subnet",
		"resourceName": doc.metadata.name,
		"searchKey": sprintf("spec.%s.vpcIdRef.name", [section]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("referenced VPC '%s' should exist in the same file", [vpcRefName]),
		"keyActualValue": sprintf("referenced VPC '%s' is not defined in the same file", [vpcRefName]),
	}
}

# Composed Subnet (nested under a Composition wrapper)
WizPolicy[result] {
	doc := input.document[i]
	doc.kind == "Composition"
	base := doc.spec.resources[j].base
	isAWSSubnet(base)
	spec := cp_lib.mergedSpec(base)
	vpcRefName := spec.vpcIdRef.name

	not vpcExists(vpcRefName)
	section := cp_lib.fieldLocation(base, "vpcIdRef")

	result := {
		"documentId": doc.id,
		"resourceType": "Subnet",
		"resourceName": base.metadata.name,
		"searchKey": sprintf("spec.resources[%d].base.spec.%s.vpcIdRef.name", [j, section]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("referenced VPC '%s' should exist in the same file", [vpcRefName]),
		"keyActualValue": sprintf("referenced VPC '%s' is not defined in the same file", [vpcRefName]),
	}
}

# --- Local predicates ---

# isAWSSubnet matches an AWS EC2 Subnet from either provider family.
isAWSSubnet(r) {
	r.kind == "Subnet"
	startswith(r.apiVersion, "ec2.aws.")
}

# isAWSVPC matches an AWS EC2 VPC from either provider family.
isAWSVPC(r) {
	r.kind == "VPC"
	startswith(r.apiVersion, "ec2.aws.")
}

# vpcExists is true if a VPC with the given metadata.name appears anywhere in
# the same file — as a standalone doc or nested inside a Composition.
vpcExists(name) {
	doc := input.document[_]
	isAWSVPC(doc)
	doc.metadata.name == name
}{
	doc := input.document[_]
	doc.kind == "Composition"
	base := doc.spec.resources[_].base
	isAWSVPC(base)
	base.metadata.name == name
}
