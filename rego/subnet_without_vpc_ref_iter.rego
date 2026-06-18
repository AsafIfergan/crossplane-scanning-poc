package wiz

import data.generic.crossplane as cp_lib

# DEMO: iterator-based equivalent of subnet_without_vpc_ref_walk.rego.
#
# The Subnet kind is shared with Azure's network.azure.upbound.io VNet Subnets,
# so an apiVersion prefix check is needed to scope to AWS EC2. The "ec2.aws."
# prefix matches both ec2.aws.crossplane.io/ (legacy) and ec2.aws.upbound.io/
# (Upbound), so a single isAWSSubnet predicate covers both families.
#
# vpcExists also uses the iterator now — covers standalone and composed VPCs in
# one body.

WizPolicy[result] {
	doc := input.document[i]
	r := cp_lib.getResources(doc)[_]
	resource := r.resource
	isAWSSubnet(resource)
	spec := cp_lib.mergedSpec(resource)
	vpcRefName := spec.vpcIdRef.name

	not vpcExists(vpcRefName)
	section := cp_lib.fieldLocation(resource, "vpcIdRef")

	result := {
		"documentId": doc.id,
		"resourceType": "Subnet",
		"resourceName": resource.metadata.name,
		"searchKey": cp_lib.getPath(r.walkPath, section, "vpcIdRef.name"),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("referenced VPC '%s' should exist in the same file", [vpcRefName]),
		"keyActualValue": sprintf("referenced VPC '%s' is not defined in the same file", [vpcRefName]),
	}
}

# --- Local predicates ---

isAWSSubnet(resource) {
	resource.kind == "Subnet"
	startswith(resource.apiVersion, "ec2.aws.")
}

isAWSVPC(resource) {
	resource.kind == "VPC"
	startswith(resource.apiVersion, "ec2.aws.")
}

# vpcExists: iterate every doc in the file and ask getResources for its
# managed resources. Returns true if any matching AWS VPC has the requested
# name — covers standalone and composed alike via the iterator.
vpcExists(name) {
	doc := input.document[_]
	r := cp_lib.getResources(doc)[_]
	isAWSVPC(r.resource)
	r.resource.metadata.name == name
}
