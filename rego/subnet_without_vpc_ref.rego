package crossplane.aws.subnet_without_vpc_ref

import data.generic.crossplane as cp_lib

# Detect subnets that reference a VPC which exists in the same document
# (demonstrates cross-resource correlation via associatedByRef)
deny[result] {
	subnet := input.resource.Subnet[subnetName]
	vpcRefName := subnet.spec.forProvider.vpcIdRef.name

	# Check that the referenced VPC actually exists
	not input.resource.VPC[vpcRefName]

	result := {
		"resourceType": "Subnet",
		"resourceName": cp_lib.getResourceName(subnet, subnetName),
		"severity": "MEDIUM",
		"message": sprintf("Subnet references VPC '%s' which is not defined in the scanned files", [vpcRefName]),
	}
}
