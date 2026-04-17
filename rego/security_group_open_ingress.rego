package crossplane.aws.security_group_open_ingress

import data.generic.crossplane as cp_lib

# Detect security groups with 0.0.0.0/0 ingress
deny[result] {
	resource := input.resource.SecurityGroup[name]
	rule := resource.spec.forProvider.ingress[_]
	cidr := rule.ipRanges[_]
	cidr.cidrIp == "0.0.0.0/0"

	result := {
		"resourceType": "SecurityGroup",
		"resourceName": cp_lib.getResourceName(resource, name),
		"severity": "HIGH",
		"message": sprintf("Security group allows ingress from 0.0.0.0/0 on port %v", [rule.fromPort]),
	}
}
