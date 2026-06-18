package wiz

import data.generic.crossplane as cp_lib

# DEMO: iterator-based equivalent of security_group_open_ingress_walk.rego.
#
# This rule has TWO families with fundamentally different shapes:
#   - Legacy contrib: kind=SecurityGroup with inline spec.forProvider.ingress[]
#   - Upbound:        kind=SecurityGroupIngressRule (one resource per rule),
#                     with spec.forProvider.cidrIpv4 (singular)
#
# The shapes can't merge — different fields, different searchKey templates.
# So we keep one block per family. Within each family, getResources collapses
# the standalone+composed duplication into a single block.

# --- Legacy crossplane-contrib/provider-aws: SecurityGroup inline ingress -----

WizPolicy[result] {
	doc := input.document[i]
	r := cp_lib.getResources(doc)[_]
	resource := r.resource
	resource.kind == "SecurityGroup"
	spec := cp_lib.mergedSpec(resource)
	rule := spec.ingress[rule_index]
	cidr := rule.ipRanges[cidr_index]
	cidr.cidrIp == "0.0.0.0/0"
	section := cp_lib.fieldLocation(resource, "ingress")

	result := {
		"documentId": doc.id,
		"resourceType": "SecurityGroup",
		"resourceName": resource.metadata.name,
		"searchKey": cp_lib.getPath(r.walkPath, section, sprintf("ingress[%d].ipRanges[%d].cidrIp", [rule_index, cidr_index])),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ingress should not allow traffic from 0.0.0.0/0",
		"keyActualValue": sprintf("ingress allows traffic from 0.0.0.0/0 on port %v", [rule.fromPort]),
	}
}

# --- Upbound provider-aws-ec2: SecurityGroupIngressRule (one resource per rule)

WizPolicy[result] {
	doc := input.document[i]
	r := cp_lib.getResources(doc)[_]
	resource := r.resource
	resource.kind == "SecurityGroupIngressRule"
	spec := cp_lib.mergedSpec(resource)
	spec.cidrIpv4 == "0.0.0.0/0"
	section := cp_lib.fieldLocation(resource, "cidrIpv4")

	result := {
		"documentId": doc.id,
		"resourceType": "SecurityGroupIngressRule",
		"resourceName": resource.metadata.name,
		"searchKey": cp_lib.getPath(r.walkPath, section, "cidrIpv4"),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "cidrIpv4 should not be 0.0.0.0/0",
		"keyActualValue": sprintf("cidrIpv4 is 0.0.0.0/0 on port %v", [spec.fromPort]),
	}
}
