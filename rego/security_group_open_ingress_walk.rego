package wiz

import data.generic.crossplane as cp_lib

# DEMO: walk-based equivalent of security_group_open_ingress.rego.
#
# This rule has TWO families with fundamentally different shapes:
#   - Legacy contrib: kind=SecurityGroup with inline spec.forProvider.ingress[]
#   - Upbound:        kind=SecurityGroupIngressRule (one resource per rule),
#                     with spec.forProvider.cidrIpv4 (singular)
#
# The shapes can't merge into one block — different fields, different searchKey
# templates. So we keep one block per family. But within each family, walk +
# getPath collapses the standalone+composed duplication: 4 blocks → 2 blocks.

# --- Legacy crossplane-contrib/provider-aws: SecurityGroup inline ingress -----

WizPolicy[result] {
	doc := input.document[i]
	walk(doc, [path, value])
	value.kind == "SecurityGroup"
	spec := cp_lib.mergedSpec(value)
	rule := spec.ingress[rule_index]
	cidr := rule.ipRanges[cidr_index]
	cidr.cidrIp == "0.0.0.0/0"
	section := cp_lib.fieldLocation(value, "ingress")

	result := {
		"documentId": doc.id,
		"resourceType": "SecurityGroup",
		"resourceName": value.metadata.name,
		"searchKey": cp_lib.getPath(path, section, sprintf("ingress[%d].ipRanges[%d].cidrIp", [rule_index, cidr_index])),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ingress should not allow traffic from 0.0.0.0/0",
		"keyActualValue": sprintf("ingress allows traffic from 0.0.0.0/0 on port %v", [rule.fromPort]),
	}
}

# --- Upbound provider-aws-ec2: SecurityGroupIngressRule (one resource per rule)

WizPolicy[result] {
	doc := input.document[i]
	walk(doc, [path, value])
	value.kind == "SecurityGroupIngressRule"
	spec := cp_lib.mergedSpec(value)
	spec.cidrIpv4 == "0.0.0.0/0"
	section := cp_lib.fieldLocation(value, "cidrIpv4")

	result := {
		"documentId": doc.id,
		"resourceType": "SecurityGroupIngressRule",
		"resourceName": value.metadata.name,
		"searchKey": cp_lib.getPath(path, section, "cidrIpv4"),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "cidrIpv4 should not be 0.0.0.0/0",
		"keyActualValue": sprintf("cidrIpv4 is 0.0.0.0/0 on port %v", [spec.fromPort]),
	}
}
