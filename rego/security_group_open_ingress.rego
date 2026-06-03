package wiz

import data.generic.common as common_lib
import data.generic.crossplane as cp_lib

# --- Legacy crossplane-contrib/provider-aws: SecurityGroup with inline ingress

WizPolicy[result] {
	r := cp_lib.managedResourcesOf("SecurityGroup")[_]
	cp_lib.isAWSLegacy(r.resource)
	spec := cp_lib.mergedSpec(r.resource)
	rule := spec.ingress[rule_index]
	cidr := rule.ipRanges[_]
	cidr.cidrIp == "0.0.0.0/0"

	result := {
		"documentId": r.doc.id,
		"resourceType": "SecurityGroup",
		"resourceName": r.name,
		"searchKey": sprintf("SecurityGroup[%s].spec.forProvider.ingress[%d]", [r.name, rule_index]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ingress should not allow traffic from 0.0.0.0/0",
		"keyActualValue": sprintf("ingress allows traffic from 0.0.0.0/0 on port %v", [rule.fromPort]),
		"searchLine": common_lib.build_search_line(r.searchPath, ["spec", "forProvider", "ingress", rule_index]),
	}
}

# --- Upbound provider-aws-ec2: SecurityGroupIngressRule (one resource per rule)

WizPolicy[result] {
	r := cp_lib.managedResourcesOf("SecurityGroupIngressRule")[_]
	cp_lib.isAWSUpboundEC2(r.resource)
	spec := cp_lib.mergedSpec(r.resource)
	spec.cidrIpv4 == "0.0.0.0/0"

	result := {
		"documentId": r.doc.id,
		"resourceType": "SecurityGroupIngressRule",
		"resourceName": r.name,
		"searchKey": sprintf("SecurityGroupIngressRule[%s].spec.forProvider.cidrIpv4", [r.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "cidrIpv4 should not be 0.0.0.0/0",
		"keyActualValue": sprintf("cidrIpv4 is 0.0.0.0/0 on port %v", [spec.fromPort]),
		"searchLine": common_lib.build_search_line(r.searchPath, ["spec", "forProvider", "cidrIpv4"]),
	}
}
