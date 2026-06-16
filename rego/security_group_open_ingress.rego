package wiz

import data.generic.crossplane as cp_lib

# --- Legacy crossplane-contrib/provider-aws: kind SecurityGroup with inline ingress ---
# SecurityGroup with inline ingress is unique to AWS legacy — kind alone disambiguates.

# Standalone
WizPolicy[result] {
	doc := input.document[i]
	doc.kind == "SecurityGroup"
	spec := cp_lib.mergedSpec(doc)
	rule := spec.ingress[rule_index]
	cidr := rule.ipRanges[cidr_index]
	cidr.cidrIp == "0.0.0.0/0"
	section := cp_lib.fieldLocation(doc, "ingress")

	result := {
		"documentId": doc.id,
		"resourceType": "SecurityGroup",
		"resourceName": doc.metadata.name,
		"searchKey": sprintf("spec.%s.ingress[%d].ipRanges[%d].cidrIp", [section, rule_index, cidr_index]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ingress should not allow traffic from 0.0.0.0/0",
		"keyActualValue": sprintf("ingress allows traffic from 0.0.0.0/0 on port %v", [rule.fromPort]),
	}
}

# Composed
WizPolicy[result] {
	doc := input.document[i]
	doc.kind == "Composition"
	base := doc.spec.resources[j].base
	base.kind == "SecurityGroup"
	spec := cp_lib.mergedSpec(base)
	rule := spec.ingress[rule_index]
	cidr := rule.ipRanges[cidr_index]
	cidr.cidrIp == "0.0.0.0/0"
	section := cp_lib.fieldLocation(base, "ingress")

	result := {
		"documentId": doc.id,
		"resourceType": "SecurityGroup",
		"resourceName": base.metadata.name,
		"searchKey": sprintf("spec.resources[%d].base.spec.%s.ingress[%d].ipRanges[%d].cidrIp", [j, section, rule_index, cidr_index]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ingress should not allow traffic from 0.0.0.0/0",
		"keyActualValue": sprintf("ingress allows traffic from 0.0.0.0/0 on port %v", [rule.fromPort]),
	}
}

# --- Upbound provider-aws-ec2: kind SecurityGroupIngressRule (one resource per rule) ---
# SecurityGroupIngressRule is unique to Upbound AWS EC2 — kind alone disambiguates.

# Standalone
WizPolicy[result] {
	doc := input.document[i]
	doc.kind == "SecurityGroupIngressRule"
	spec := cp_lib.mergedSpec(doc)
	spec.cidrIpv4 == "0.0.0.0/0"
	section := cp_lib.fieldLocation(doc, "cidrIpv4")

	result := {
		"documentId": doc.id,
		"resourceType": "SecurityGroupIngressRule",
		"resourceName": doc.metadata.name,
		"searchKey": sprintf("spec.%s.cidrIpv4", [section]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "cidrIpv4 should not be 0.0.0.0/0",
		"keyActualValue": sprintf("cidrIpv4 is 0.0.0.0/0 on port %v", [spec.fromPort]),
	}
}

# Composed
WizPolicy[result] {
	doc := input.document[i]
	doc.kind == "Composition"
	base := doc.spec.resources[j].base
	base.kind == "SecurityGroupIngressRule"
	spec := cp_lib.mergedSpec(base)
	spec.cidrIpv4 == "0.0.0.0/0"
	section := cp_lib.fieldLocation(base, "cidrIpv4")

	result := {
		"documentId": doc.id,
		"resourceType": "SecurityGroupIngressRule",
		"resourceName": base.metadata.name,
		"searchKey": sprintf("spec.resources[%d].base.spec.%s.cidrIpv4", [j, section]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "cidrIpv4 should not be 0.0.0.0/0",
		"keyActualValue": sprintf("cidrIpv4 is 0.0.0.0/0 on port %v", [spec.fromPort]),
	}
}
