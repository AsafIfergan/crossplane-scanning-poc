package wiz

import data.generic.common as common_lib
import data.generic.crossplane as cp_lib

WizPolicy[result] {
	document := input.document[i]
	resource := document.resource.SecurityGroup[name]
	rule := resource.spec.forProvider.ingress[rule_index]
	cidr := rule.ipRanges[_]
	cidr.cidrIp == "0.0.0.0/0"

	result := {
		"documentId": document.id,
		"resourceType": "SecurityGroup",
		"resourceName": cp_lib.getResourceName(resource, name),
		"searchKey": sprintf("resource.SecurityGroup[%s].spec.forProvider.ingress[%d]", [name, rule_index]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ingress should not allow traffic from 0.0.0.0/0",
		"keyActualValue": sprintf("ingress allows traffic from 0.0.0.0/0 on port %v", [rule.fromPort]),
		"searchLine": common_lib.build_search_line(["resource", "SecurityGroup", name, "spec", "forProvider", "ingress", rule_index], []),
	}
}
