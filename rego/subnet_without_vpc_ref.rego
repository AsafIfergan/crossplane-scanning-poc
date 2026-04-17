package wiz

import data.generic.common as common_lib
import data.generic.crossplane as cp_lib

WizPolicy[result] {
	document := input.document[i]
	subnet := document.resource.Subnet[name]
	vpcRefName := subnet.spec.forProvider.vpcIdRef.name

	not document.resource.VPC[vpcRefName]

	result := {
		"documentId": document.id,
		"resourceType": "Subnet",
		"resourceName": cp_lib.getResourceName(subnet, name),
		"searchKey": sprintf("resource.Subnet[%s].spec.forProvider.vpcIdRef", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("referenced VPC '%s' should exist", [vpcRefName]),
		"keyActualValue": sprintf("referenced VPC '%s' is not defined in scanned files", [vpcRefName]),
		"searchLine": common_lib.build_search_line(["resource", "Subnet", name, "spec", "forProvider", "vpcIdRef"], []),
	}
}
