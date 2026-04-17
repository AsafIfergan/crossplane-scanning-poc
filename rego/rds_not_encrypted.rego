package wiz

import data.generic.common as common_lib
import data.generic.crossplane as cp_lib

WizPolicy[result] {
	document := input.document[i]
	resource := document.resource.RDSInstance[name]

	not common_lib.valid_key(resource.spec.forProvider, "storageEncrypted")

	result := {
		"documentId": document.id,
		"resourceType": "RDSInstance",
		"resourceName": cp_lib.getResourceName(resource, name),
		"searchKey": sprintf("resource.RDSInstance[%s].spec.forProvider", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "storageEncrypted should be defined and set to true",
		"keyActualValue": "storageEncrypted is not defined",
		"searchLine": common_lib.build_search_line(["resource", "RDSInstance", name, "spec", "forProvider"], []),
	}
}

WizPolicy[result] {
	document := input.document[i]
	resource := document.resource.RDSInstance[name]

	resource.spec.forProvider.storageEncrypted == false

	result := {
		"documentId": document.id,
		"resourceType": "RDSInstance",
		"resourceName": cp_lib.getResourceName(resource, name),
		"searchKey": sprintf("resource.RDSInstance[%s].spec.forProvider.storageEncrypted", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "storageEncrypted should be set to true",
		"keyActualValue": "storageEncrypted is set to false",
		"searchLine": common_lib.build_search_line(["resource", "RDSInstance", name, "spec", "forProvider", "storageEncrypted"], []),
	}
}
