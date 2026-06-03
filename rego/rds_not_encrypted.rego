package wiz

import data.generic.common as common_lib
import data.generic.crossplane as cp_lib

# --- Legacy crossplane-contrib/provider-aws: RDSInstance ---------------------

WizPolicy[result] {
	r := cp_lib.managedResourcesOf("RDSInstance")[_]
	cp_lib.isAWSLegacy(r.resource)
	spec := cp_lib.mergedSpec(r.resource)
	not common_lib.valid_key(spec, "storageEncrypted")

	result := {
		"documentId": r.doc.id,
		"resourceType": "RDSInstance",
		"resourceName": r.name,
		"searchKey": sprintf("RDSInstance[%s].spec.forProvider", [r.name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "storageEncrypted should be defined and set to true",
		"keyActualValue": "storageEncrypted is not defined",
		"searchLine": common_lib.build_search_line(r.searchPath, ["spec", "forProvider"]),
	}
}

WizPolicy[result] {
	r := cp_lib.managedResourcesOf("RDSInstance")[_]
	cp_lib.isAWSLegacy(r.resource)
	spec := cp_lib.mergedSpec(r.resource)
	spec.storageEncrypted == false

	result := {
		"documentId": r.doc.id,
		"resourceType": "RDSInstance",
		"resourceName": r.name,
		"searchKey": sprintf("RDSInstance[%s].spec.forProvider.storageEncrypted", [r.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "storageEncrypted should be set to true",
		"keyActualValue": "storageEncrypted is set to false",
		"searchLine": common_lib.build_search_line(r.searchPath, ["spec", "forProvider", "storageEncrypted"]),
	}
}

# --- Upbound provider-aws-rds: Instance --------------------------------------

WizPolicy[result] {
	r := cp_lib.managedResourcesOf("Instance")[_]
	cp_lib.isAWSUpboundRDS(r.resource)
	spec := cp_lib.mergedSpec(r.resource)
	not common_lib.valid_key(spec, "storageEncrypted")

	result := {
		"documentId": r.doc.id,
		"resourceType": "Instance",
		"resourceName": r.name,
		"searchKey": sprintf("Instance[%s].spec.forProvider", [r.name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "storageEncrypted should be defined and set to true",
		"keyActualValue": "storageEncrypted is not defined",
		"searchLine": common_lib.build_search_line(r.searchPath, ["spec", "forProvider"]),
	}
}

WizPolicy[result] {
	r := cp_lib.managedResourcesOf("Instance")[_]
	cp_lib.isAWSUpboundRDS(r.resource)
	spec := cp_lib.mergedSpec(r.resource)
	spec.storageEncrypted == false

	result := {
		"documentId": r.doc.id,
		"resourceType": "Instance",
		"resourceName": r.name,
		"searchKey": sprintf("Instance[%s].spec.forProvider.storageEncrypted", [r.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "storageEncrypted should be set to true",
		"keyActualValue": "storageEncrypted is set to false",
		"searchLine": common_lib.build_search_line(r.searchPath, ["spec", "forProvider", "storageEncrypted"]),
	}
}
