package wiz

import data.generic.common as common_lib
import data.generic.crossplane as cp_lib

# Both legacy and Upbound AWS use kind=Subnet with the same vpcIdRef.name path,
# so a single WizPolicy block covers both families. The isAWS filter exists to
# avoid matching a hypothetical non-AWS "Subnet" kind from another provider.

WizPolicy[result] {
	r := cp_lib.managedResourcesOf("Subnet")[_]
	cp_lib.isAWS(r.resource)
	spec := cp_lib.mergedSpec(r.resource)
	vpcRefName := spec.vpcIdRef.name

	not cp_lib.resourceExists("VPC", vpcRefName)

	result := {
		"documentId": r.doc.id,
		"resourceType": "Subnet",
		"resourceName": r.name,
		"searchKey": sprintf("Subnet[%s].spec.forProvider.vpcIdRef", [r.name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("referenced VPC '%s' should exist", [vpcRefName]),
		"keyActualValue": sprintf("referenced VPC '%s' is not defined in scanned files", [vpcRefName]),
		"searchLine": common_lib.build_search_line(r.searchPath, ["spec", "forProvider", "vpcIdRef"]),
	}
}
