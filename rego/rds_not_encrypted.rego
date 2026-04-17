package crossplane.aws.rds_not_encrypted

import data.generic.crossplane as cp_lib

# Detect RDS instances without storageEncrypted defined
deny[result] {
	resource := input.resource.RDSInstance[name]
	not resource.spec.forProvider.storageEncrypted

	result := {
		"resourceType": "RDSInstance",
		"resourceName": cp_lib.getResourceName(resource, name),
		"severity": "HIGH",
		"message": "RDS Instance storage encryption is not enabled",
	}
}

# Detect RDS instances with storageEncrypted explicitly false
deny[result] {
	resource := input.resource.RDSInstance[name]
	resource.spec.forProvider.storageEncrypted == false

	result := {
		"resourceType": "RDSInstance",
		"resourceName": cp_lib.getResourceName(resource, name),
		"severity": "HIGH",
		"message": "RDS Instance storage encryption is explicitly disabled",
	}
}
