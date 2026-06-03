package generic.crossplane

import data.generic.common as common_lib

# getResourceName returns the resource's metadata name.
getResourceName(resource) = name {
	name := resource.metadata.name
}

get_resource_tags(resource) = tags {
	tags = resource.metadata.labels
	is_object(tags)
	tags != {}
} else = tags {
	tags = resource.metadata.annotations
	is_object(tags)
	tags != {}
} else = {} {
	true
}

# associatedByRef checks whether a resource references another resource via a *Ref field.
# Example: subnet.spec.forProvider.vpcIdRef.name == vpcName
associatedByRef(resource, refField, targetName) {
	resource.spec.forProvider[refField].name == targetName
}

# associatedBySelector checks whether a resource selects another via a *Selector field.
associatedBySelector(resource, selectorField, targetResource) {
	selector := resource.spec.forProvider[selectorField]
	matchLabels := selector.matchLabels
	label := matchLabels[key]
	targetResource.metadata.labels[key] == label
}

# --- Provider-family detection -----------------------------------------------
# Operate on the MANAGED RESOURCE (cr.base for composed, the doc itself for
# standalone) — NOT on the Composition wrapper, whose apiVersion is always
# apiextensions.crossplane.io/v1.

isAWSLegacy(resource) {
	contains(resource.apiVersion, ".aws.crossplane.io/")
}

isAWSUpbound(resource) {
	contains(resource.apiVersion, ".aws.upbound.io/")
}

# Convenience: matches either AWS provider family.
isAWS(resource) {
	isAWSLegacy(resource)
}

isAWS(resource) {
	isAWSUpbound(resource)
}

# Sub-family helpers — needed when a kind name is ambiguous across Upbound
# services (e.g. "Instance" exists in both rds.aws.upbound.io and ec2.aws.upbound.io).
isAWSUpboundRDS(resource) {
	startswith(resource.apiVersion, "rds.aws.upbound.io/")
}

isAWSUpboundEC2(resource) {
	startswith(resource.apiVersion, "ec2.aws.upbound.io/")
}

# --- Spec accessor -----------------------------------------------------------

# mergedSpec returns forProvider ∪ initProvider so rules don't care where the
# field was declared. forProvider wins on conflict. Legacy resources have no
# initProvider; the merge falls through to plain forProvider.
mergedSpec(resource) = merged {
	fp := object.get(resource.spec, "forProvider", {})
	ip := object.get(resource.spec, "initProvider", {})
	merged := object.union(ip, fp)
}

# --- Resource iteration ------------------------------------------------------

# managedResourcesOf yields every resource of the given kind, whether declared
# standalone or nested inside a Composition's spec.resources[].base.
#
# Each result has:
#   doc        — the input.document[] entry that contains this resource
#   resource   — the managed-resource payload (with kind/metadata/spec)
#   name       — resource.metadata.name
#   searchPath — path prefix in the input, for build_search_line
managedResourcesOf(kind) = results {
	standalone := {r |
		doc := input.document[i]
		doc.kind == kind
		r := {
			"doc": doc,
			"resource": doc,
			"name": doc.metadata.name,
			"searchPath": ["document", i],
		}
	}
	composed := {r |
		doc := input.document[i]
		doc.kind == "Composition"
		cr := doc.spec.resources[j]
		cr.base.kind == kind
		r := {
			"doc": doc,
			"resource": cr.base,
			"name": cr.base.metadata.name,
			"searchPath": ["document", i, "spec", "resources", j, "base"],
		}
	}
	results := standalone | composed
}

# resourceExists is true when any resource of the given kind has the given name.
resourceExists(kind, name) {
	managedResourcesOf(kind)[_].name == name
}
