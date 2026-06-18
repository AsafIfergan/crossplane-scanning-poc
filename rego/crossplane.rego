package generic.crossplane

import data.generic.common as common_lib

# getResourceName returns the resource's metadata name.
getResourceName(resource) = name {
	name := resource.metadata.name
}

# get_resource_tags returns labels (preferred) or annotations as a map of tags.
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

# mergedSpec returns forProvider ∪ initProvider so rules don't care which
# section a field was declared in. Upbound providers mirror fields between
# the two; forProvider wins on conflict. Legacy providers have no initProvider,
# in which case the merge falls through to plain forProvider.
mergedSpec(resource) = merged {
	fp := object.get(resource.spec, "forProvider", {})
	ip := object.get(resource.spec, "initProvider", {})
	merged := object.union(ip, fp)
}

# fieldLocation returns the spec section ("forProvider" or "initProvider") where
# the given field is declared. Used to build accurate JSON-path searchKey values
# pointing at the exact location of a misconfiguration in the source YAML.
# Defaults to "forProvider" when the field is missing from both — that's the
# canonical place to add it.
fieldLocation(resource, field) = "forProvider" {
	common_lib.valid_key(resource.spec.forProvider, field)
} else = "initProvider" {
	common_lib.valid_key(resource.spec.initProvider, field)
} else = "forProvider" {
	true
}

# walkPrefix converts a walk() path into a string prefix safe to splice into a
# searchKey, with a trailing dot when non-empty. Internal helper — rule code
# should use getPath instead.
#
# Walk paths that yield a Crossplane managed resource:
#   []                                  → standalone (walk yielded the doc itself)
#                                         walkPrefix returns ""
#   ["spec", "resources", j, "base"]    → composed (resource under Composition)
#                                         walkPrefix returns "spec.resources[<j>].base."
walkPrefix(walkPath) = sprintf("%s.", [pathStr]) {
	count(walkPath) > 0
	pathStr := trim_prefix(concat("", [s | p := walkPath[_]; s := pathSeg(p)]), ".")
} else = "" {
	true
}

# pathSeg formats one element of a walk path: ".name" for strings, "[N]" for
# array indices. Concat'ing them produces ".spec.resources[0].base"; walkPrefix
# trims the leading dot and adds a trailing one.
pathSeg(p) = sprintf(".%s", [p]) {
	is_string(p)
}
pathSeg(p) = sprintf("[%d]", [p]) {
	is_number(p)
}

# getPath assembles a complete searchKey of the form
# `<walkPrefix>spec.<section>.<rest>`. The walk prefix comes from walkPrefix
# (empty for standalone, "spec.resources[j].base." for composed). The
# section is the spec subdivision the caller resolved via fieldLocation
# ("forProvider" or "initProvider"). The rest is the dot-and-bracket path
# inside the spec section.
#
# Usage (canonical rule pattern):
#   section := cp_lib.fieldLocation(value, "metadataOptions")
#   "searchKey": cp_lib.getPath(path, section, "metadataOptions")
#
# Nested example:
#   section := cp_lib.fieldLocation(value, "ingress")
#   "searchKey": cp_lib.getPath(path, section, sprintf("ingress[%d].ipRanges[%d].cidrIp", [i, j]))
#
# MissingAttribute case — pass "" for rest to get `<walkPrefix>spec.<section>`
# (no field appended). The searchKey lands on the section that should contain
# the missing field; the scanner's line resolver then highlights the
# `forProvider:` (or `initProvider:`) line.
#
#   "searchKey": cp_lib.getPath(path, section, "")
getPath(walkPath, section, rest) = sprintf("%sspec.%s.%s", [walkPrefix(walkPath), section, rest]) {
	rest != ""
} else = sprintf("%sspec.%s", [walkPrefix(walkPath), section]) {
	true
}

# getResources returns a list of every Crossplane managed resource inside
# the given document — the doc itself if standalone, or each
# spec.resources[].base entry if doc is a Composition. Returns a single-element
# list for standalone docs, N elements for a Composition with N resources, []
# for an empty Composition. Iterate the returned list with [_] in the rule body.
#
# Each entry bundles:
#   resource    - the managed resource (has spec.forProvider, metadata.name, etc.)
#   walkPath    - path prefix passed to getPath / walkPrefix to build the right
#                 searchKey for standalone ([]) vs composed (["spec", "resources",
#                 j, "base"]) shapes
#
# documentId is NOT bundled because the rule body already binds `doc` from the
# outer iteration — use `doc.id` directly for the result's documentId field.
#
# Implemented as a function returning a list (not a partial rule) so the rule
# body can keep its explicit `doc := input.document[i]` iteration — the helper
# operates per-doc and the rule controls which doc(s) to evaluate.
#
# Usage in a rule (replaces the walk + variant-predicate pattern):
#   doc := input.document[i]
#   mr := cp_lib.getResources(doc)[_]
#   isAWSMyResource(mr.resource)
#   spec := cp_lib.mergedSpec(mr.resource)
#   ...
#   "documentId": doc.id,
#   "resourceType": mr.resource.kind,
#   "resourceName": mr.resource.metadata.name,
#   "searchKey": cp_lib.getPath(mr.walkPath, section, "fieldName"),
getResources(doc) = mrs {
	# Standalone — the doc IS the managed resource. The variant predicate in the
	# rule body filters out docs that aren't Crossplane managed resources.
	not doc.kind == "Composition"
	mrs := [{
		"resource": doc,
		"walkPath": [],
	}]
} else = mrs {
	# Composed — walk into Composition.spec.resources[j].base. The comprehension
	# binds one mr per resource entry; N resources produces N elements.
	doc.kind == "Composition"
	mrs := [mr |
		base := doc.spec.resources[j].base
		mr := {
			"resource": base,
			"walkPath": ["spec", "resources", j, "base"],
		}
	]
}
