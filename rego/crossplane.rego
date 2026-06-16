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

# getPath converts a walk() path into a string prefix safe to splice into a
# searchKey, with a trailing dot when non-empty. Used to collapse the per-rule
# standalone+composed block duplication into a single WizPolicy block that
# walks the document and matches resources at any valid depth.
#
# Walk paths that yield a Crossplane managed resource:
#   []                                  → standalone (walk yielded the doc itself)
#                                         getPath returns ""
#   ["spec", "resources", j, "base"]    → composed (resource under Composition)
#                                         getPath returns "spec.resources[<j>].base."
#
# Usage in a rule:
#   walk(doc, [path, value])
#   isAWSMyResource(value)                # variant predicate is the load-bearing filter
#   "searchKey": sprintf("%sspec.%s.<field>", [cp_lib.getPath(path), section])
getPath(path) = sprintf("%s.", [pathStr]) {
	count(path) > 0
	pathStr := trim_prefix(concat("", [s | p := path[_]; s := pathSeg(p)]), ".")
} else = "" {
	true
}

# pathSeg formats one element of a walk path: ".name" for strings, "[N]" for
# array indices. Concat'ing them produces ".spec.resources[0].base"; getPath
# trims the leading dot and adds a trailing one.
pathSeg(p) = sprintf(".%s", [p]) {
	is_string(p)
}
pathSeg(p) = sprintf("[%d]", [p]) {
	is_number(p)
}
