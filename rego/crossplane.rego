package generic.crossplane

import data.generic.common as common_lib

# Returns forProvider ∪ initProvider with forProvider winning on conflict.
# Upbound resources can declare the same field in either section; legacy
# providers only have forProvider, in which case the merge is a no-op.
mergedSpec(resource) = merged {
	fp := object.get(resource.spec, "forProvider", {})
	ip := object.get(resource.spec, "initProvider", {})
	merged := object.union(ip, fp)
}

# Returns the spec section where `field` is declared ("forProvider" or
# "initProvider"). Defaults to "forProvider" when missing from both — the
# canonical place to add it, so MissingAttribute findings point at the right
# section for remediation.
fieldLocation(resource, field) = "forProvider" {
	common_lib.valid_key(resource.spec.forProvider, field)
} else = "initProvider" {
	common_lib.valid_key(resource.spec.initProvider, field)
} else = "forProvider" {
	true
}

# Internal: converts a walk-style path to a string prefix with trailing dot
# when non-empty. Used by getPath. Rule code should call getPath, not this.
walkPrefix(walkPath) = sprintf("%s.", [pathStr]) {
	count(walkPath) > 0
	pathStr := trim_prefix(concat("", [s | p := walkPath[_]; s := pathSeg(p)]), ".")
} else = "" {
	true
}

# Internal: per-element type dispatch for walkPrefix. Strings produce ".name";
# integers produce "[N]". Comprehensions can't do this inline (no if/else),
# so this needs to be a function.
pathSeg(p) = sprintf(".%s", [p]) {
	is_string(p)
}
pathSeg(p) = sprintf("[%d]", [p]) {
	is_number(p)
}

# Builds a searchKey of the form `<walkPrefix>spec.<section>.<rest>`.
# Pass empty `rest` for MissingAttribute findings — the result drops the
# trailing dot, landing the searchKey on the section that should contain
# the missing field.
getPath(walkPath, section, rest) = sprintf("%sspec.%s.%s", [walkPrefix(walkPath), section, rest]) {
	rest != ""
} else = sprintf("%sspec.%s", [walkPrefix(walkPath), section]) {
	true
}

# Returns the list of Crossplane managed resources in `doc`: one entry for a
# standalone doc, N entries for a Composition with N entries under
# spec.resources[].base, [] for an empty Composition. Each entry is
# `{resource, walkPath}`; rules read documentId from the outer `doc.id`
# directly.
#
# Implemented as a function returning a list (not a partial rule) so callers
# keep the explicit `doc := input.document[i]` iteration — the helper operates
# per-doc and the rule chooses which docs to evaluate.
getResources(doc) = mrs {
	not doc.kind == "Composition"
	mrs := [{"resource": doc, "walkPath": []}]
} else = mrs {
	doc.kind == "Composition"
	mrs := [mr |
		base := doc.spec.resources[j].base
		mr := {"resource": base, "walkPath": ["spec", "resources", j, "base"]}
	]
}
