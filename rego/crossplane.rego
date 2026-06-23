package generic.crossplane

import data.generic.common as common_lib

# Returns forProvider ∪ initProvider; forProvider wins on conflict.
mergedSpec(resource) = merged {
	fp := object.get(resource.spec, "forProvider", {})
	ip := object.get(resource.spec, "initProvider", {})
	merged := object.union(ip, fp)
}

# Returns the spec section where `field` is declared. Defaults to "forProvider"
# when missing from both (canonical place to add it).
fieldLocation(resource, field) = "forProvider" {
	common_lib.valid_key(resource.spec.forProvider, field)
} else = "initProvider" {
	common_lib.valid_key(resource.spec.initProvider, field)
} else = "forProvider" {
	true
}

# Internal helper for getPath: walk path → string prefix with trailing dot.
walkPrefix(walkPath) = sprintf("%s.", [pathStr]) {
	count(walkPath) > 0
	pathStr := trim_prefix(concat("", [s | p := walkPath[_]; s := pathSeg(p)]), ".")
} else = "" {
	true
}

# Internal: type dispatch per walk-path element. Must be a function — Rego
# comprehensions can't if/else inline.
pathSeg(p) = sprintf(".%s", [p]) {
	is_string(p)
}
pathSeg(p) = sprintf("[%d]", [p]) {
	is_number(p)
}

# Builds a searchKey: `<walkPrefix>spec.<section>.<rest>`. Empty `rest` drops
# the trailing dot — use for MissingAttribute findings.
getPath(walkPath, section, rest) = sprintf("%sspec.%s.%s", [walkPrefix(walkPath), section, rest]) {
	rest != ""
} else = sprintf("%sspec.%s", [walkPrefix(walkPath), section]) {
	true
}

# Returns the managed resources in `doc` — one entry for a standalone doc,
# N entries for a Composition with N spec.resources[].base entries, [] for an
# empty Composition. List-returning function (not partial rule) so callers
# keep their explicit `doc := input.document[i]` iteration.
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
