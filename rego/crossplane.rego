package generic.crossplane

import data.generic.common as common_lib

getResourceName(resource, name) = result {
	result = resource.metadata.name
} else = result {
	result = name
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
