package generic.common

valid_key(obj, key) {
	_ = obj[key]
}

get_tag_name_if_exists(resource) = name {
	tags := resource.metadata.labels
	name := tags["Name"]
} else = name {
	tags := resource.metadata.annotations
	name := tags["Name"]
}

build_search_line(path, obj) = result {
	result = array.concat(path, obj)
}

concat_path(path) = result {
	result := concat(".", [x | x := path[_]; is_string(x)])
}
