package objects

import rego.v1

# Provides a list of uuids for which the requested action is permitted on the resource and for which it is denied.
# Returns array of allowedObjects and forbiddenObjects and boolean value actionAllowedForGroupOfObjects.
# The actionAllowedForGroupOfObjects specifies whether the user has access to all objects or only those explicitly allowed.
# When false, the user can access only objects to which access is explicitly allowed.
# When true, the user can access all objects except those to which access is explicitly forbidden.

# Allow action for all objects except those explicitly forbidden
# as all resources are allowed
actionAllowedForGroupOfObjects if {
	input.principal.permissions.allowAllResources == true
}

# Allow action for all objects except those explicitly forbidden
# as all actions for requested resource are allowed
actionAllowedForGroupOfObjects if {
	# find requested resource between permissions
	some r in input.principal.permissions.resources
	r.name == input.requestedResource.name

	# Check all actions are allowed for the resource
	r.allowAllActions == true
}

# Allow action for all objects except those explicitly forbidden
# as requested action is allwed on requested resource
actionAllowedForGroupOfObjects if {
	# find requested resource between permissions
	some r in input.principal.permissions.resources
	r.name == input.requestedResource.name

	# check if requested action is allowed for the resource
	input.requestedResource.action in r.actions
}

# Find uuids of objects for which the requested action is explicitly allowed
allowedObjects contains object.uuid if {
	# find requested resource between permissions
	some r in input.principal.permissions.resources
	r.name == input.requestedResource.name

	# find objects under the resource for which the action is allowed
	some object in r.objects
	input.requestedResource.action in object.allow
}

# Find uuids of objects for which the requested action is explicitly forbidden
forbiddenObjects contains object.uuid if {
	# find requested resource between permissions
	some r in input.principal.permissions.resources
	r.name == input.requestedResource.name

	# find objects under the resource for which the action is denied
	some object in r.objects
	input.requestedResource.action in object.deny
}

default actionAllowedForGroupOfObjects := false
