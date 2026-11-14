package method

import rego.v1

authorized if {
	count(allow) > 0
	count(deny) == 0
}

# Allow access when all resources are allowed
allow contains "AllResourcesAllowed" if {
	input.principal.permissions.allowAllResources == true
}

# Allow access when all actions are allowed on requested resource
allow contains "AllActionsAllowedOnResource" if {
	# find requested resource between permissions
	some r in input.principal.permissions.resources
	r.name == input.requestedResource.name

	# check if all action are allowed on requested resource
	r.allowAllActions == true
}

# Allow access when requested action is allowed on requested resource
allow contains "ActionAllowedOnResource" if {
	# find requested resource between permissions
	some r in input.principal.permissions.resources
	r.name == input.requestedResource.name

	#
	input.requestedResource.action in r.actions
}

# Allow access when requested action on resource is allowed for some objects and no object UUIDs are specified
allow contains "ActionAllowedForSomeObjects" if {
	not input.requestedResource.uuids

	# find requested resource between permissions
	some r in input.principal.permissions.resources
	r.name == input.requestedResource.name

	# check that requested action is allowed for some object under the resource
	input.requestedResource.action in r.objects[_].allow
}

# Allow access when action is allowed for given objects
allow contains "ActionAllowedForSpecificObject" if {
	# requested contains uuids of specific objects
	input.requestedResource.uuids

	# find requested resource between permissions
	some r in input.principal.permissions.resources
	r.name == input.requestedResource.name

	# get all objects uuids for which the action is allowed
	allowedUUIDs := [uuid |
		some o in r.objects
		input.requestedResource.action in o.allow
		uuid := o.uuid
	]

	# check that array of allowedUUIDs conatins all requested uuids
	every uuid in input.requestedResource.uuids {
		uuid in allowedUUIDs
	}
}

# Allow access when any group object UUIDs is in allowed objects for groups members action
allow contains "ActionAllowedForSpecificObjectBasedOnGroupMembership" if {
	# requested contains uuids of specific objects
	input.requestedResource.uuids

	input.requestedResource.name == "groups"
	input.requestedResource.action == "members"

	# find requested resource between permissions
	some r in input.principal.permissions.resources
	r.name == input.requestedResource.name

	# get all objects uuids for which the action is allowed
	allowedUUIDs := [uuid |
		some o in r.objects
		input.requestedResource.action in o.allow
		uuid := o.uuid
	]

	# check that array of allowedUUIDs conatins any of requested uuids
	some uuid in input.requestedResource.uuids
	uuid in allowedUUIDs
}

# Allow access when action is ANY and at least one action allowed is allowed for requested resource
allow contains "AtLeastOneActionOnResource" if {
	# requested action is ANY
	input.requestedResource.action == "ANY"

	# find requested resource between permissions
	some r in input.principal.permissions.resources
	r.name == input.requestedResource.name

	# at least one action is allowed on resource
	count(r.actions) > 0
}

# Allow access when action is ANY and at least one action allowed is allowed for requested resource
allow contains "AtLeastOneActionOnObject" if {
	# Requested action is ANY
	input.requestedResource.action == "ANY"

	# requested contains uuids of specific objects
	input.requestedResource.uuids

	# find requested resource between permissions
	some r in input.principal.permissions.resources
	r.name == input.requestedResource.name

	# get all objects which has at least one action allowed
	uuidsOfObjectsWithOneOrMoreAllowedActions := [uuid |
		some o in r.objects
		count(o.allow) > 0
		uuid := o.uuid
	]

	# check that every object has at least one action allowed
	every uuid in input.requestedResource.uuids {
		uuid in uuidsOfObjectsWithOneOrMoreAllowedActions
	}
}


# Allows access to anonymous users to selected set of resources
allow contains "Anonymous" if {
	# check if user is authenticated as anonymous
	input.principal.user.username = "anonymousUser"

	# define the set of allowed resources
	resourcesWithAnonymousAccess := [{"resource": "connector", "action": "register"}]

	# does the requested resource belong to the allowed resources
	requestedResource := {
		"resource": input.requestedResource.name,
		"action": input.requestedResource.action,
	}
	requestedResource in resourcesWithAnonymousAccess
}

# Deny access when requested action is forbidden for given object
deny contains "ActionDeniedForSpecificObject" if {
	# requested contains uuids of specific objects
	input.requestedResource.uuids

	# find requested resource between permissions
	some r in input.principal.permissions.resources
	r.name == input.requestedResource.name

	# get all objects uuids for which the action is allowed
	forbiddenUUIDs := [uuid |
		some o in r.objects
		input.requestedResource.action in o.deny
		uuid := o.uuid
	]

	# check whether the array of forbiddenUUIDs conatins some of the requested uuids
	some uuid in input.requestedResource.uuids
	uuid in forbiddenUUIDs
}

default authorized := false
