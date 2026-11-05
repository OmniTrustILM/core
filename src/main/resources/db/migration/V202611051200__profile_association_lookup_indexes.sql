-- The user profile checks on every load whether the user owns any certificate, key or secret, and authorization
-- counts a user's owned objects; both look owner associations up by owner uuid, which the owner username index
-- cannot serve. A user holding the members action on every group is checked for any group association of a resource,
-- which no index leading with object or group uuid can seek. ProfileAssociationLookupIndexesMigrationITest pins each
-- index to its lookup.
--
-- CREATE INDEX blocks writes to its table while it builds; Flyway's transaction rules out CONCURRENTLY.
CREATE INDEX "idx_owner_association_owner_uuid" ON "owner_association" ("owner_uuid", "resource");
CREATE INDEX "idx_group_association_resource" ON "group_association" ("resource", "group_uuid");
