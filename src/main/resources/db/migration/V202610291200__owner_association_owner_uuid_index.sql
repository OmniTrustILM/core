-- The user profile checks on every load whether the user owns any certificate, key or secret, and authorization
-- counts a user's owned objects; both look owner associations up by owner uuid, which the owner username index
-- cannot serve.
--
-- CREATE INDEX blocks writes to owner_association while it builds; Flyway's transaction rules out CONCURRENTLY.
CREATE INDEX "idx_owner_association_owner_uuid" ON "owner_association" ("owner_uuid", "resource");
