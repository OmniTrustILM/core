package com.otilm.core.attribute.engine;

import com.otilm.api.model.core.auth.AttributeResource;
import java.util.Optional;
import java.util.UUID;
import java.util.function.BiFunction;

/**
 * What the connector a request goes to may receive of the objects the request reaches. Core lends an object's own
 * references only to the connector the object belongs to: the authority a discovery names gives that discovery's
 * connector its OAuth client secret and TLS trust, which the same connector already receives for every operation of the
 * authority, so lending them creates no new holder and asks no right of the caller. An object of another connector is
 * refused: its content is that connector's connection. Both are asked for every object, at every level.
 */
@FunctionalInterface
public interface ReferenceLending {

    /** Lends nothing and refuses nothing: the references inside a referenced object stay references. */
    ReferenceLending NOTHING = (kind, uuid) -> null;

    /**
     * @return the loader for the references inside the object, or {@code null} to leave them as references
     */
    ReferenceLoader insideOf(AttributeResource kind, UUID uuid);

    /**
     * Whether the object belongs to a connector other than the one the request goes to. An object of no connector, such
     * as a credential, secret or certificate, may go to any.
     */
    default boolean belongsToAnotherConnector(AttributeResource kind, UUID uuid) {
        return false;
    }

    /**
     * The lending for a request to the connector: an object of the connector lends its references through the loader,
     * and an object of another connector is refused.
     *
     * @param ownerOf the connector an object belongs to, empty for one that belongs to none
     */
    static ReferenceLending forConnector(UUID connectorUuid,
            BiFunction<AttributeResource, UUID, Optional<UUID>> ownerOf, ReferenceLoader loader) {
        return new ReferenceLending() {
            @Override
            public ReferenceLoader insideOf(AttributeResource kind, UUID uuid) {
                return ownerOf.apply(kind, uuid).filter(connectorUuid::equals).isPresent() ? loader : null;
            }

            @Override
            public boolean belongsToAnotherConnector(AttributeResource kind, UUID uuid) {
                return ownerOf.apply(kind, uuid).filter(owner -> !owner.equals(connectorUuid)).isPresent();
            }
        };
    }
}
