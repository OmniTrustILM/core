package com.otilm.core.model.crypto;

import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.model.group.GroupModel;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/** Immutable key-wrapper snapshot; map while its groups are accessible. */
public record ImmutableCryptographicKeyBasicModel(UUID uuid, String name, String description, UUID tokenProfileUuid,
        UUID tokenInstanceReferenceUuid, Set<GroupModel> groups) implements CryptographicKeyBasicModel {

    public ImmutableCryptographicKeyBasicModel {
        groups = Set.copyOf(groups);
    }

    public static ImmutableCryptographicKeyBasicModel from(CryptographicKey key) {
        Objects.requireNonNull(key, "Cryptographic key is required.");
        Set<GroupModel> groups = key.getGroups().stream().map(GroupModel::from).collect(Collectors.toSet());
        return new ImmutableCryptographicKeyBasicModel(key.getUuid(), key.getName(), key.getDescription(),
                key.getTokenProfileUuid(), key.getTokenInstanceReferenceUuid(), groups);
    }
}
