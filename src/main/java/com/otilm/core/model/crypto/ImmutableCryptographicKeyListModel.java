package com.otilm.core.model.crypto;

import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.model.group.GroupModel;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public record ImmutableCryptographicKeyListModel(UUID uuid, String name, String description, UUID tokenProfileUuid,
        UUID tokenInstanceReferenceUuid, Set<GroupModel> groups, String tokenProfileName, String tokenInstanceName,
        OffsetDateTime created, UUID ownerUuid, String ownerName, List<CryptographicKeyItemBasicModel> items,
        int associationCount) implements CryptographicKeyListModel {

    public ImmutableCryptographicKeyListModel {
        groups = Set.copyOf(groups);
        items = List.copyOf(items);
    }

    /** Certificate links are counted separately so building a summary never initializes those collections. */
    public static ImmutableCryptographicKeyListModel from(CryptographicKey key, long certificateCount) {
        Objects.requireNonNull(key, "Cryptographic key is required.");
        TokenProfile profile = key.getTokenProfile();
        TokenInstanceReference token = key.getTokenInstanceReference();
        OwnerAssociation owner = key.getOwner();
        Set<GroupModel> groups = key.getGroups().stream().map(GroupModel::from).collect(Collectors.toSet());
        List<CryptographicKeyItemBasicModel> items = key
                .getItems()
                .stream()
                .map(CryptographicKeyItemBasicModel::from)
                .toList();
        int associationCount = Math.toIntExact(certificateCount + items.size() - 1);
        return new ImmutableCryptographicKeyListModel(key.getUuid(), key.getName(), key.getDescription(),
                key.getTokenProfileUuid(), key.getTokenInstanceReferenceUuid(), groups,
                profile == null ? null : profile.getName(), token == null ? null : token.getName(), key.getCreated(),
                owner == null ? null : owner.getOwnerUuid(), owner == null ? null : owner.getOwnerUsername(), items,
                associationCount);
    }
}
