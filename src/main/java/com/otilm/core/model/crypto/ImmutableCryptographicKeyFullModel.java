package com.otilm.core.model.crypto;

import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.model.group.GroupModel;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/** Immutable key-wrapper snapshot; construct while its persistence associations are accessible. */
public record ImmutableCryptographicKeyFullModel(UUID uuid, String name, String description, UUID tokenProfileUuid,
        UUID tokenInstanceReferenceUuid, TokenProfileBasicModel tokenProfile, TokenInstanceFullModel tokenInstance,
        Set<GroupModel> groups, OffsetDateTime created, UUID ownerUuid, String ownerName,
        List<CryptographicKeyItemBasicModel> items,
        List<KeyCertificateAssociationModel> certificateAssociations) implements CryptographicKeyFullModel {

    public ImmutableCryptographicKeyFullModel {
        groups = Set.copyOf(groups);
        items = List.copyOf(items);
        certificateAssociations = List.copyOf(certificateAssociations);
    }

    public static ImmutableCryptographicKeyFullModel from(CryptographicKey key) {
        Objects.requireNonNull(key, "Cryptographic key is required.");
        TokenProfile profileEntity = key.getTokenProfile();
        TokenProfileBasicModel profile = profileEntity == null
                ? null
                : ImmutableTokenProfileBasicModel.from(profileEntity);
        TokenInstanceReference tokenEntity = key.getTokenInstanceReference();
        TokenInstanceFullModel token = tokenEntity == null ? null : ImmutableTokenInstanceFullModel.from(tokenEntity);
        Set<GroupModel> groups = key.getGroups().stream().map(GroupModel::from).collect(Collectors.toSet());
        OwnerAssociation owner = key.getOwner();
        UUID ownerUuid = owner == null ? null : owner.getOwnerUuid();
        String ownerName = owner == null ? null : owner.getOwnerUsername();
        List<CryptographicKeyItemBasicModel> items = key
                .getItems()
                .stream()
                .map(CryptographicKeyItemBasicModel::from)
                .toList();
        List<KeyCertificateAssociationModel> certificates = certificateAssociations(key);
        return new ImmutableCryptographicKeyFullModel(key.getUuid(), key.getName(), key.getDescription(),
                key.getTokenProfileUuid(), key.getTokenInstanceReferenceUuid(), profile, token, groups,
                key.getCreated(), ownerUuid, ownerName, items, certificates);
    }

    private static List<KeyCertificateAssociationModel> certificateAssociations(CryptographicKey key) {
        List<KeyCertificateAssociationModel> certificates = new ArrayList<>();
        if (key.getCertificates() != null) {
            key.getCertificates().stream().map(KeyCertificateAssociationModel::from).forEach(certificates::add);
        }
        if (key.getAltCertificates() != null) {
            key.getAltCertificates().stream().map(KeyCertificateAssociationModel::from).forEach(certificates::add);
        }
        return certificates;
    }
}
