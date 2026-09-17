package com.otilm.core.util.builders;

import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.model.crypto.KeyCertificateAssociationModel;
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import com.otilm.core.model.crypto.TokenProfileBasicModel;
import com.otilm.core.model.group.GroupModel;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static com.otilm.core.util.builders.CryptographicKeyItemBasicModelBuilder.aKeyItemSnapshot;

public class CryptographicKeyFullModelBuilder {

    private List<CryptographicKeyItemBasicModel> items = List.of(aKeyItemSnapshot().build());
    private Set<GroupModel> groups = Set.of();
    private List<KeyCertificateAssociationModel> associations = List.of();
    private TokenProfileBasicModel tokenProfile;
    private TokenInstanceFullModel tokenInstance;
    private UUID ownerUuid;
    private String ownerName;

    public static CryptographicKeyFullModelBuilder aKeySnapshot() {
        return new CryptographicKeyFullModelBuilder();
    }

    public CryptographicKeyFullModelBuilder withItems(List<CryptographicKeyItemBasicModel> items) {
        this.items = items;
        return this;
    }

    public CryptographicKeyFullModelBuilder withGroups(Set<GroupModel> groups) {
        this.groups = groups;
        return this;
    }

    public CryptographicKeyFullModelBuilder withAssociations(List<KeyCertificateAssociationModel> associations) {
        this.associations = associations;
        return this;
    }

    public CryptographicKeyFullModelBuilder withTokenProfile(TokenProfileBasicModel tokenProfile) {
        this.tokenProfile = tokenProfile;
        return this;
    }

    public CryptographicKeyFullModelBuilder withTokenInstance(TokenInstanceFullModel tokenInstance) {
        this.tokenInstance = tokenInstance;
        return this;
    }

    public CryptographicKeyFullModelBuilder withOwner(UUID ownerUuid, String ownerName) {
        this.ownerUuid = ownerUuid;
        this.ownerName = ownerName;
        return this;
    }

    public ImmutableCryptographicKeyFullModel build() {
        UUID tokenProfileUuid = tokenProfile == null ? null : tokenProfile.uuid();
        UUID tokenInstanceUuid = tokenInstance == null ? null : tokenInstance.uuid();
        return new ImmutableCryptographicKeyFullModel(UUID.randomUUID(), "signing-key", "Application signing",
                tokenProfileUuid, tokenInstanceUuid, tokenProfile, tokenInstance, groups,
                OffsetDateTime.parse("2026-09-10T10:00:00Z"), ownerUuid, ownerName, items, associations);
    }
}
