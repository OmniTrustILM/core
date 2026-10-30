package com.otilm.core.model.crypto;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.model.group.GroupModel;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
import static com.otilm.core.util.builders.CryptographicKeyFullModelBuilder.aKeySnapshot;
import static com.otilm.core.util.builders.CryptographicKeyItemBasicModelBuilder.aKeyItemSnapshot;
import static com.otilm.core.util.builders.CryptographicKeyItemBuilder.aKeyItem;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class CryptographicKeySnapshotsTest {

    @Test
    void from_returnsEmptyCertificateAssociationsForUnassociatedKey() {
        // given
        CryptographicKey key = aCryptographicKey().build();

        // when
        var snapshot = ImmutableCryptographicKeyFullModel.from(key);

        // then
        assertThat(snapshot.certificateAssociations()).isEmpty();
    }

    @Test
    void constructor_rejectsMissingCertificateAssociations() {
        // given
        var builder = aKeySnapshot().withAssociations(null);

        // when
        Executable construct = builder::build;

        // then
        assertThrows(NullPointerException.class, construct);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("metadataReferences")
    void from_selectsMetadataReferenceWhenPresent(List<MetadataAttribute> keyMeta) {
        // given
        CryptographicKeyItem entity = aKeyItem().build();
        UUID legacyReference = UUID.randomUUID();
        entity.setKeyReferenceUuid(legacyReference);
        entity.setKeyMeta(keyMeta);

        // when
        CryptographicKeyItemBasicModel snapshot = CryptographicKeyItemBasicModel.from(entity);

        // then
        assertThat(snapshot.reference()).isEqualTo(new RemoteKeyReference.MetadataReference(keyMeta));
    }

    @Test
    void from_usesUuidReferenceWhenMetadataIsAbsent() {
        // given
        CryptographicKeyItem entity = aKeyItem().build();
        UUID remoteUuid = UUID.randomUUID();
        entity.setKeyReferenceUuid(remoteUuid);

        // when
        CryptographicKeyItemBasicModel snapshot = CryptographicKeyItemBasicModel.from(entity);

        // then
        assertThat(snapshot.reference()).isEqualTo(new RemoteKeyReference.UuidReference(remoteUuid));
    }

    @Test
    void constructor_copiesUsages() {
        // given
        KeyUsage allowedUsage = KeyUsage.SIGN;
        List<KeyUsage> usages = new ArrayList<>(List.of(allowedUsage));
        CryptographicKeyItemBasicModel snapshot = aKeyItemSnapshot().withUsages(usages).build();

        // when
        usages.clear();

        // then
        assertThat(snapshot.usages()).containsExactly(allowedUsage);
    }

    @Test
    void constructor_copiesCollections() {
        // given
        GroupModel group = groupSnapshot();
        CryptographicKeyItemBasicModel item = aKeyItemSnapshot().build();
        KeyCertificateAssociationModel association = new KeyCertificateAssociationModel(UUID.randomUUID(),
                "signing.example.test");
        Set<GroupModel> groups = new HashSet<>(Set.of(group));
        List<CryptographicKeyItemBasicModel> items = new ArrayList<>(List.of(item));
        List<KeyCertificateAssociationModel> associations = new ArrayList<>(List.of(association));
        var snapshot = aKeySnapshot().withGroups(groups).withItems(items).withAssociations(associations).build();

        // when
        groups.clear();
        items.clear();
        associations.clear();

        // then
        assertThat(snapshot.groups()).containsExactly(group);
        assertThat(snapshot.items()).containsExactly(item);
        assertThat(snapshot.certificateAssociations()).containsExactly(association);
    }

    @Test
    void from_snapshotsBasicKeyGroups() {
        // given
        String originalGroupName = "signing-operators";
        Group group = new Group();
        group.setUuid(UUID.randomUUID());
        group.setName(originalGroupName);
        CryptographicKey entity = aCryptographicKey().build();
        entity.setGroups(new HashSet<>(Set.of(group)));
        var snapshot = ImmutableCryptographicKeyBasicModel.from(entity);

        // when
        group.setName("different-operators");
        entity.getGroups().clear();

        // then
        assertThat(snapshot.groups()).singleElement().satisfies(value -> {
            assertThat(value.uuid()).isEqualTo(group.getUuid());
            assertThat(value.name()).isEqualTo(originalGroupName);
        });
    }

    private static Stream<Arguments> metadataReferences() {
        MetadataAttributeV2 handle = new MetadataAttributeV2();
        handle.setName("provider-key-handle");
        return Stream
                .of(arguments(named("opaque handle", List.<MetadataAttribute>of(handle))),
                        arguments(named("empty handle still selects v2", List.<MetadataAttribute>of())));
    }

    private static GroupModel groupSnapshot() {
        return new GroupModel(UUID.randomUUID(), "signing-operators", null, null);
    }
}
