package com.otilm.core.mapper.crypto;

import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyListModel;
import com.otilm.core.model.crypto.RemoteKeyReference;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static com.otilm.core.util.builders.CryptographicKeyFullModelBuilder.aKeySnapshot;
import static com.otilm.core.util.builders.CryptographicKeyItemBasicModelBuilder.aKeyItemSnapshot;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

class CryptographicKeyDtoMapperTest {

    @Test
    void mapToDto_preservesListingFieldsWithoutReadingDetailAssociations() {
        // given
        CryptographicKey key = spy(keyWithOwnerAndToken());
        TokenInstanceReference token = spy(key.getTokenInstanceReference());
        key.setTokenInstanceReference(token);
        long certificateCount = 3;
        int expectedAssociationCount = 4;
        key.setItems(Set.of(item(key, ComplianceStatus.OK), item(key, ComplianceStatus.NOK)));

        // when
        var model = ImmutableCryptographicKeyListModel.from(key, certificateCount);
        KeyDto dto = CryptographicKeyDtoMapper.mapToDto(model);

        // then
        assertThat(dto.getUuid()).isEqualTo(key.getUuid().toString());
        assertThat(dto.getName()).isEqualTo(key.getName());
        assertThat(dto.getDescription()).isEqualTo(key.getDescription());
        assertThat(dto.getCreationTime()).isEqualTo(key.getCreated());
        assertThat(dto.getOwnerUuid()).isEqualTo(key.getOwner().getOwnerUuid().toString());
        assertThat(dto.getOwner()).isEqualTo(key.getOwner().getOwnerUsername());
        assertThat(dto.getTokenProfileUuid()).isEqualTo(key.getTokenProfileUuid().toString());
        assertThat(dto.getTokenProfileName()).isEqualTo(key.getTokenProfile().getName());
        assertThat(dto.getTokenInstanceUuid()).isEqualTo(token.getUuid().toString());
        assertThat(dto.getTokenInstanceName()).isEqualTo(token.getName());
        assertThat(dto.getGroups())
                .singleElement()
                .satisfies(group -> assertThat(group.getUuid())
                        .isEqualTo(key.getGroups().iterator().next().getUuid().toString()));
        assertThat(dto.getAssociations()).isEqualTo(expectedAssociationCount);
        assertThat(dto.getComplianceStatus()).isEqualTo(ComplianceStatus.NOK);
        assertThat(dto.getItems()).hasSize(model.items().size()).allSatisfy(item -> {
            assertThat(item.getKeyWrapperUuid()).isEqualTo(dto.getUuid());
            assertThat(item.getOwnerUuid()).isEqualTo(dto.getOwnerUuid());
            assertThat(item.getTokenProfileName()).isEqualTo(dto.getTokenProfileName());
            assertThat(item.getTokenInstanceName()).isEqualTo(dto.getTokenInstanceName());
        });
        verify(key, never()).getCertificates();
        verify(key, never()).getAltCertificates();
        verify(token, never()).getTokenProfiles();
        verify(token, never()).getConnectorInterface();
    }

    @Test
    void mapToDto_supportsListingWithoutOwnerOrToken() {
        // given
        CryptographicKey key = key();
        long noCertificates = 0;

        // when
        KeyDto dto = CryptographicKeyDtoMapper.mapToDto(ImmutableCryptographicKeyListModel.from(key, noCertificates));

        // then
        assertThat(dto.getOwnerUuid()).isNull();
        assertThat(dto.getTokenProfileUuid()).isNull();
        assertThat(dto.getTokenInstanceUuid()).isNull();
        assertThat(dto.getAssociations()).isZero();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keyMaterialResponses")
    void mapItemToDetailDto_describesMissingMaterialAndPreservesExistingMaterial(CryptographicKeyItemBasicModel item,
            KeyFormat expectedFormat, String expectedData) {
        // given
        var model = aKeySnapshot().withItems(List.of(item)).build();

        // when
        var dto = CryptographicKeyDtoMapper.mapItemToDetailDto(item);
        var nestedItems = CryptographicKeyDtoMapper.getKeyItems(model);

        // then
        assertThat(dto.getFormat()).isEqualTo(expectedFormat);
        assertThat(dto.getKeyData()).isEqualTo(expectedData);
        assertThat(nestedItems).singleElement().satisfies(nested -> {
            assertThat(nested.getFormat()).isEqualTo(expectedFormat);
            assertThat(nested.getKeyData()).isEqualTo(expectedData);
        });
    }

    /** The parent key's items answer the export permission, so they agree with the key item read on its own. */
    @Test
    void mapItemToDetailDto_statesTheExportPermission() {
        // given
        CryptographicKeyItemBasicModel item = aKeyItemSnapshot().withExportable(true).build();
        var model = aKeySnapshot().withItems(List.of(item)).build();

        // when
        var dto = CryptographicKeyDtoMapper.mapItemToDetailDto(item);
        var nestedItems = CryptographicKeyDtoMapper.getKeyItems(model);

        // then
        assertThat(dto.isExportable()).isTrue();
        assertThat(nestedItems).singleElement().satisfies(nested -> assertThat(nested.isExportable()).isTrue());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keyMaterialResponses")
    void getKeyItemsSummary_matchesDetailFormat(CryptographicKeyItemBasicModel item, KeyFormat expectedFormat) {
        // given
        var model = aKeySnapshot().withItems(List.of(item)).build();

        // when
        var items = CryptographicKeyDtoMapper.getKeyItemsSummary(model);

        // then
        assertThat(items).singleElement().satisfies(dto -> assertThat(dto.getFormat()).isEqualTo(expectedFormat));
    }

    private static Stream<Arguments> keyMaterialResponses() {
        String providerMessage = "Key material is managed by the cryptography provider and is not available in Core.";
        String encodedMaterial = "cHJpdmF0ZS1rZXktbWF0ZXJpYWw=";
        String customMaterial = "provider-specific key representation";
        return Stream
                .of(arguments(named("missing material and format", aKeyItemSnapshot().withFormat(null).build()),
                        KeyFormat.CUSTOM, providerMessage),
                        arguments(named("missing material with known format", aKeyItemSnapshot().build()),
                                KeyFormat.CUSTOM, providerMessage),
                        arguments(named("encoded material", aKeyItemSnapshot().withKeyData(encodedMaterial).build()),
                                KeyFormat.PRKI, encodedMaterial),
                        arguments(named("custom material",
                                aKeyItemSnapshot().withFormat(KeyFormat.CUSTOM).withKeyData(customMaterial).build()),
                                KeyFormat.CUSTOM, customMaterial));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keyMappers")
    void mapKey_preservesOwnershipAndTokenContext(Function<CryptographicKeyFullModel, KeyDto> mapper) {
        // given
        var context = ImmutableCryptographicKeyFullModel.from(keyWithOwnerAndToken());
        var model = aKeySnapshot()
                .withTokenProfile(context.tokenProfile())
                .withTokenInstance(context.tokenInstance())
                .withOwner(context.ownerUuid(), context.ownerName())
                .withGroups(context.groups())
                .build();

        // when
        KeyDto dto = mapper.apply(model);

        // then
        assertThat(dto.getTokenProfileUuid()).isEqualTo(context.tokenProfile().uuid().toString());
        assertThat(dto.getTokenProfileName()).isEqualTo(context.tokenProfile().name());
        assertThat(dto.getTokenInstanceUuid()).isEqualTo(context.tokenInstance().uuid().toString());
        assertThat(dto.getTokenInstanceName()).isEqualTo(context.tokenInstance().name());
        assertThat(dto.getOwnerUuid()).isEqualTo(context.ownerUuid().toString());
        assertThat(dto.getOwner()).isEqualTo(context.ownerName());
        assertThat(dto.getGroups()).singleElement().satisfies(group -> {
            assertThat(group.getUuid()).isEqualTo(context.groups().iterator().next().uuid().toString());
            assertThat(group.getName()).isEqualTo(context.groups().iterator().next().name());
        });
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("complianceStatuses")
    void mapToDto_usesHighestPriorityComplianceStatus(List<ComplianceStatus> statuses, ComplianceStatus expected) {
        // given
        CryptographicKeyFullModel model = keyWithComplianceStatuses(statuses);

        // when
        KeyDto dto = CryptographicKeyDtoMapper.mapToDto(model);

        // then
        assertThat(dto.getComplianceStatus()).isEqualTo(expected);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("complianceStatuses")
    void mapToDetailDto_usesHighestPriorityComplianceStatus(List<ComplianceStatus> statuses,
            ComplianceStatus expected) {
        // given
        CryptographicKeyFullModel model = keyWithComplianceStatuses(statuses);

        // when
        KeyDetailDto dto = CryptographicKeyDtoMapper.mapToDetailDto(model);

        // then
        assertThat(dto.getComplianceStatus()).isEqualTo(expected);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("complianceStatuses")
    void mapToChainDto_usesHighestPriorityComplianceStatus(List<ComplianceStatus> statuses, ComplianceStatus expected) {
        // given
        CryptographicKeyFullModel model = keyWithComplianceStatuses(statuses);

        // when
        KeyDto dto = CryptographicKeyDtoMapper.mapToChainDto(model);

        // then
        assertThat(dto.getComplianceStatus()).isEqualTo(expected);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("providerReferences")
    void mapItemToDetailDto_exposesOnlyUuidProviderReferences(RemoteKeyReference reference, String expectedUuid) {
        // given
        CryptographicKeyItemBasicModel item = aKeyItemSnapshot().withReference(reference).build();

        // when
        var dto = CryptographicKeyDtoMapper.mapItemToDetailDto(item);

        // then
        assertThat(dto.getKeyReferenceUuid()).isEqualTo(expectedUuid);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("providerReferences")
    void getKeyItems_exposesOnlyUuidProviderReferences(RemoteKeyReference reference, String expectedUuid) {
        // given
        CryptographicKeyItemBasicModel item = aKeyItemSnapshot().withReference(reference).build();
        var model = aKeySnapshot().withItems(List.of(item)).build();

        // when
        var items = CryptographicKeyDtoMapper.getKeyItems(model);

        // then
        assertThat(items)
                .singleElement()
                .satisfies(dto -> assertThat(dto.getKeyReferenceUuid()).isEqualTo(expectedUuid));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("providerReferences")
    void getKeyItemsSummary_exposesOnlyUuidProviderReferences(RemoteKeyReference reference, String expectedUuid) {
        // given
        CryptographicKeyItemBasicModel item = aKeyItemSnapshot().withReference(reference).build();
        var model = aKeySnapshot().withItems(List.of(item)).build();

        // when
        var items = CryptographicKeyDtoMapper.getKeyItemsSummary(model);

        // then
        assertThat(items)
                .singleElement()
                .satisfies(dto -> assertThat(dto.getKeyReferenceUuid()).isEqualTo(expectedUuid));
    }

    @Test
    void mapToDetailDto_includesPrimaryAndAlternativeCertificateAssociations() {
        // given
        CryptographicKey key = key();
        Certificate primaryCertificate = certificate("primary.example.test");
        Certificate alternativeCertificate = certificate("alternative.example.test");
        key.setCertificates(Set.of(primaryCertificate));
        key.setAltCertificates(Set.of(alternativeCertificate));
        CryptographicKeyFullModel model = ImmutableCryptographicKeyFullModel.from(key);

        // when
        KeyDetailDto dto = CryptographicKeyDtoMapper.mapToDetailDto(model);

        // then
        assertThat(dto.getAssociations())
                .extracting(association -> association.getUuid())
                .containsExactlyInAnyOrder(primaryCertificate.getUuid().toString(),
                        alternativeCertificate.getUuid().toString());
    }

    @Test
    void getKeyItemsSummary_inheritsWrapperOwnershipAndTokenContext() {
        // given
        CryptographicKey key = keyWithOwnerAndToken();
        CryptographicKeyFullModel model = ImmutableCryptographicKeyFullModel.from(key);

        // when
        var items = CryptographicKeyDtoMapper.getKeyItemsSummary(model);

        // then
        assertThat(items).singleElement().satisfies(dto -> {
            assertThat(dto.getKeyWrapperUuid()).isEqualTo(key.getUuid().toString());
            assertThat(dto.getOwnerUuid()).isEqualTo(key.getOwner().getOwnerUuid().toString());
            assertThat(dto.getOwner()).isEqualTo(key.getOwner().getOwnerUsername());
            assertThat(dto.getTokenProfileUuid()).isEqualTo(key.getTokenProfileUuid().toString());
            assertThat(dto.getTokenProfileName()).isEqualTo(key.getTokenProfile().getName());
            assertThat(dto.getTokenInstanceUuid()).isEqualTo(key.getTokenInstanceReferenceUuid().toString());
            assertThat(dto.getTokenInstanceName()).isEqualTo(key.getTokenInstanceReference().getName());
            assertThat(dto.getGroups().getFirst().getUuid())
                    .isEqualTo(key.getGroups().iterator().next().getUuid().toString());
        });
    }

    @Test
    void mapToDetailDto_preservesWrapperFieldsAndCertificateAssociations() {
        // given
        CryptographicKey key = key();
        UUID certificateUuid = UUID.randomUUID();
        String certificateName = "signing.example.test";
        Certificate certificate = new Certificate();
        certificate.setUuid(certificateUuid);
        certificate.setCommonName(certificateName);
        key.setCertificates(Set.of(certificate));
        CryptographicKeyFullModel model = ImmutableCryptographicKeyFullModel.from(key);

        // when
        KeyDetailDto dto = CryptographicKeyDtoMapper.mapToDetailDto(model);

        // then
        assertThat(dto.getUuid()).isEqualTo(key.getUuid().toString());
        assertThat(dto.getName()).isEqualTo(key.getName());
        assertThat(dto.getDescription()).isEqualTo(key.getDescription());
        assertThat(dto.getCreationTime()).isEqualTo(key.getCreated());
        assertThat(dto.getItems().size()).isEqualTo(1);
        assertThat(dto.getAssociations().size()).isEqualTo(1);
        assertThat(dto.getAssociations().getFirst().getUuid()).isEqualTo(certificateUuid.toString());
        assertThat(dto.getAssociations().getFirst().getName()).isEqualTo(certificateName);
        assertThat(dto.getAssociations().getFirst().getResource()).isEqualTo(Resource.CERTIFICATE);
    }

    @Test
    void mapToDto_aggregatesComplianceAndAssociationCount() {
        // given
        CryptographicKey key = key();
        CryptographicKeyItem failedItem = item(key, ComplianceStatus.FAILED);
        CryptographicKeyItem noncompliantItem = item(key, ComplianceStatus.NOK);
        key.setItems(Set.of(failedItem, noncompliantItem));
        CryptographicKeyFullModel model = ImmutableCryptographicKeyFullModel.from(key);

        // when
        KeyDto dto = CryptographicKeyDtoMapper.mapToDto(model);

        // then
        assertThat(dto.getComplianceStatus()).isEqualTo(ComplianceStatus.NOK);
        assertThat(dto.getAssociations()).isEqualTo(1);
        assertThat(dto.getItems().size()).isEqualTo(2);
    }

    @Test
    void mapToChainDto_doesNotReadCertificateCollections() {
        // given
        CryptographicKey key = spy(key());
        var model = ImmutableCryptographicKeyListModel.from(key, 0);

        // when
        KeyDto dto = CryptographicKeyDtoMapper.mapToChainDto(model);

        // then
        assertThat(dto.getUuid()).isEqualTo(key.getUuid().toString());
        assertThat(dto.getItems().size()).isEqualTo(1);
        verify(key, never()).getCertificates();
        verify(key, never()).getAltCertificates();
    }

    @Test
    void mapToDetailDto_usesSnapshotAfterEntitiesChange() {
        // given
        CryptographicKey key = key();
        String originalName = key.getName();
        String groupName = "Operators";
        String ownerName = "key-owner";
        Group group = new Group();
        group.setUuid(UUID.randomUUID());
        group.setName(groupName);
        key.setGroups(Set.of(group));
        OwnerAssociation owner = new OwnerAssociation();
        owner.setOwnerUuid(UUID.randomUUID());
        owner.setOwnerUsername(ownerName);
        key.setOwner(owner);
        CryptographicKeyFullModel model = ImmutableCryptographicKeyFullModel.from(key);
        key.setName("Changed key");
        group.setName("Changed group");
        owner.setOwnerUsername("changed-owner");
        key.getItems().iterator().next().setComplianceStatus(ComplianceStatus.NOK);

        // when
        KeyDetailDto dto = CryptographicKeyDtoMapper.mapToDetailDto(model);

        // then
        assertThat(dto.getName()).isEqualTo(originalName);
        assertThat(dto.getGroups().getFirst().getName()).isEqualTo(groupName);
        assertThat(dto.getOwner()).isEqualTo(ownerName);
        assertThat(dto.getItems().getFirst().getComplianceStatus()).isEqualTo(ComplianceStatus.OK);
    }

    private static CryptographicKey key() {
        CryptographicKey key = new CryptographicKey();
        key.setUuid(UUID.randomUUID());
        key.setName("Signing key");
        key.setDescription("Application signing");
        key.setCreated(OffsetDateTime.parse("2026-09-10T10:00:00Z"));
        CryptographicKeyItem item = item(key, ComplianceStatus.OK);
        key.setItems(Set.of(item));
        return key;
    }

    private static Stream<Arguments> complianceStatuses() {
        return Stream
                .of(arguments(named("no items", List.<ComplianceStatus>of()), ComplianceStatus.NOT_CHECKED),
                        arguments(named("null statuses only", Arrays.asList(null, null)), ComplianceStatus.NOT_CHECKED),
                        arguments(named("OK ignores null", Arrays.asList(null, ComplianceStatus.OK)),
                                ComplianceStatus.OK),
                        arguments(
                                named("unchecked outranks OK",
                                        List.of(ComplianceStatus.OK, ComplianceStatus.NOT_CHECKED)),
                                ComplianceStatus.NOT_CHECKED),
                        arguments(
                                named("not applicable outranks unchecked",
                                        List.of(ComplianceStatus.NOT_CHECKED, ComplianceStatus.NA)),
                                ComplianceStatus.NA),
                        arguments(
                                named("failed outranks not applicable",
                                        List.of(ComplianceStatus.NA, ComplianceStatus.FAILED)),
                                ComplianceStatus.FAILED),
                        arguments(named("noncompliant outranks failed",
                                List.of(ComplianceStatus.FAILED, ComplianceStatus.NOK)), ComplianceStatus.NOK));
    }

    private static Stream<Arguments> keyMappers() {
        Function<CryptographicKeyFullModel, KeyDto> summary = CryptographicKeyDtoMapper::mapToDto;
        Function<CryptographicKeyFullModel, KeyDto> chain = CryptographicKeyDtoMapper::mapToChainDto;
        return Stream.of(arguments(named("summary", summary)), arguments(named("chain", chain)));
    }

    private static Stream<Arguments> providerReferences() {
        UUID remoteUuid = UUID.randomUUID();
        return Stream
                .of(arguments(named("legacy UUID", new RemoteKeyReference.UuidReference(remoteUuid)),
                        remoteUuid.toString()),
                        arguments(named("unassigned UUID", new RemoteKeyReference.UuidReference(null)), null),
                        arguments(named("opaque metadata", new RemoteKeyReference.MetadataReference(List.of())), null));
    }

    private static CryptographicKeyFullModel keyWithComplianceStatuses(List<ComplianceStatus> statuses) {
        List<CryptographicKeyItemBasicModel> items = statuses
                .stream()
                .map(status -> aKeyItemSnapshot().withComplianceStatus(status).build())
                .toList();
        return aKeySnapshot().withItems(items).build();
    }

    private static Certificate certificate(String commonName) {
        Certificate certificate = new Certificate();
        certificate.setUuid(UUID.randomUUID());
        certificate.setCommonName(commonName);
        return certificate;
    }

    private static CryptographicKey keyWithOwnerAndToken() {
        CryptographicKey key = key();
        OwnerAssociation owner = new OwnerAssociation();
        owner.setOwnerUuid(UUID.randomUUID());
        owner.setOwnerUsername("signing-owner");
        key.setOwner(owner);
        Group group = new Group();
        group.setUuid(UUID.randomUUID());
        group.setName("signing-operators");
        key.setGroups(Set.of(group));
        TokenInstanceReference token = new TokenInstanceReference();
        token.setUuid(UUID.randomUUID());
        token.setName("signing-token");
        key.setTokenInstanceReference(token);
        TokenProfile profile = new TokenProfile();
        profile.setUuid(UUID.randomUUID());
        profile.setName("signing-profile");
        profile.setTokenInstanceReference(token);
        key.setTokenProfile(profile);
        return key;
    }

    private static CryptographicKeyItem item(CryptographicKey key, ComplianceStatus status) {
        CryptographicKeyItem item = new CryptographicKeyItem();
        item.setUuid(UUID.randomUUID());
        item.setKey(key);
        item.setComplianceStatus(status);
        return item;
    }
}
