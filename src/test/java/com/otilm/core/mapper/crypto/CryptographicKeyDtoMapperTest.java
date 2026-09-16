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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

class CryptographicKeyDtoMapperTest {

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
        assertEquals(expectedFormat, dto.getFormat());
        assertEquals(expectedData, dto.getKeyData());
        assertThat(nestedItems).singleElement().satisfies(nested -> {
            assertEquals(expectedFormat, nested.getFormat());
            assertEquals(expectedData, nested.getKeyData());
        });
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keyMaterialResponses")
    void getKeyItemsSummary_matchesDetailFormat(CryptographicKeyItemBasicModel item, KeyFormat expectedFormat) {
        // given
        var model = aKeySnapshot().withItems(List.of(item)).build();

        // when
        var items = CryptographicKeyDtoMapper.getKeyItemsSummary(model);

        // then
        assertThat(items).singleElement().satisfies(dto -> assertEquals(expectedFormat, dto.getFormat()));
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
        assertEquals(context.tokenProfile().uuid().toString(), dto.getTokenProfileUuid());
        assertEquals(context.tokenProfile().name(), dto.getTokenProfileName());
        assertEquals(context.tokenInstance().uuid().toString(), dto.getTokenInstanceUuid());
        assertEquals(context.tokenInstance().name(), dto.getTokenInstanceName());
        assertEquals(context.ownerUuid().toString(), dto.getOwnerUuid());
        assertEquals(context.ownerName(), dto.getOwner());
        assertThat(dto.getGroups()).singleElement().satisfies(group -> {
            assertEquals(context.groups().iterator().next().uuid().toString(), group.getUuid());
            assertEquals(context.groups().iterator().next().name(), group.getName());
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
        assertEquals(expected, dto.getComplianceStatus());
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
        assertEquals(expected, dto.getComplianceStatus());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("complianceStatuses")
    void mapToChainDto_usesHighestPriorityComplianceStatus(List<ComplianceStatus> statuses, ComplianceStatus expected) {
        // given
        CryptographicKeyFullModel model = keyWithComplianceStatuses(statuses);

        // when
        KeyDto dto = CryptographicKeyDtoMapper.mapToChainDto(model);

        // then
        assertEquals(expected, dto.getComplianceStatus());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("providerReferences")
    void mapItemToDetailDto_exposesOnlyUuidProviderReferences(RemoteKeyReference reference, String expectedUuid) {
        // given
        CryptographicKeyItemBasicModel item = aKeyItemSnapshot().withReference(reference).build();

        // when
        var dto = CryptographicKeyDtoMapper.mapItemToDetailDto(item);

        // then
        assertEquals(expectedUuid, dto.getKeyReferenceUuid());
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
        assertThat(items).singleElement().satisfies(dto -> assertEquals(expectedUuid, dto.getKeyReferenceUuid()));
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
        assertThat(items).singleElement().satisfies(dto -> assertEquals(expectedUuid, dto.getKeyReferenceUuid()));
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
            assertEquals(key.getUuid().toString(), dto.getKeyWrapperUuid());
            assertEquals(key.getOwner().getOwnerUuid().toString(), dto.getOwnerUuid());
            assertEquals(key.getOwner().getOwnerUsername(), dto.getOwner());
            assertEquals(key.getTokenProfileUuid().toString(), dto.getTokenProfileUuid());
            assertEquals(key.getTokenProfile().getName(), dto.getTokenProfileName());
            assertEquals(key.getTokenInstanceReferenceUuid().toString(), dto.getTokenInstanceUuid());
            assertEquals(key.getTokenInstanceReference().getName(), dto.getTokenInstanceName());
            assertEquals(key.getGroups().iterator().next().getUuid().toString(), dto.getGroups().getFirst().getUuid());
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
        assertEquals(key.getUuid().toString(), dto.getUuid());
        assertEquals(key.getName(), dto.getName());
        assertEquals(key.getDescription(), dto.getDescription());
        assertEquals(key.getCreated(), dto.getCreationTime());
        assertEquals(1, dto.getItems().size());
        assertEquals(1, dto.getAssociations().size());
        assertEquals(certificateUuid.toString(), dto.getAssociations().getFirst().getUuid());
        assertEquals(certificateName, dto.getAssociations().getFirst().getName());
        assertEquals(Resource.CERTIFICATE, dto.getAssociations().getFirst().getResource());
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
        assertEquals(ComplianceStatus.NOK, dto.getComplianceStatus());
        assertEquals(1, dto.getAssociations());
        assertEquals(2, dto.getItems().size());
    }

    @Test
    void mapToChainDto_doesNotReadCertificateCollections() {
        // given
        CryptographicKey key = spy(key());
        CryptographicKeyFullModel model = ImmutableCryptographicKeyFullModel.fromForChain(key);

        // when
        KeyDto dto = CryptographicKeyDtoMapper.mapToChainDto(model);

        // then
        assertEquals(key.getUuid().toString(), dto.getUuid());
        assertEquals(1, dto.getItems().size());
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
        assertEquals(originalName, dto.getName());
        assertEquals(groupName, dto.getGroups().getFirst().getName());
        assertEquals(ownerName, dto.getOwner());
        assertEquals(ComplianceStatus.OK, dto.getItems().getFirst().getComplianceStatus());
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
