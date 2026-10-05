package com.otilm.core.integration.discovery;

import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.metadata.MetadataResponseDto;
import com.otilm.api.model.client.metadata.ResponseMetadata;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.connector.discovery.DiscoveryProviderCertificateDataDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredCertificateDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryItemDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryCertificate;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.events.handlers.CertificateDiscoveredEventHandler;
import com.otilm.core.mapper.discovery.DiscoveryDtoMapper;
import com.otilm.core.service.handler.CertificateHandler;
import com.otilm.core.service.handler.discovery.StagedMetadata;
import com.otilm.core.service.writer.discovery.DiscoveryItemWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Metadata attributes a connector declares encrypted are held apart and encrypted while discovery stages them, and
 * every reader of the staging tables gets them back.
 */
class StagedMetadataITest extends BaseSpringBootTest {

    private static final String SECRET = "s3cr3t-value";

    @Autowired
    private CertificateHandler certificateHandler;
    @Autowired
    private DiscoveryItemWriter itemWriter;
    @Autowired
    private DiscoveryItemRepository itemRepository;
    @Autowired
    private DiscoveryCertificateRepository discoveryCertificateRepository;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateDiscoveredEventHandler certificateDiscoveredEventHandler;
    @Autowired
    private AttributeEngine attributeEngine;

    private Discovery discovery;

    @BeforeEach
    void setUp() {
        Connector connector = new Connector();
        connector.setVersion(ConnectorVersion.V1);
        connector = connectorRepository.save(connector);
        discovery = new Discovery();
        discovery.setName("staged-metadata");
        discovery.setKind("IP");
        discovery.setStatus(DiscoveryStatus.PROCESSING);
        discovery.setConnectorStatus(DiscoveryStatus.COMPLETED);
        discovery.setConnectorUuid(connector.getUuid());
        discovery = discoveryRepository.save(discovery);
    }

    @Test
    void sealingWithoutProtectedAttributesKeepsEverythingInTheClear() {
        List<MetadataAttribute> meta = List.of(attribute("host", "web-1", ProtectionLevel.NONE));

        StagedMetadata.Sealed sealed = StagedMetadata.seal(meta);

        assertThat(sealed.meta()).isEqualTo(meta);
        assertThat(sealed.protectedMeta()).isNull();
    }

    @Test
    void unsealingPutsProtectedAttributesBack() {
        StagedMetadata.Sealed sealed = StagedMetadata.seal(mixedMeta());

        assertThat(names(sealed.meta())).containsExactly("host");
        assertThat(sealed.protectedMeta()).isNotNull().doesNotContain(SECRET);
        List<MetadataAttribute> unsealed = StagedMetadata.unseal(sealed.meta(), sealed.protectedMeta());
        assertThat(names(unsealed)).containsExactly("host", "token");
        assertThat(valueOf(unsealed, "token")).isEqualTo(SECRET);
    }

    @Test
    void aRowStagedBeforeTheSplitReadsAsStored() {
        List<MetadataAttribute> legacy = mixedMeta();

        assertThat(StagedMetadata.unseal(legacy, null)).isSameAs(legacy);
    }

    @Test
    void anUnreadableProtectedValueLeavesOnlyTheVisibleMetadata() {
        List<MetadataAttribute> visible = List.of(attribute("host", "web-1", ProtectionLevel.NONE));

        assertThat(names(StagedMetadata.unseal(visible, "not-a-sealed-value"))).containsExactly("host");
    }

    @Test
    void aStagedCertificateKeepsProtectedMetadataEncryptedAndTheImportRestoresIt() throws Exception {
        X509Certificate x509 = selfSignedCertificate();
        DiscoveryProviderCertificateDataDto discovered = new DiscoveryProviderCertificateDataDto();
        discovered.setUuid(UUID.randomUUID().toString());
        discovered.setBase64Content(Base64.getEncoder().encodeToString(x509.getEncoded()));
        discovered.setMeta(mixedMeta());

        certificateHandler.stageDiscoveredCertificates("1", discovery, List.of(discovered), false);

        DiscoveryCertificate staged = discoveryCertificateRepository.findAll().getFirst();
        assertThat(names(staged.getMeta())).containsExactly("host");
        assertThat(staged.getProtectedMeta()).isNotNull().doesNotContain(SECRET);

        certificateDiscoveredEventHandler
                .handleEvent(CertificateDiscoveredEventHandler.constructEventMessage(discovery.getUuid(), null, null));

        UUID certificateUuid = certificateRepository
                .findByFingerprint(CertificateUtil.getThumbprint(x509))
                .orElseThrow()
                .getUuid();
        List<ResponseMetadata> imported = attributeEngine
                .getMappedMetadataContent(
                        ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificateUuid).build())
                .stream()
                .map(MetadataResponseDto::getItems)
                .flatMap(List::stream)
                .toList();
        assertThat(imported).extracting(ResponseMetadata::getName).contains("host", "token");
        assertThat(imported
                .stream()
                .filter(item -> "token".equals(item.getName()))
                .flatMap(item -> item.<AttributeContent>getContent().stream())
                .map(content -> Objects.toString(content.getData()))).containsExactly(SECRET);
    }

    @Test
    void aStagedItemKeepsProtectedMetadataEncryptedAndTheListingRestoresIt() {
        DiscoveredCertificateDto payload = new DiscoveredCertificateDto();
        payload.setCertificateData("certificate-bytes");
        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setSequence(1L);
        item.setUniqueRef("ref-1");
        item.setPayload(payload);
        item.setDiscoveredAt(OffsetDateTime.now(ZoneOffset.UTC));
        item.setMeta(mixedMeta());

        itemWriter.stage(discovery.getUuid(), item, true);

        DiscoveryItem staged = itemRepository.findAll().getFirst();
        assertThat(names(staged.getMeta())).containsExactly("host");
        assertThat(staged.getProtectedMeta()).isNotNull().doesNotContain(SECRET);
        DiscoveryItemDto listed = DiscoveryDtoMapper
                .toItemDto(itemRepository.listItems(discovery.getUuid(), null, null, 50, 0).getFirst());
        assertThat(names(listed.getMeta())).containsExactly("host", "token");
        assertThat(valueOf(listed.getMeta(), "token")).isEqualTo(SECRET);
    }

    private static List<MetadataAttribute> mixedMeta() {
        return List
                .of(attribute("host", "web-1", ProtectionLevel.NONE),
                        attribute("token", SECRET, ProtectionLevel.ENCRYPTED));
    }

    private static MetadataAttribute attribute(String name, String value, ProtectionLevel protectionLevel) {
        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setUuid(UUID.nameUUIDFromBytes(name.getBytes(StandardCharsets.UTF_8)).toString());
        attribute.setName(name);
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV2(null, value)));
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel(name);
        properties.setProtectionLevel(protectionLevel);
        attribute.setProperties(properties);
        return attribute;
    }

    private static List<String> names(List<? extends MetadataAttribute> meta) {
        return meta.stream().map(MetadataAttribute::getName).toList();
    }

    private static String valueOf(List<? extends MetadataAttribute> meta, String name) {
        return meta
                .stream()
                .filter(attribute -> name.equals(attribute.getName()))
                .flatMap(attribute -> attribute.<List<AttributeContent>>getContent().stream())
                .map(content -> Objects.toString(content.getData()))
                .findFirst()
                .orElseThrow();
    }

    private static X509Certificate selfSignedCertificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        X500Name subject = new X500Name("CN=staged-metadata-itest-" + UUID.randomUUID());
        Instant now = Instant.now();
        return new JcaX509CertificateConverter()
                .getCertificate(new JcaX509v3CertificateBuilder(subject, BigInteger.valueOf(now.toEpochMilli()),
                        Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(86400)), subject,
                        keyPair.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())));
    }
}
