package com.otilm.core.mapper.certificate;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.api.model.core.certificate.CertificateExtensionDto;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.extension.ExtensionTypes;
import com.otilm.core.extension.JerCodec;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateExtensionDtoMapperTest {

    private static final String BASIC_CONSTRAINTS = "2.5.29.19";
    private static final String PRIVATE_KEY_USAGE_PERIOD = "2.5.29.16";
    private static final String NAME_CONSTRAINTS = "2.5.29.30";
    private static final String UNDESCRIBED = "1.2.3.4.5";
    private static final String BROKEN_MODULE = "1.2.3.4.6";

    // The OidHandler cache is process-wide static state shared across the whole test JVM.
    private static Map<String, OidRecord> savedExtensionCache;

    @BeforeAll
    static void snapshotExtensionCache() {
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.CERTIFICATE_EXTENSION);
        savedExtensionCache = existing == null ? null : new HashMap<>(existing);
    }

    @AfterAll
    static void restoreExtensionCache() {
        OidHandler
                .cacheOidCategory(OidCategory.CERTIFICATE_EXTENSION,
                        savedExtensionCache != null ? savedExtensionCache : new HashMap<>());
    }

    @BeforeEach
    void seedExtensionRegistry() {
        OidHandler.cacheOidCategory(OidCategory.CERTIFICATE_EXTENSION, new HashMap<>());
        OidHandler
                .cacheOid(OidCategory.CERTIFICATE_EXTENSION, BROKEN_MODULE,
                        OidRecord.builder().displayName("Broken").valueSchema("this is not an ASN.1 module").build());
    }

    private static Extensions extensions(Object... oidCriticalValue) throws IOException {
        ExtensionsGenerator generator = new ExtensionsGenerator();
        for (int i = 0; i < oidCriticalValue.length; i += 3) {
            generator
                    .addExtension(new ASN1ObjectIdentifier((String) oidCriticalValue[i]),
                            (Boolean) oidCriticalValue[i + 1], (byte[]) oidCriticalValue[i + 2]);
        }
        return generator.generate();
    }

    private static byte[] privateKeyUsagePeriod(int tag) throws IOException {
        return new DERSequence(new DERTaggedObject(false, tag, new DERGeneralizedTime("20300101000000Z"))).getEncoded();
    }

    private static byte[] nameConstraints() throws IOException {
        DERSequence subtree = new DERSequence(
                new DERSequence(new DERTaggedObject(false, 2, new DERIA5String("a.test"))));
        return new DERSequence(new DERTaggedObject(false, 0, subtree)).getEncoded();
    }

    private static final byte[] EMPTY_SEQUENCE = {0x30, 0x00};

    @Test
    void basicConstraintsDefaultReadsAsEffectiveValue() throws IOException {
        List<CertificateExtensionDto> dtos = CertificateExtensionDtoMapper
                .toDtos(extensions(BASIC_CONSTRAINTS, true, EMPTY_SEQUENCE));

        assertThat(dtos).hasSize(1);
        assertThat(dtos.get(0).getJer().toString()).isEqualTo("{\"cA\":false}");
    }

    @Test
    void privateKeyUsagePeriodIsToldApartByTag() throws IOException {
        JsonNode notAfterOnly = CertificateExtensionDtoMapper
                .toDtos(extensions(PRIVATE_KEY_USAGE_PERIOD, false, privateKeyUsagePeriod(1)))
                .get(0)
                .getJer();
        JsonNode notBeforeOnly = CertificateExtensionDtoMapper
                .toDtos(extensions(PRIVATE_KEY_USAGE_PERIOD, false, privateKeyUsagePeriod(0)))
                .get(0)
                .getJer();

        assertThat(notAfterOnly.has("notAfter")).isTrue();
        assertThat(notAfterOnly.has("notBefore")).isFalse();
        assertThat(notBeforeOnly.has("notBefore")).isTrue();
        assertThat(notBeforeOnly.has("notAfter")).isFalse();
    }

    @Test
    void nameConstraintsDecodes() throws IOException {
        List<CertificateExtensionDto> dtos = CertificateExtensionDtoMapper
                .toDtos(extensions(NAME_CONSTRAINTS, true, nameConstraints()));

        assertThat(dtos.get(0).getJer()).isNotNull();
    }

    @Test
    void decodedJerReencodesToTheSameDer() throws IOException {
        Map<String, byte[]> values = Map
                .of(BASIC_CONSTRAINTS, EMPTY_SEQUENCE, PRIVATE_KEY_USAGE_PERIOD, privateKeyUsagePeriod(1),
                        NAME_CONSTRAINTS, nameConstraints());

        for (Map.Entry<String, byte[]> value : values.entrySet()) {
            CertificateExtensionDto entry = CertificateExtensionDtoMapper
                    .toDtos(extensions(value.getKey(), false, value.getValue()))
                    .get(0);

            assertThat(JerCodec.encode(entry.getJer(), ExtensionTypes.resolve(value.getKey()).orElseThrow()))
                    .as(value.getKey())
                    .isEqualTo(value.getValue());
        }
    }

    @Test
    void extensionWithoutModuleListsDerOnly() throws IOException {
        List<CertificateExtensionDto> dtos = CertificateExtensionDtoMapper
                .toDtos(extensions(UNDESCRIBED, false, new byte[]{1, 2, 3}));

        assertThat(dtos).hasSize(1);
        assertThat(dtos.get(0).getJer()).isNull();
        assertThat(dtos.get(0).getDer()).isEqualTo(Base64.getEncoder().encodeToString(new byte[]{1, 2, 3}));
    }

    @Test
    void undecodableValueListsDerOnly() throws IOException {
        List<CertificateExtensionDto> dtos = CertificateExtensionDtoMapper
                .toDtos(extensions(BASIC_CONSTRAINTS, false, new byte[]{(byte) 0xFF, (byte) 0xFF},
                        PRIVATE_KEY_USAGE_PERIOD, false, privateKeyUsagePeriod(1)));

        assertThat(dtos).hasSize(2);
        CertificateExtensionDto broken = dtos
                .stream()
                .filter(d -> d.getOid().equals(BASIC_CONSTRAINTS))
                .findFirst()
                .orElseThrow();
        CertificateExtensionDto valid = dtos
                .stream()
                .filter(d -> d.getOid().equals(PRIVATE_KEY_USAGE_PERIOD))
                .findFirst()
                .orElseThrow();
        assertThat(broken.getJer()).isNull();
        assertThat(broken.getDer()).isNotEmpty();
        assertThat(valid.getJer()).isNotNull();
    }

    @Test
    void unreadableRegisteredModuleListsDerOnly() throws IOException {
        List<CertificateExtensionDto> dtos = CertificateExtensionDtoMapper
                .toDtos(extensions(BROKEN_MODULE, false, EMPTY_SEQUENCE));

        assertThat(dtos).hasSize(1);
        assertThat(dtos.get(0).getJer()).isNull();
    }

    @Test
    void criticalAndOrderAreKept() throws IOException {
        List<CertificateExtensionDto> dtos = CertificateExtensionDtoMapper
                .toDtos(extensions(UNDESCRIBED, false, new byte[]{1}, BASIC_CONSTRAINTS, true, EMPTY_SEQUENCE,
                        NAME_CONSTRAINTS, false, nameConstraints()));

        assertThat(dtos)
                .extracting(CertificateExtensionDto::getOid)
                .containsExactly(UNDESCRIBED, BASIC_CONSTRAINTS, NAME_CONSTRAINTS);
        assertThat(dtos).extracting(CertificateExtensionDto::isCritical).containsExactly(false, true, false);
    }

    @Test
    void nullExtensionsGiveEmptyList() {
        assertThat(CertificateExtensionDtoMapper.toDtos(null)).isEmpty();
    }
}
