package com.otilm.core.attribute;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.mapping.ExtensionMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.FieldType;
import com.otilm.api.model.common.attribute.v3.mapping.MappedField;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.SanMappedField;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateRequestAttributeProjectorTest {

    // The OidHandler cache is process-wide static state shared across the whole test JVM.
    // Snapshot CERTIFICATE_EXTENSION before this class replaces it; restore it afterwards.
    private static Map<String, OidRecord> savedExtensionCache;

    @BeforeAll
    static void snapshotExtensionCache() {
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.CERTIFICATE_EXTENSION);
        savedExtensionCache = existing == null ? null : new HashMap<>(existing);
    }

    @AfterAll
    static void restoreExtensionCache() {
        OidHandler.cacheOidCategory(OidCategory.CERTIFICATE_EXTENSION,
                savedExtensionCache != null ? savedExtensionCache : new HashMap<>());
    }

    @BeforeEach
    void seedExtensionRegistry() {
        OidHandler.cacheOidCategory(OidCategory.CERTIFICATE_EXTENSION, new HashMap<>());
        OidHandler.cacheOid(OidCategory.CERTIFICATE_EXTENSION, REGISTERED_EXT_OID,
                OidRecord.builder()
                        .displayName("Registered Extension")
                        .defaultCritical(true)
                        .valueEncoding(ExtensionValueEncoding.IA5_STRING)
                        .build());
    }

    @Test
    void projectsExtensionCriticalityAndEncoding_fromOidRegistry_whenOidIsRegistered() {
        // given — a mapped extension whose OID is registered as critical with an IA5_STRING encoding
        var uuid = UUID.randomUUID();
        var def = dataAttribute(uuid, extensionMapping(REGISTERED_EXT_OID));
        var values = List.of(stringValue(uuid, "registered-value"));

        // when
        X509RequestContent content = CertificateRequestAttributeProjector.project(List.of(def), values);

        // then — criticality and encoding are taken from the registry, not hard-coded
        assertThat(content.getExtensions()).singleElement()
                .satisfies(ext -> {
                    assertThat(ext.getOid()).isEqualTo(REGISTERED_EXT_OID);
                    assertThat(ext.getCritical()).isTrue();
                    assertThat(ext.getEncoding()).isEqualTo(ExtensionValueEncoding.IA5_STRING);
                    assertThat(ext.getValue()).isEqualTo("registered-value");
                });
    }

    @Test
    void projectsExtensionAsNonCriticalWithoutEncoding_whenOidIsUnregistered() {
        // given — a mapped extension whose OID is not in the registry
        var unregisteredOid = "1.3.6.1.4.1.99999.7";
        var uuid = UUID.randomUUID();
        var def = dataAttribute(uuid, extensionMapping(unregisteredOid));
        var values = List.of(stringValue(uuid, "unregistered-value"));

        // when
        X509RequestContent content = CertificateRequestAttributeProjector.project(List.of(def), values);

        // then — falls back to non-critical with no declared encoding
        assertThat(content.getExtensions()).singleElement()
                .satisfies(ext -> {
                    assertThat(ext.getCritical()).isFalse();
                    assertThat(ext.getEncoding()).isNull();
                });
    }

    @Test
    void projectsRdnSubject_fromRdnMappedField() {
        // given — a CN RDN mapping carrying a value
        var uuid = UUID.randomUUID();
        var def = dataAttribute(uuid, rdnMapping("CN"));
        var values = List.of(stringValue(uuid, "host.example.com"));

        // when
        X509RequestContent content = CertificateRequestAttributeProjector.project(List.of(def), values);

        // then
        assertThat(content.getSubject()).singleElement()
                .satisfies(rdn -> {
                    assertThat(rdn.getType()).isEqualTo("CN");
                    assertThat(rdn.getValue()).isEqualTo("host.example.com");
                });
    }

    @Test
    void projectsSubjectAltName_fromSanMappedField() {
        // given — a DNS SAN mapping carrying a value
        var uuid = UUID.randomUUID();
        var def = dataAttribute(uuid, sanMapping(GeneralNameType.DNS));
        var values = List.of(stringValue(uuid, "alt.example.com"));

        // when
        X509RequestContent content = CertificateRequestAttributeProjector.project(List.of(def), values);

        // then
        assertThat(content.getSubjectAltNames()).singleElement()
                .satisfies(san -> {
                    assertThat(san.getType()).isEqualTo(GeneralNameType.DNS);
                    assertThat(san.getValue()).isEqualTo("alt.example.com");
                });
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static final String REGISTERED_EXT_OID = "1.3.6.1.4.1.99999.1";

    private static DataAttributeV3 dataAttribute(UUID uuid, FieldMapping fieldMapping) {
        DataAttributeV3 attr = new DataAttributeV3();
        attr.setUuid(uuid.toString());
        attr.setName("attr-" + uuid);
        attr.setContentType(AttributeContentType.STRING);
        attr.setFieldMapping(fieldMapping);
        return attr;
    }

    private static FieldMapping extensionMapping(String extensionOid) {
        ExtensionMappedField field = new ExtensionMappedField();
        field.setFieldType(FieldType.EXTENSION);
        field.setExtensionOid(extensionOid);
        return mappingOf(field);
    }

    private static FieldMapping rdnMapping(String rdn) {
        RdnMappedField field = new RdnMappedField();
        field.setFieldType(FieldType.RDN);
        field.setRdn(rdn);
        return mappingOf(field);
    }

    private static FieldMapping sanMapping(GeneralNameType type) {
        SanMappedField field = new SanMappedField();
        field.setFieldType(FieldType.SAN);
        field.setGeneralNameType(type);
        return mappingOf(field);
    }

    private static FieldMapping mappingOf(MappedField field) {
        FieldMapping fm = new FieldMapping();
        fm.setFields(List.of(field));
        return fm;
    }

    private static RequestAttribute stringValue(UUID uuid, String value) {
        List<BaseAttributeContentV3<?>> content = List.of(new StringAttributeContentV3(value));
        return new RequestAttributeV3(uuid, "attr-" + uuid, AttributeContentType.STRING, content);
    }
}
