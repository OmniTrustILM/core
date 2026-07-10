package com.otilm.core.attribute;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.IntegerAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.mapping.ExtensionMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.FieldType;
import com.otilm.api.model.common.attribute.v3.mapping.MappedField;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.SanMappedField;
import com.otilm.api.model.connector.v3.certificate.GeneralNameEntry;
import com.otilm.api.model.connector.v3.certificate.RdnEntry;
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

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

    @Test
    void projectsEveryValueOfMultiValuedAttribute_asRepeatedRdns() {
        // given — one two-valued attribute mapped to OU (many→1: one attribute, repeated RDNs)
        var uuid = UUID.randomUUID();
        var def = dataAttribute(uuid, rdnMapping("OU"));
        var values = List.of(multiStringValue(uuid, "unit-one", "unit-two"));

        // when
        X509RequestContent content = CertificateRequestAttributeProjector.project(List.of(def), values);

        // then — one OU entry per value, in content order
        assertThat(content.getSubject())
                .extracting(RdnEntry::getType, RdnEntry::getValue)
                .containsExactly(tuple("OU", "unit-one"), tuple("OU", "unit-two"));
    }

    @Test
    void projectsEveryValueOfMultiValuedAttribute_asMultipleSans() {
        // given — one three-valued attribute mapped to a DNS SAN (many→1: one SAN entry per value)
        var uuid = UUID.randomUUID();
        var def = dataAttribute(uuid, sanMapping(GeneralNameType.DNS));
        var values = List.of(multiStringValue(uuid, "a.example.com", "b.example.com", "c.example.com"));

        // when
        X509RequestContent content = CertificateRequestAttributeProjector.project(List.of(def), values);

        // then — one SAN entry per value, in content order
        assertThat(content.getSubjectAltNames())
                .extracting(GeneralNameEntry::getType, GeneralNameEntry::getValue)
                .containsExactly(
                        tuple(GeneralNameType.DNS, "a.example.com"),
                        tuple(GeneralNameType.DNS, "b.example.com"),
                        tuple(GeneralNameType.DNS, "c.example.com"));
    }

    @Test
    void skipsNonStringContentItems_withoutDroppingTheAttribute() {
        // given — mixed content: an integer item ahead of a string item
        var uuid = UUID.randomUUID();
        var def = dataAttribute(uuid, rdnMapping("CN"));
        List<BaseAttributeContentV3<?>> mixed =
                List.of(new IntegerAttributeContentV3(42), new StringAttributeContentV3("kept"));
        var values = List.<RequestAttribute>of(
                new RequestAttributeV3(uuid, "attr-" + uuid, AttributeContentType.STRING, mixed));

        // when
        X509RequestContent content = CertificateRequestAttributeProjector.project(List.of(def), values);

        // then — the string item projects; only the non-string item is skipped
        assertThat(content.getSubject())
                .extracting(RdnEntry::getValue)
                .containsExactly("kept");
    }

    @Test
    void omitsAttribute_whenContentHasNoStringValues() {
        // given — content holding no string items at all
        var uuid = UUID.randomUUID();
        var def = dataAttribute(uuid, rdnMapping("CN"));
        List<BaseAttributeContentV3<?>> integers = List.of(new IntegerAttributeContentV3(7));
        var values = List.<RequestAttribute>of(
                new RequestAttributeV3(uuid, "attr-" + uuid, AttributeContentType.INTEGER, integers));

        // when
        X509RequestContent content = CertificateRequestAttributeProjector.project(List.of(def), values);

        // then — nothing to project
        assertThat(content.getSubject()).isNull();
    }

    @Test
    void projectsOneValueToEveryMappedField_cnAndDnsSan() {
        // given — 1→many: one FQDN mapped to both CN and dNSName
        var uuid = UUID.randomUUID();
        var def = dataAttribute(uuid, mappingOf(rdnField("CN", 1), sanField(GeneralNameType.DNS, 2)));
        var values = List.of(stringValue(uuid, "host.example.com"));

        // when
        X509RequestContent content = CertificateRequestAttributeProjector.project(List.of(def), values);

        // then — the single value lands in both target fields
        assertThat(content.getSubject())
                .extracting(RdnEntry::getType, RdnEntry::getValue)
                .containsExactly(tuple("CN", "host.example.com"));
        assertThat(content.getSubjectAltNames())
                .extracting(GeneralNameEntry::getType, GeneralNameEntry::getValue)
                .containsExactly(tuple(GeneralNameType.DNS, "host.example.com"));
    }

    @Test
    void ordersProjectedEntries_byFieldOrderThenContentOrder() {
        // given — two RDN fields declared in reverse of their explicit order, on a two-valued attribute
        var uuid = UUID.randomUUID();
        var def = dataAttribute(uuid, mappingOf(rdnField("OU", 2), rdnField("CN", 1)));
        var values = List.of(multiStringValue(uuid, "first", "second"));

        // when
        X509RequestContent content = CertificateRequestAttributeProjector.project(List.of(def), values);

        // then — CN (order 1) precedes OU (order 2); values keep content order within each field
        assertThat(content.getSubject())
                .extracting(RdnEntry::getType, RdnEntry::getValue)
                .containsExactly(
                        tuple("CN", "first"), tuple("CN", "second"),
                        tuple("OU", "first"), tuple("OU", "second"));
    }

    @Test
    void projectsField_whenOrderIsNull() {
        // given — a mapped RDN field with no explicit order (null coalesces to the default 0)
        var uuid = UUID.randomUUID();
        var def = dataAttribute(uuid, mappingOf(rdnField("CN", null)));
        var values = List.of(stringValue(uuid, "host.example.com"));

        // when
        X509RequestContent content = CertificateRequestAttributeProjector.project(List.of(def), values);

        // then — a null order does not drop the field; it still projects
        assertThat(content.getSubject())
                .extracting(RdnEntry::getType, RdnEntry::getValue)
                .containsExactly(tuple("CN", "host.example.com"));
    }

    @Test
    void rejectsMultiValuedAttributeMappedToExtension() {
        // given — two values feeding one extension OID: cannot render to valid RFC 5280 Extensions
        var uuid = UUID.randomUUID();
        var def = dataAttribute(uuid, extensionMapping(REGISTERED_EXT_OID));
        var defs = List.of(def);
        var values = List.of(multiStringValue(uuid, "value-one", "value-two"));

        // when / then
        assertThatThrownBy(() -> CertificateRequestAttributeProjector.project(defs, values))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(REGISTERED_EXT_OID)
                .hasMessageContaining(def.getName());
    }

    @Test
    void rejectsDuplicateExtensionOidAcrossDefinitions() {
        // given — two definitions mapping the same extension OID, each supplying a single value
        var uuidA = UUID.randomUUID();
        var uuidB = UUID.randomUUID();
        var defA = dataAttribute(uuidA, extensionMapping(REGISTERED_EXT_OID));
        var defB = dataAttribute(uuidB, extensionMapping(REGISTERED_EXT_OID));
        var defs = List.of(defA, defB);
        var values = List.of(stringValue(uuidA, "value-a"), stringValue(uuidB, "value-b"));

        // when / then — an extension OID may appear only once (RFC 5280)
        assertThatThrownBy(() -> CertificateRequestAttributeProjector.project(defs, values))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(REGISTERED_EXT_OID);
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
        return mappingOf(rdnField(rdn, 1));
    }

    private static FieldMapping sanMapping(GeneralNameType type) {
        return mappingOf(sanField(type, 1));
    }

    private static RdnMappedField rdnField(String rdn, Integer order) {
        RdnMappedField field = new RdnMappedField();
        field.setFieldType(FieldType.RDN);
        field.setRdn(rdn);
        field.setOrder(order);
        return field;
    }

    private static SanMappedField sanField(GeneralNameType type, Integer order) {
        SanMappedField field = new SanMappedField();
        field.setFieldType(FieldType.SAN);
        field.setGeneralNameType(type);
        field.setOrder(order);
        return field;
    }

    private static FieldMapping mappingOf(MappedField... fields) {
        FieldMapping fm = new FieldMapping();
        fm.setFields(List.of(fields));
        return fm;
    }

    private static RequestAttribute stringValue(UUID uuid, String value) {
        return multiStringValue(uuid, value);
    }

    private static RequestAttribute multiStringValue(UUID uuid, String... values) {
        List<BaseAttributeContentV3<?>> content = new ArrayList<>();
        for (String value : values) {
            content.add(new StringAttributeContentV3(value));
        }
        return new RequestAttributeV3(uuid, "attr-" + uuid, AttributeContentType.STRING, content);
    }
}
