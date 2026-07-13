package com.otilm.core.certificate.request;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.connector.v3.certificate.CertificateExtension;
import com.otilm.api.model.connector.v3.certificate.CertificateRegistrationRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.GeneralNameEntry;
import com.otilm.api.model.connector.v3.certificate.RdnEntry;
import com.otilm.api.model.connector.v3.certificate.RequestedExtension;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.groups.Tuple.tuple;

class RegisterWireBuilderTest {

    private static Map<String, OidRecord> savedRdnCache;

    @BeforeAll
    static void snapshotAndSeedRdnCache() {
        // Snapshot the original global cache BEFORE seeding so restoreRdnCache can put it back.
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
        savedRdnCache = existing == null ? null : new HashMap<>(existing);

        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
        OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                OidRecord.builder().displayName("Common Name").code("CN").build());
        OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.10",
                OidRecord.builder().displayName("Organization").code("O").build());
    }

    @AfterAll
    static void restoreRdnCache() {
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE,
                savedRdnCache != null ? savedRdnCache : new HashMap<>());
    }

    // ── Content building (operator flat input → typed content) ─────────────

    @Nested
    class ContentBuilding {

        @Test
        void buildsOrderedRdns_fromSubjectDnString() {
            // when
            X509RequestContent content = RegisterWireBuilder.buildContent("CN=device-7,O=Acme", null, null);

            // then — sequence order preserved
            assertThat(content.getCertificateType()).isEqualTo(CertificateType.X509);
            assertThat(content.getSubject()).extracting(RdnEntry::getType).containsExactly("CN", "O");
            assertThat(content.getSubject()).extracting(RdnEntry::getValue).containsExactly("device-7", "Acme");
        }

        @Test
        void yieldsEmptySubject_whenSubjectDnIsBlank() {
            // when
            X509RequestContent content = RegisterWireBuilder.buildContent("   ", "DNS:a.test", null);

            // then
            assertThat(content.getSubject()).isEmpty();
        }

        @Test
        void throwsValidation_onMalformedSubjectDn() {
            assertThatThrownBy(() -> RegisterWireBuilder.buildContent("@@@ not a dn @@@", null, null))
                    .isInstanceOf(ValidationException.class);
        }

        @Test
        void parsesDnsSan() {
            // when
            X509RequestContent content = RegisterWireBuilder.buildContent(null, "DNS:device-7.acme.test", null);

            // then
            assertThat(content.getSubjectAltNames()).hasSize(1);
            GeneralNameEntry entry = content.getSubjectAltNames().get(0);
            assertThat(entry.getType()).isEqualTo(GeneralNameType.DNS);
            assertThat(entry.getValue()).isEqualTo("device-7.acme.test");
        }

        @Test
        void parsesMultipleSanTypes() {
            // when
            X509RequestContent content = RegisterWireBuilder.buildContent(
                    null, "DNS:a.test,IP:1.2.3.4,email:x@y.test,URI:https://a.test,RID:1.2.3.4.5", null);

            // then
            assertThat(content.getSubjectAltNames())
                    .extracting(GeneralNameEntry::getType)
                    .containsExactly(GeneralNameType.DNS, GeneralNameType.IP, GeneralNameType.EMAIL,
                            GeneralNameType.URI, GeneralNameType.REGISTERED_ID);
        }

        @Test
        void sanPrefixMatchingIsCaseInsensitive() {
            // when
            X509RequestContent content = RegisterWireBuilder.buildContent(null, "dns:a.test,Email:x@y.test", null);

            // then
            assertThat(content.getSubjectAltNames())
                    .extracting(GeneralNameEntry::getType)
                    .containsExactly(GeneralNameType.DNS, GeneralNameType.EMAIL);
        }

        @Test
        void parsesDirNameSanWithEmbeddedCommas() {
            // given — a dirName value contains commas; the comma-separated tail segments have no
            // SAN prefix and must be folded back into the preceding entry's value
            String san = "dirName:CN=intermediate,O=Acme,DNS:a.test";

            // when
            X509RequestContent content = RegisterWireBuilder.buildContent(null, san, null);

            // then
            assertThat(content.getSubjectAltNames()).hasSize(2);
            assertThat(content.getSubjectAltNames().get(0).getType()).isEqualTo(GeneralNameType.DIRECTORY_NAME);
            assertThat(content.getSubjectAltNames().get(0).getValue()).isEqualTo("CN=intermediate,O=Acme");
            assertThat(content.getSubjectAltNames().get(1).getType()).isEqualTo(GeneralNameType.DNS);
        }

        @Test
        void parsesOtherNameSan() {
            // when — OpenSSL otherName convention: otherName:<oid>;UTF8:<value>
            X509RequestContent content = RegisterWireBuilder.buildContent(
                    null, "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:user@acme.test", null);

            // then
            GeneralNameEntry entry = content.getSubjectAltNames().get(0);
            assertThat(entry.getType()).isEqualTo(GeneralNameType.OTHER_NAME);
            assertThat(entry.getOtherNameOid()).isEqualTo("1.3.6.1.4.1.311.20.2.3");
            assertThat(entry.getValue()).isEqualTo("user@acme.test");
            assertThat(entry.getValueEncoding()).isEqualTo(ExtensionValueEncoding.UTF8_STRING);
        }

        @Test
        void throwsValidation_onUnknownSanPrefix() {
            assertThatThrownBy(() -> RegisterWireBuilder.buildContent(null, "carrierPigeon:coop-7", null))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("carrierPigeon");
        }

        @Test
        void throwsValidation_whenFirstSanSegmentHasNoPrefix() {
            assertThatThrownBy(() -> RegisterWireBuilder.buildContent(null, "just-a-hostname", null))
                    .isInstanceOf(ValidationException.class);
        }

        @Test
        void throwsValidation_onOtherNameWithoutOidValueSeparator() {
            assertThatThrownBy(() -> RegisterWireBuilder.buildContent(null, "otherName:no-separator-here", null))
                    .isInstanceOf(ValidationException.class);
        }

        @Test
        void mapsExtensionsToDerRequestedExtensions() {
            // given
            CertificateExtension eku = new CertificateExtension();
            eku.setOid("2.5.29.37");
            eku.setCritical(false);
            eku.setValueBase64("MAoGCCsGAQUFBwMB");

            // when
            X509RequestContent content = RegisterWireBuilder.buildContent("CN=device-7", null, List.of(eku));

            // then
            assertThat(content.getExtensions()).hasSize(1);
            RequestedExtension mapped = content.getExtensions().get(0);
            assertThat(mapped.getOid()).isEqualTo("2.5.29.37");
            assertThat(mapped.getCritical()).isFalse();
            assertThat(mapped.getEncoding()).isEqualTo(ExtensionValueEncoding.DER);
            assertThat(mapped.getValue()).isEqualTo("MAoGCCsGAQUFBwMB");
        }

        @Test
        void yieldsEmptyCollections_whenSanAndExtensionsAbsent() {
            // when
            X509RequestContent content = RegisterWireBuilder.buildContent("CN=device-7", null, null);

            // then
            assertThat(content.getSubjectAltNames()).isEmpty();
            assertThat(content.getExtensions()).isEmpty();
        }
    }

    // ── Registered-identity content (override on register-bound issue) ──────

    @Nested
    class IdentityContent {

        @Test
        void projectsPlaceholderSubjectIntoStructuredContent() {
            // given — the platform-canonical display form stored on the placeholder row
            X509RequestContent content = RegisterWireBuilder.buildIdentityContent("O=Acme, CN=device-7");

            // then
            assertThat(content.getCertificateType()).isEqualTo(CertificateType.X509);
            assertThat(content.getSubject())
                    .extracting(RdnEntry::getType, RdnEntry::getValue)
                    .contains(tuple("CN", "device-7"),
                            tuple("O", "Acme"));
            // then — SAN and extensions are not persisted on the placeholder, so they stay unset
            assertThat(content.getSubjectAltNames()).isNull();
            assertThat(content.getExtensions()).isNull();
        }

        @Test
        void yieldsEmptySubject_whenPlaceholderHasNoSubjectDn() {
            // when — SAN-only registration recorded no subject DN on the placeholder
            X509RequestContent content = RegisterWireBuilder.buildIdentityContent(null);

            // then
            assertThat(content.getSubject()).isEmpty();
        }
    }

    // ── Wire building (content + capability → v3 register DTO fields) ──────

    @Nested
    class WireBuilding {

        private X509RequestContent fullContent() {
            return RegisterWireBuilder.buildContent(
                    "CN=device-7,O=Acme",
                    "DNS:device-7.acme.test",
                    List.of(extension("2.5.29.37", false, "MAoGCCsGAQUFBwMB")));
        }

        private CertificateExtension extension(String oid, boolean critical, String valueBase64) {
            CertificateExtension ext = new CertificateExtension();
            ext.setOid(oid);
            ext.setCritical(critical);
            ext.setValueBase64(valueBase64);
            return ext;
        }

        @Test
        void structuredConnector_carriesRequestContent() {
            // when
            CertificateRegistrationRequestDtoV3 dto = RegisterWireBuilder.buildRegistration(fullContent(), true);

            // then — the structured form is authoritative and carried verbatim
            assertThat(dto.getRequestContent()).isInstanceOf(X509RequestContent.class);
            X509RequestContent carried = (X509RequestContent) dto.getRequestContent();
            assertThat(carried.getSubject()).extracting(RdnEntry::getValue).containsExactly("device-7", "Acme");
        }

        @Test
        void structuredConnector_stillRendersFlatSubjectAnchor() {
            // when
            CertificateRegistrationRequestDtoV3 dto = RegisterWireBuilder.buildRegistration(fullContent(), true);

            // then — flat subjectDn stays the validation anchor (platform canonical display order)
            assertThat(dto.getSubjectDn()).isEqualTo("O=Acme, CN=device-7");
            assertThat(dto.getSubjectAltName()).isEqualTo("DNS:device-7.acme.test");
        }

        @Test
        void structuredConnector_leavesFlatExtensionsUnset() {
            // when
            CertificateRegistrationRequestDtoV3 dto = RegisterWireBuilder.buildRegistration(fullContent(), true);

            // then — extensions ride the structured wire only (no duplicate source)
            assertThat(dto.getExtensions()).isNull();
        }

        @Test
        void legacyConnector_getsNoRequestContent() {
            // when
            CertificateRegistrationRequestDtoV3 dto = RegisterWireBuilder.buildRegistration(fullContent(), false);

            // then
            assertThat(dto.getRequestContent()).isNull();
        }

        @Test
        void legacyConnector_rendersFlatIdentityAndExtensions() {
            // when
            CertificateRegistrationRequestDtoV3 dto = RegisterWireBuilder.buildRegistration(fullContent(), false);

            // then
            assertThat(dto.getSubjectDn()).isEqualTo("O=Acme, CN=device-7");
            assertThat(dto.getSubjectAltName()).isEqualTo("DNS:device-7.acme.test");
            assertThat(dto.getExtensions()).hasSize(1);
            CertificateExtension flat = dto.getExtensions().get(0);
            assertThat(flat.getOid()).isEqualTo("2.5.29.37");
            assertThat(flat.isCritical()).isFalse();
            assertThat(flat.getValueBase64()).isEqualTo("MAoGCCsGAQUFBwMB");
        }

        @Test
        void flatSan_rendersAllRenderableTypes() {
            // given
            X509RequestContent content = RegisterWireBuilder.buildContent(
                    "CN=device-7",
                    "DNS:a.test,IP:1.2.3.4,email:x@y.test,URI:https://a.test,RID:1.2.3.4.5",
                    null);

            // when
            CertificateRegistrationRequestDtoV3 dto = RegisterWireBuilder.buildRegistration(content, false);

            // then
            assertThat(dto.getSubjectAltName())
                    .isEqualTo("DNS:a.test,IP:1.2.3.4,email:x@y.test,URI:https://a.test,RID:1.2.3.4.5");
        }

        @Test
        void flatSan_rendersUtf8OtherName() {
            // given
            X509RequestContent content = RegisterWireBuilder.buildContent(
                    null, "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:user@acme.test", null);

            // when
            CertificateRegistrationRequestDtoV3 dto = RegisterWireBuilder.buildRegistration(content, false);

            // then
            assertThat(dto.getSubjectAltName()).isEqualTo("otherName:1.3.6.1.4.1.311.20.2.3;UTF8:user@acme.test");
        }

        @Test
        void flatWire_rejectsOtherNameWithNonTextualEncoding() {
            // A DER-encoded otherName has no faithful flat-string form; with no structured wire to carry it the
            // flat register wire fails closed rather than silently dropping it.
            GeneralNameEntry derOtherName = new GeneralNameEntry();
            derOtherName.setType(GeneralNameType.OTHER_NAME);
            derOtherName.setOtherNameOid("1.3.6.1.4.1.311.20.2.3");
            derOtherName.setValue("BASE64DER==");
            derOtherName.setValueEncoding(ExtensionValueEncoding.DER);
            GeneralNameEntry dns = new GeneralNameEntry();
            dns.setType(GeneralNameType.DNS);
            dns.setValue("a.test");
            X509RequestContent content = new X509RequestContent();
            content.setCertificateType(CertificateType.X509);
            content.setSubjectAltNames(List.of(derOtherName, dns));

            assertThatThrownBy(() -> RegisterWireBuilder.buildRegistration(content, false))
                    .isInstanceOf(ValidationException.class);
        }

        @Test
        void structuredConnector_retainsNonTextualOtherNameOnStructuredWire() {
            // given — a DER-encoded otherName has no faithful flat-string form, but the structured wire carries it
            // verbatim, so the entry survives when the connector advertises the capability
            GeneralNameEntry derOtherName = new GeneralNameEntry();
            derOtherName.setType(GeneralNameType.OTHER_NAME);
            derOtherName.setOtherNameOid("1.3.6.1.4.1.311.20.2.3");
            derOtherName.setValue("BASE64DER==");
            derOtherName.setValueEncoding(ExtensionValueEncoding.DER);
            X509RequestContent content = new X509RequestContent();
            content.setCertificateType(CertificateType.X509);
            content.setSubjectAltNames(List.of(derOtherName));

            // when
            CertificateRegistrationRequestDtoV3 dto = RegisterWireBuilder.buildRegistration(content, true);

            // then
            X509RequestContent carried = (X509RequestContent) dto.getRequestContent();
            assertThat(carried.getSubjectAltNames()).contains(derOtherName);
        }

        @Test
        void flatWire_rejectsNonDerExtension() {
            // A UTF8-encoded requested extension is not a DER blob and cannot ride the flat wire; fail closed
            // rather than silently drop it when the connector has no structured wire.
            RequestedExtension utf8 = new RequestedExtension();
            utf8.setOid("1.2.3.4.5");
            utf8.setCritical(false);
            utf8.setEncoding(ExtensionValueEncoding.UTF8_STRING);
            utf8.setValue("plain text");
            RequestedExtension der = new RequestedExtension();
            der.setOid("2.5.29.37");
            der.setCritical(true);
            der.setEncoding(ExtensionValueEncoding.DER);
            der.setValue("MAoGCCsGAQUFBwMB");
            X509RequestContent content = new X509RequestContent();
            content.setCertificateType(CertificateType.X509);
            content.setExtensions(List.of(utf8, der));

            assertThatThrownBy(() -> RegisterWireBuilder.buildRegistration(content, false))
                    .isInstanceOf(ValidationException.class);
        }

        @Test
        void flatExtensions_treatNullEncodingAsDer() {
            // given — encoding == null means the value already carries base64 DER (contract default)
            RequestedExtension nullEncoding = new RequestedExtension();
            nullEncoding.setOid("2.5.29.37");
            nullEncoding.setCritical(false);
            nullEncoding.setValue("MAoGCCsGAQUFBwMB");
            X509RequestContent content = new X509RequestContent();
            content.setCertificateType(CertificateType.X509);
            content.setExtensions(List.of(nullEncoding));

            // when
            CertificateRegistrationRequestDtoV3 dto = RegisterWireBuilder.buildRegistration(content, false);

            // then
            assertThat(dto.getExtensions()).hasSize(1);
        }

        @Test
        void flatExtensions_treatNullCriticalAsNonCritical() {
            // given
            RequestedExtension nullCritical = new RequestedExtension();
            nullCritical.setOid("2.5.29.37");
            nullCritical.setEncoding(ExtensionValueEncoding.DER);
            nullCritical.setValue("MAoGCCsGAQUFBwMB");
            X509RequestContent content = new X509RequestContent();
            content.setCertificateType(CertificateType.X509);
            content.setExtensions(List.of(nullCritical));

            // when
            CertificateRegistrationRequestDtoV3 dto = RegisterWireBuilder.buildRegistration(content, false);

            // then
            assertThat(dto.getExtensions().get(0).isCritical()).isFalse();
        }

        @Test
        void sanOnlyContent_yieldsNullSubjectDnWithRenderedSanAnchor() {
            // given — RFC 5280 §4.1.2.6: subject carried entirely in the SAN
            X509RequestContent content = RegisterWireBuilder.buildContent(null, "DNS:device-1.example.com", null);

            // when
            CertificateRegistrationRequestDtoV3 dto = RegisterWireBuilder.buildRegistration(content, true);

            // then — the flat SAN remains the subject-identification validation anchor
            assertThat(dto.getSubjectDn()).isNull();
            assertThat(dto.getSubjectAltName()).isEqualTo("DNS:device-1.example.com");
            assertThat(dto.isSubjectIdentificationProvided()).isTrue();
        }

        @Test
        void emptyContent_yieldsNullFlatFields() {
            // given
            X509RequestContent content = RegisterWireBuilder.buildContent(null, null, null);

            // when
            CertificateRegistrationRequestDtoV3 dto = RegisterWireBuilder.buildRegistration(content, false);

            // then
            assertThat(dto.getSubjectDn()).isNull();
            assertThat(dto.getSubjectAltName()).isNull();
            assertThat(dto.getExtensions()).isNull();
        }
    }
}
