package com.otilm.core.certificate.request;

import com.otilm.api.exception.CertificateRequestValidationException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.connector.v3.certificate.GeneralNameEntry;
import com.otilm.api.model.connector.v3.certificate.RdnEntry;
import com.otilm.api.model.connector.v3.certificate.RequestedExtension;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.otilm.core.util.builders.MappedDataAttributeV3Builder.aMappedDataAttribute;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateRequestContentValidatorTest {

    private static Map<String, OidRecord> savedRdnCache;

    @BeforeAll
    static void seedRdnOidCache() {
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
        savedRdnCache = existing == null ? null : new HashMap<>(existing);
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
        OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                OidRecord.builder().displayName("Common Name").code("CN").build());
        OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.10",
                OidRecord.builder().displayName("Organization").code("O").build());
    }

    @AfterAll
    static void restoreRdnOidCache() {
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE,
                savedRdnCache != null ? savedRdnCache : new HashMap<>());
    }

    @Nested
    class RequiredFields {

        @Test
        void passes_whenAllRequiredMappedFieldsPresentAndConstraintsSatisfied() {
            // given
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().withRegex("^.{1,64}$").mappingRdn("CN").build(),
                    aMappedDataAttribute().withName("dns").mappingSan(GeneralNameType.DNS).build());
            var content = content(
                    List.of(rdn("CN", "host.example.com")),
                    List.of(san(GeneralNameType.DNS, "host.example.com")));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, true));

            // then
            assertThat(result.isValid()).isTrue();
        }

        @Test
        void reportsError_whenRequiredMappedFieldMissing() {
            // given
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());
            var content = content(List.of(), List.of());

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, false));

            // then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrors()).anyMatch(e -> e.toLowerCase().contains("required"));
        }

        @Test
        void ignoresDefinitionsWithoutFieldMapping() {
            // given — a plain required attribute with no fieldMapping must not affect validation
            DataAttributeV3 plain = new DataAttributeV3();
            plain.setName("note");
            plain.setContentType(AttributeContentType.STRING);
            DataAttributeProperties properties = new DataAttributeProperties();
            properties.setLabel("note");
            properties.setRequired(true);
            plain.setProperties(properties);
            List<BaseAttribute> definitions = List.of(plain,
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());
            var content = content(List.of(rdn("CN", "host.example.com")), List.of());

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, true));

            // then
            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    class Constraints {

        @Test
        void reportsError_whenValueViolatesRegex() {
            // given
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("country").required().withRegex("^[A-Z]{2}$").mappingRdn("C").build());
            var content = content(List.of(rdn("C", "Czechia")), List.of());

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, false));

            // then
            assertThat(result.isValid()).isFalse();
        }
    }

    @Nested
    class Whitelist {

        @Test
        void rejectsSanOutsideSet_whenWhitelistEnabled() {
            // given — set maps CN only; CSR carries an unmapped dNSName SAN
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());
            var content = content(
                    List.of(rdn("CN", "host.example.com")),
                    List.of(san(GeneralNameType.DNS, "evil.example.com")));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, true));

            // then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrors()).anyMatch(e -> e.contains("dNSName"));
        }

        @Test
        void allowsSanOutsideSet_whenWhitelistDisabled() {
            // given
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());
            var content = content(
                    List.of(rdn("CN", "host.example.com")),
                    List.of(san(GeneralNameType.DNS, "extra.example.com")));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, false));

            // then
            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    class PolicyStrictness {

        @Test
        void downgradesViolationsToWarnings_whenPolicyIsLenient() {
            // given — missing required mapped field AND a whitelist violation
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());
            var content = content(
                    List.of(),
                    List.of(san(GeneralNameType.DNS, "extra.example.com")));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(false, true));

            // then
            assertThat(result.isValid()).isTrue();
            assertThat(result.hasErrors()).isFalse();
            assertThat(result.getErrors()).isEmpty();
            assertThat(result.getWarnings())
                    .anyMatch(w -> w.toLowerCase().contains("required"))
                    .anyMatch(w -> w.contains("dNSName"));
        }

        @Test
        void reportsErrors_whenPolicyIsStrict() {
            // given — same content as the lenient case above
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());
            var content = content(
                    List.of(),
                    List.of(san(GeneralNameType.DNS, "extra.example.com")));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, true));

            // then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrors())
                    .anyMatch(e -> e.toLowerCase().contains("required"))
                    .anyMatch(e -> e.contains("dNSName"));
            assertThat(result.getWarnings()).isEmpty();
        }
    }

    @Nested
    class OidFormRdnMapping {

        @Test
        void matchesOidFormMapping_againstShortCodeSubject() {
            // given — the mapping targets the RDN by dotted OID (2.5.4.3), while the parser emits "CN"
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("2.5.4.3").build());
            var content = content(List.of(rdn("CN", "host.example.com")), List.of());

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, true));

            // then — OID<->code normalization makes the OID-form mapping match the short-code RDN
            assertThat(result.isValid()).isTrue();
        }

        @Test
        void doesNotFlagWhitelist_whenOidFormMappingCoversPresentRdn() {
            // given — CSR carries CN only; the set maps it by OID, so whitelist must not reject it
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("2.5.4.3").build());
            var content = content(List.of(rdn("CN", "host.example.com")), List.of());

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, true));

            // then
            assertThat(result.getErrors()).noneMatch(e -> e.contains("not allowed"));
        }
    }

    @Nested
    class MappedExtensions {

        @Test
        void passes_whenRequiredMappedExtensionPresent() {
            // given — the set requires the extendedKeyUsage extension and the CSR carries it
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("eku").required().mappingExtension("2.5.29.37").build());
            var content = content(List.of(), List.of(), List.of(ext("2.5.29.37", "MAoGCCsGAQUFBwMB")));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, true));

            // then
            assertThat(result.isValid()).isTrue();
        }

        @Test
        void reportsError_whenRequiredMappedExtensionMissing() {
            // given — required extension mapping, but the CSR carries no extensions
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("eku").required().mappingExtension("2.5.29.37").build());
            var content = content(List.of(), List.of(), List.of());

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, false));

            // then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrors()).anyMatch(e -> e.toLowerCase().contains("required"));
        }

        @Test
        void rejectsExtensionOutsideSet_whenWhitelistEnabled() {
            // given — the set maps CN only; the CSR carries an unmapped extension
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());
            var content = content(
                    List.of(rdn("CN", "host.example.com")), List.of(),
                    List.of(ext("2.5.29.37", "MAoGCCsGAQUFBwMB")));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, true));

            // then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrors()).anyMatch(e -> e.contains("2.5.29.37") && e.contains("not allowed"));
        }

        @Test
        void allowsExtensionOutsideSet_whenWhitelistDisabled() {
            // given
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());
            var content = content(
                    List.of(rdn("CN", "host.example.com")), List.of(),
                    List.of(ext("2.5.29.37", "MAoGCCsGAQUFBwMB")));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, false));

            // then
            assertThat(result.isValid()).isTrue();
        }

        @Test
        void doesNotFlagWhitelist_whenExtensionMappingCoversPresentExtension() {
            // given — the CSR carries an extension that the set explicitly maps
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("eku").mappingExtension("2.5.29.37").build());
            var content = content(List.of(), List.of(), List.of(ext("2.5.29.37", "MAoGCCsGAQUFBwMB")));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, true));

            // then
            assertThat(result.getErrors()).noneMatch(e -> e.contains("not allowed"));
        }
    }

    @Nested
    class WhitelistErrorVocabulary {

        @Test
        void namesEachSanTypeUsingItsAsn1FieldName_whenWhitelistRejects() {
            // given — the set maps CN only; the CSR carries one SAN of every whitelist-reportable type
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());
            var content = content(
                    List.of(rdn("CN", "host.example.com")),
                    List.of(san(GeneralNameType.EMAIL, "user@example.com"),
                            san(GeneralNameType.DNS, "host.example.com"),
                            san(GeneralNameType.DIRECTORY_NAME, "CN=dir"),
                            san(GeneralNameType.URI, "https://example.com"),
                            san(GeneralNameType.IP, "10.0.0.1"),
                            san(GeneralNameType.REGISTERED_ID, "1.2.3.4")));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, true));

            // then — each SAN is reported using the same ASN.1 vocabulary as the parser
            assertThat(result.getErrors())
                    .anyMatch(e -> e.contains("rfc822Name"))
                    .anyMatch(e -> e.contains("dNSName"))
                    .anyMatch(e -> e.contains("directoryName"))
                    .anyMatch(e -> e.contains("uniformResourceIdentifier"))
                    .anyMatch(e -> e.contains("iPAddress"))
                    .anyMatch(e -> e.contains("registeredID"));
        }

        @Test
        void rejectsSubjectRdnOutsideSet_whenWhitelistEnabled() {
            // given — the set maps CN only; the CSR subject also carries an unmapped O
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());
            var content = content(
                    List.of(rdn("CN", "host.example.com"), rdn("O", "Acme")), List.of());

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, true));

            // then
            assertThat(result.getErrors()).anyMatch(e -> e.contains("O") && e.contains("not allowed"));
        }
    }

    @Nested
    class InstanceOverload {

        @Test
        void throws_whenStrictAndRequiredRdnMissing() throws Exception {
            // given — CSR subject has O only; the set requires CN; strict (lenient=false)
            CertificateRequest request = pkcs10("O=Example");
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());

            // when / then
            assertThatThrownBy(() -> new CertificateRequestContentValidator().validate(request, definitions, false))
                    .isInstanceOf(CertificateRequestValidationException.class)
                    .hasMessageContaining("request-attribute policy");
        }

        @Test
        void accepts_whenLenientAndRequiredRdnMissing() throws Exception {
            // given — same CSR and set, but lenient (lenient=true) downgrades the violation to a warning
            CertificateRequest request = pkcs10("O=Example");
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());

            // when / then
            assertThatCode(() -> new CertificateRequestContentValidator().validate(request, definitions, true))
                    .doesNotThrowAnyException();
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static CertificateRequest pkcs10(String subjectDn) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        JcaPKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectDn), kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new Pkcs10CertificateRequest(builder.build(signer).getEncoded());
    }

    private static X509RequestContent content(List<RdnEntry> subject, List<GeneralNameEntry> sans) {
        return content(subject, sans, List.of());
    }

    private static X509RequestContent content(List<RdnEntry> subject, List<GeneralNameEntry> sans, List<RequestedExtension> extensions) {
        X509RequestContent c = new X509RequestContent();
        c.setSubject(subject);
        c.setSubjectAltNames(sans);
        c.setExtensions(extensions);
        return c;
    }

    private static RequestedExtension ext(String oid, String value) {
        RequestedExtension e = new RequestedExtension();
        e.setOid(oid);
        e.setValue(value);
        return e;
    }

    private static RdnEntry rdn(String type, String value) {
        RdnEntry e = new RdnEntry();
        e.setType(type);
        e.setValue(value);
        return e;
    }

    private static GeneralNameEntry san(GeneralNameType type, String value) {
        GeneralNameEntry e = new GeneralNameEntry();
        e.setType(type);
        e.setValue(value);
        return e;
    }
}
