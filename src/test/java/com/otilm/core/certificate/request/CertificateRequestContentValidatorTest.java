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
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
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
        void requiresEveryMappedTarget_ofOneToManyMapping() {
            // A required attribute mapped 1-to-many (FQDN -> CN + dNSName) demands every target:
            // validating an uploaded CSR is the reverse of the renderer, which projects the value into all mapped targets.
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("fqdn").required()
                            .mappingRdn("CN").mappingSan(GeneralNameType.DNS).build());
            var content = content(List.of(rdn("CN", "host.example.com")), List.of());

            // when — CN present, sibling dNSName target absent
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, false));

            // then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrors()).anyMatch(e -> e.contains("Missing required") && e.contains("dNSName"));
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

        @Test
        void rejectsOtherNameSanOutsideSet_whenWhitelistEnabled() {
            // given — set maps CN only; CSR carries an unmapped otherName SAN (the whitelist-bypass case)
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());
            var content = content(
                    List.of(rdn("CN", "host.example.com")),
                    List.of(san(GeneralNameType.OTHER_NAME, "1.3.6.1.4.1.311.20.2.3=user@example.com")));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, true));

            // then — the otherName is no longer invisible to the whitelist
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrors()).anyMatch(e -> e.contains("otherName"));
        }
    }

    @Nested
    class OtherNameOidMatching {

        private static final String UPN_OID = "1.3.6.1.4.1.311.20.2.3";

        @Test
        void acceptsOtherName_whoseTypeIdOidIsMapped() {
            // given
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("upn").required().mappingOtherName(UPN_OID).build());
            var content = content(List.of(), List.of(otherName(UPN_OID, "user@example.com")));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, true));

            // then
            assertThat(result.isValid()).isTrue();
        }

        @Test
        void rejectsOtherName_whoseTypeIdOidIsNotMapped() {
            // given — the set maps UPN only; the CSR carries an otherName of a different type-id
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("upn").mappingOtherName(UPN_OID).build());
            var content = content(List.of(), List.of(otherName("1.2.3.4", "arbitrary")));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, true));

            // then — an otherName mapping whitelists its own OID, not the whole otherName kind
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrors()).anyMatch(e -> e.contains("otherName") && e.contains("1.2.3.4"));
        }

        @Test
        void requiredOtherName_isNotSatisfiedByDifferentTypeIdOid() {
            // given
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("upn").required().mappingOtherName(UPN_OID).build());
            var content = content(List.of(), List.of(otherName("1.2.3.4", "arbitrary")));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, false));

            // then
            assertThat(result.getErrors()).anyMatch(e -> e.toLowerCase().contains("required"));
        }
    }

    @Nested
    class UnrepresentableSans {

        @Test
        void whitelistFailsClosed_onSansTheParserCannotRepresent() {
            // given — the parser reported an x400Address SAN it could not decode into typed content
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());
            var parsed = new ParsedRequestContent(
                    content(List.of(rdn("CN", "host.example.com")), List.of()), List.of("x400Address"));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, parsed, new RequestAttributePolicy(true, true));

            // then — the CSR is forwarded verbatim, so an unvalidatable SAN must fail closed
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrors()).anyMatch(e -> e.contains("x400Address"));
        }

        @Test
        void ignoresUnrepresentableSans_whenWhitelistDisabled() {
            // given
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());
            var parsed = new ParsedRequestContent(
                    content(List.of(rdn("CN", "host.example.com")), List.of()), List.of("x400Address"));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, parsed, new RequestAttributePolicy(true, false));

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

        @Test
        void doesNotApplyStringConstraintsToDerEncodedExtensionValue() {
            // given — a mapped extension whose regex the Base64(DER) blob could never satisfy; running the
            //         constraint against the opaque DER bytes would wrongly reject a valid uploaded CSR
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("eku").required().withRegex("^[0-9]+$")
                            .mappingExtension("2.5.29.37").build());
            var content = content(List.of(), List.of(), List.of(ext("2.5.29.37", "MAoGCCsGAQUFBwMB")));

            // when
            var result = CertificateRequestContentValidator.validate(definitions, content, new RequestAttributePolicy(true, true));

            // then — presence is enforced, but the DER value is not regex-checked, so it stays valid
            assertThat(result.isValid()).isTrue();
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

        @Test
        void shapesUncheckedParseFailure_asValidationException_withoutLeakingInternals() throws Exception {
            // given — a PKCS#10 whose extensionRequest attribute has an EMPTY value set: structurally
            // valid ASN.1 that fails extension extraction with an unchecked exception, not a typed one
            CertificateRequest request = pkcs10WithEmptyExtensionRequest();
            List<BaseAttribute> definitions = List.of(
                    aMappedDataAttribute().withName("cn").required().mappingRdn("CN").build());

            // when / then — protocol adapters expose this message on the wire and the global advice
            // forwards cause messages to clients, so the exception must be platform-authored and causeless
            assertThatThrownBy(() -> new CertificateRequestContentValidator().validate(request, definitions, false))
                    .isInstanceOf(CertificateRequestValidationException.class)
                    .hasMessage("Certificate request could not be processed for validation")
                    .hasNoCause();
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

    /** Hand-assembled PKCS#10 with an empty extensionRequest value set; the placeholder signature is never checked here. */
    private static CertificateRequest pkcs10WithEmptyExtensionRequest() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        Attribute emptyExtensionRequest = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet());
        CertificationRequestInfo info = new CertificationRequestInfo(
                new X500Name("CN=host.example.com"),
                SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()),
                new DERSet(emptyExtensionRequest));
        CertificationRequest csr = new CertificationRequest(info,
                new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE),
                new DERBitString(new byte[]{0}));
        return new Pkcs10CertificateRequest(csr.getEncoded());
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

    private static GeneralNameEntry otherName(String otherNameOid, String value) {
        GeneralNameEntry e = san(GeneralNameType.OTHER_NAME, value);
        e.setOtherNameOid(otherNameOid);
        e.setValueEncoding(ExtensionValueEncoding.UTF8_STRING);
        return e;
    }
}
