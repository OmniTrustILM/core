package com.otilm.core.certificate.request;

import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class X509RequestContentParserTest {

    private static Map<String, OidRecord> savedRdnCache;

    @BeforeAll
    static void snapshotRdnCache() {
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
        savedRdnCache = existing == null ? null : new HashMap<>(existing);
    }

    @AfterAll
    static void restoreRdnCache() {
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE,
                savedRdnCache != null ? savedRdnCache : new HashMap<>());
    }

    static {
        // Seed the OidHandler with standard RDN attribute types for PlatformX500NameStyle
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
        OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                OidRecord.builder().displayName("Common Name").code("CN").build());
        OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.10",
                OidRecord.builder().displayName("Organization").code("O").build());
    }

    @Nested
    class Subject {

        @Test
        void parsesOrderedRdns_fromPkcs10Subject() throws Exception {
            // given
            var request = pkcs10("CN=host.example.com,O=Example", false);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request);

            // then — DEFAULT style preserves CN, O order with short codes
            assertThat(content.getSubject()).extracting("type").containsExactly("CN", "O");
            assertThat(content.getSubject().get(0).getValue()).isEqualTo("host.example.com");
        }

        @Test
        void yieldsEmptySubject_whenDnIsEmpty() throws Exception {
            // given
            var request = pkcs10("", false);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request);

            // then
            assertThat(content.getSubject()).isEmpty();
        }
    }

    @Nested
    class SubjectAltNames {

        @Test
        void parsesTypedSans_fromExtensionRequest() throws Exception {
            // given
            var request = pkcs10("CN=host.example.com", true);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request);

            // then
            assertThat(content.getSubjectAltNames())
                    .anySatisfy(s -> {
                        assertThat(s.getType()).isEqualTo(GeneralNameType.DNS);
                        assertThat(s.getValue()).isEqualTo("host.example.com");
                    })
                    .anySatisfy(s -> {
                        assertThat(s.getType()).isEqualTo(GeneralNameType.EMAIL);
                        assertThat(s.getValue()).isEqualTo("admin@example.com");
                    });
        }

        @Test
        void parsesRegisteredIdSan_asRegisteredIdType() throws Exception {
            // given
            var request = pkcs10WithSan(new GeneralName(GeneralName.registeredID, "1.2.3.4.5"));

            // when
            X509RequestContent content = X509RequestContentParser.parse(request);

            // then
            assertThat(content.getSubjectAltNames())
                    .anySatisfy(s -> {
                        assertThat(s.getType()).isEqualTo(GeneralNameType.REGISTERED_ID);
                        assertThat(s.getValue()).isEqualTo("1.2.3.4.5");
                    });
        }

        @Test
        void skipsOtherNameSan_whenEncodingCannotBeRecovered() throws Exception {
            // given
            var otherName = new org.bouncycastle.asn1.x509.OtherName(
                    new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                    new org.bouncycastle.asn1.DERUTF8String("user@example.com"));
            var request = pkcs10WithSan(new GeneralName(GeneralName.otherName, otherName.toASN1Primitive()));

            // when
            X509RequestContent content = X509RequestContentParser.parse(request);

            // then
            assertThat(content.getSubjectAltNames())
                    .noneSatisfy(s -> assertThat(s.getType()).isEqualTo(GeneralNameType.OTHER_NAME));
        }
    }

    @Nested
    class Extensions {

        @Test
        void parsesNonSanExtensions_andExcludesSan() throws Exception {
            // given
            var request = pkcs10("CN=host.example.com", true);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request);

            // then
            assertThat(content.getExtensions()).extracting("oid")
                    .contains(Extension.extendedKeyUsage.getId())
                    .doesNotContain(Extension.subjectAlternativeName.getId());
        }

        @Test
        void yieldsEmptyExtensions_whenNoExtensionRequestPresent() throws Exception {
            // given
            var request = pkcs10("CN=host.example.com", false);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request);

            // then
            assertThat(content.getExtensions()).isEmpty();
        }

        @Test
        void skipsExtension_whenValueIsEmptyOctets() throws Exception {
            // given — a zero-length-octet extension value would base64 to "" and violate RequestedExtension's
            //         @NotBlank REQUIRED contract, so the parser must not emit it
            var request = pkcs10WithRawExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"), new byte[0]);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request);

            // then
            assertThat(content.getExtensions()).extracting("oid").doesNotContain("1.3.6.1.4.1.99999.1");
            assertThat(content.getExtensions()).noneMatch(e -> e.getValue() == null || e.getValue().isBlank());
        }
    }

    @Nested
    class BlankValues {

        @Test
        void skipsRdn_whenValueIsBlank() throws Exception {
            // given — an empty CN RDN alongside a populated O; the empty CN violates RdnEntry's @NotBlank
            X500Name subject = new X500NameBuilder()
                    .addRDN(BCStyle.CN, "")
                    .addRDN(BCStyle.O, "Example")
                    .build();
            var request = pkcs10(subject);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request);

            // then — no blank-valued RDN is emitted, and the populated O survives
            assertThat(content.getSubject()).noneMatch(e -> e.getValue() == null || e.getValue().isBlank());
            assertThat(content.getSubject())
                    .anySatisfy(e -> assertThat(e.getValue()).isEqualTo("Example"));
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static CertificateRequest pkcs10(X500Name subject) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new Pkcs10CertificateRequest(builder.build(signer).getEncoded());
    }

    private static CertificateRequest pkcs10WithRawExtension(ASN1ObjectIdentifier oid, byte[] value) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=host.example.com"), kp.getPublic());
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(oid, false, value);
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new Pkcs10CertificateRequest(builder.build(signer).getEncoded());
    }

    private static CertificateRequest pkcs10(String dn, boolean withSanAndEku) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        PKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(new X500Name(dn), kp.getPublic());
        if (withSanAndEku) {
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            extGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{
                    new GeneralName(GeneralName.dNSName, "host.example.com"),
                    new GeneralName(GeneralName.rfc822Name, "admin@example.com")
            }));
            extGen.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new Pkcs10CertificateRequest(builder.build(signer).getEncoded());
    }

    private static CertificateRequest pkcs10WithSan(GeneralName sanEntry) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        PKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=host.example.com"), kp.getPublic());
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{sanEntry}));
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new Pkcs10CertificateRequest(builder.build(signer).getEncoded());
    }
}
