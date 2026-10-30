package com.otilm.core.certificate.request;

import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.CertificateKeyUsage;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.model.request.CrmfCertificateRequest;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.service.cmp.CmpTestUtil;
import com.otilm.core.util.CertificateTestUtil;
import com.otilm.core.util.X509RequestContentRenderer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class X509RequestContentParserTest {

    private static Map<String, OidRecord> savedRdnCache;

    @BeforeAll
    static void snapshotAndSeedRdnCache() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Snapshot the original global cache BEFORE seeding.
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
        savedRdnCache = existing == null ? null : new HashMap<>(existing);

        // Seed the OidHandler with standard RDN attribute types for PlatformX500NameStyle
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                        OidRecord.builder().displayName("Common Name").code("CN").build());
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.10",
                        OidRecord.builder().displayName("Organization").code("O").build());
    }

    @AfterAll
    static void restoreRdnCache() {
        OidHandler
                .cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE,
                        savedRdnCache != null ? savedRdnCache : new HashMap<>());
    }

    @Nested
    class Subject {

        @Test
        void parsesOrderedRdns_fromPkcs10Subject() throws Exception {
            // given
            var request = pkcs10("CN=host.example.com,O=Example", false);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then — DEFAULT style preserves CN, O order with short codes
            assertThat(content.getSubject()).extracting("type").containsExactly("CN", "O");
            assertThat(content.getSubject().get(0).getValue()).isEqualTo("host.example.com");
        }

        @Test
        void yieldsEmptySubject_whenDnIsEmpty() throws Exception {
            // given
            var request = pkcs10("", false);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then
            assertThat(content.getSubject()).isEmpty();
        }

        @Test
        void splitsMultiValuedRdn_intoSeparateEntries() throws Exception {
            // given — a single multi-valued RDN packing CN and O together (RFC 4514 "CN=...+O=...")
            X500Name subject = new X500NameBuilder()
                    .addMultiValuedRDN(new ASN1ObjectIdentifier[]{BCStyle.CN, BCStyle.O},
                            new String[]{"host.example.com", "Acme"})
                    .build();
            var request = pkcs10(subject);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then — each component is its own entry, so neither can escape whitelist/required checks
            assertThat(content.getSubject()).extracting("type").contains("CN", "O");
            assertThat(content.getSubject())
                    .anySatisfy(e -> assertThat(e.getValue()).isEqualTo("host.example.com"))
                    .anySatisfy(e -> assertThat(e.getValue()).isEqualTo("Acme"));
        }

        @Test
        void preservesRfc4514SpecialCharacters_inRdnValues() throws Exception {
            // given — values with unescaped ',', '+', '=' that a rendered-DN round-trip would mis-split
            X500Name subject = new X500NameBuilder()
                    .addRDN(BCStyle.O, "Acme, Inc. + Co")
                    .addRDN(BCStyle.CN, "key=value")
                    .build();
            var request = pkcs10(subject);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then — decoded from the ASN.1 objects directly, so the values survive verbatim
            assertThat(content.getSubject())
                    .hasSize(2)
                    .anySatisfy(e -> assertThat(e.getValue()).isEqualTo("Acme, Inc. + Co"))
                    .anySatisfy(e -> assertThat(e.getValue()).isEqualTo("key=value"));
        }

        @Test
        void setsX509CertificateType_onParsedContent() throws Exception {
            // given
            var request = pkcs10("CN=host.example.com", false);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then — the REQUIRED discriminator is populated
            assertThat(content.getCertificateType()).isEqualTo(CertificateType.X509);
        }
    }

    @Nested
    class SubjectAltNames {

        @Test
        void parsesTypedSans_fromExtensionRequest() throws Exception {
            // given
            var request = pkcs10("CN=host.example.com", true);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then
            assertThat(content.getSubjectAltNames()).anySatisfy(s -> {
                assertThat(s.getType()).isEqualTo(GeneralNameType.DNS);
                assertThat(s.getValue()).isEqualTo("host.example.com");
            }).anySatisfy(s -> {
                assertThat(s.getType()).isEqualTo(GeneralNameType.EMAIL);
                assertThat(s.getValue()).isEqualTo("admin@example.com");
            });
        }

        @Test
        void parsesRegisteredIdSan_asRegisteredIdType() throws Exception {
            // given
            var request = pkcs10WithSan(new GeneralName(GeneralName.registeredID, "1.2.3.4.5"));

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then
            assertThat(content.getSubjectAltNames()).anySatisfy(s -> {
                assertThat(s.getType()).isEqualTo(GeneralNameType.REGISTERED_ID);
                assertThat(s.getValue()).isEqualTo("1.2.3.4.5");
            });
        }

        @Test
        void decodesIpv4San_toDottedForm() throws Exception {
            // given — iPAddress SANs are DER octet strings; policy rules expect the textual form
            var request = pkcs10WithSan(new GeneralName(GeneralName.iPAddress, "10.0.0.1"));

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then
            assertThat(content.getSubjectAltNames()).anySatisfy(s -> {
                assertThat(s.getType()).isEqualTo(GeneralNameType.IP);
                assertThat(s.getValue()).isEqualTo("10.0.0.1");
            });
        }

        @Test
        void decodesIpv6San_toColonForm() throws Exception {
            // given
            var request = pkcs10WithSan(new GeneralName(GeneralName.iPAddress, "2001:db8::1"));

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then — canonical Java textual form of the 16-octet address
            assertThat(content.getSubjectAltNames()).anySatisfy(s -> {
                assertThat(s.getType()).isEqualTo(GeneralNameType.IP);
                assertThat(s.getValue()).isEqualTo("2001:db8:0:0:0:0:0:1");
            });
        }

        @Test
        void parsesDirectoryNameSan_asDnString() throws Exception {
            // given
            var request = pkcs10WithSan(new GeneralName(GeneralName.directoryName, new X500Name("CN=dir.example.com")));

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then
            assertThat(content.getSubjectAltNames()).anySatisfy(s -> {
                assertThat(s.getType()).isEqualTo(GeneralNameType.DIRECTORY_NAME);
                assertThat(s.getValue()).contains("dir.example.com");
            });
        }

        @Test
        void reportsUndecodableIpAddressSan_insteadOfSilentlyDropping() throws Exception {
            // given — a 3-octet iPAddress is neither IPv4 nor IPv6
            var request = pkcs10WithSan(
                    new GeneralName(GeneralName.iPAddress, new DEROctetString(new byte[]{1, 2, 3})));

            // when
            ParsedRequestContent parsed = X509RequestContentParser.parse(request);

            // then — surfaced for fail-closed whitelist enforcement
            assertThat(parsed.content().getSubjectAltNames()).isEmpty();
            assertThat(parsed.unsupportedSans()).containsExactly("iPAddress");
        }

        @Test
        void reportsUnrepresentableSanKind_insteadOfSilentlyDropping() throws Exception {
            // given — an x400Address SAN, which GeneralNameType cannot model
            var request = pkcs10WithSan(new GeneralName(GeneralName.x400Address, new DERSequence()));

            // when
            ParsedRequestContent parsed = X509RequestContentParser.parse(request);

            // then — surfaced for fail-closed whitelist enforcement, not dropped
            assertThat(parsed.content().getSubjectAltNames()).isEmpty();
            assertThat(parsed.unsupportedSans()).containsExactly("x400Address");
        }

        @Test
        void parsesOtherNameSan_asOtherNameType_soWhitelistCanSeeIt() throws Exception {
            // given — a UPN otherName SAN
            var otherName = new OtherName(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                    new DERUTF8String("user@example.com"));
            var request = pkcs10WithSan(new GeneralName(GeneralName.otherName, otherName.toASN1Primitive()));

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then — represented as OTHER_NAME carrying its OID, so a strict whitelist can reject it
            assertThat(content.getSubjectAltNames()).anySatisfy(s -> {
                assertThat(s.getType()).isEqualTo(GeneralNameType.OTHER_NAME);
                assertThat(s.getOtherNameOid()).isEqualTo("1.3.6.1.4.1.311.20.2.3");
                assertThat(s.getValue()).isEqualTo("user@example.com");
            });
        }
    }

    @Nested
    class FromCertificate {

        @Test
        void parsesOrderedRdnsAndTypeDiscriminator_fromCertificateSubject() throws Exception {
            // given
            X509Certificate certificate = CertificateTestUtil
                    .createCertificateWithSubjectAndSans("CN=host.example.com,O=Example");

            // when
            X509RequestContent content = X509RequestContentParser.parse(certificate).content();

            // then
            assertThat(content.getSubject()).extracting("type").containsExactly("CN", "O");
            assertThat(content.getSubject().getFirst().getValue()).isEqualTo("host.example.com");
            assertThat(content.getCertificateType()).isEqualTo(CertificateType.X509);
        }

        @Test
        void keepsRepeatedAttributesInOrder_asSeparateEntries() throws Exception {
            // given — repeated OUs are separate RDNs, the case the projector emits and the wire carries in order;
            // a multi-valued RDN is a different thing, covered below
            X509Certificate certificate = CertificateTestUtil
                    .createCertificateWithSubjectAndSans("CN=host.example.com,OU=First,OU=Second");

            // when
            X509RequestContent content = X509RequestContentParser.parse(certificate).content();

            // then
            assertThat(content.getSubject()).extracting("value").containsExactly("host.example.com", "First", "Second");
        }

        @Test
        void parsesEveryTypedSanKind_fromCertificateExtension() throws Exception {
            // given
            X509Certificate certificate = CertificateTestUtil
                    .createCertificateWithSubjectAndSans("CN=host.example.com",
                            new GeneralName(GeneralName.dNSName, "host.example.com"),
                            new GeneralName(GeneralName.rfc822Name, "admin@example.com"),
                            new GeneralName(GeneralName.iPAddress, "10.0.0.1"),
                            new GeneralName(GeneralName.uniformResourceIdentifier, "https://example.com/a"),
                            new GeneralName(GeneralName.registeredID, "1.2.3.4.5"),
                            new GeneralName(GeneralName.directoryName, new X500Name("CN=dir.example.com")));

            // when
            X509RequestContent content = X509RequestContentParser.parse(certificate).content();

            // then
            assertThat(content.getSubjectAltNames())
                    .extracting("type")
                    .containsExactly(GeneralNameType.DNS, GeneralNameType.EMAIL, GeneralNameType.IP,
                            GeneralNameType.URI, GeneralNameType.REGISTERED_ID, GeneralNameType.DIRECTORY_NAME);
            assertThat(content.getSubjectAltNames().get(2).getValue()).isEqualTo("10.0.0.1");
        }

        @Test
        void recoversOtherNameOidAndEncoding_fromCertificateSan() throws Exception {
            // given — a UPN otherName, the form the OTHER_NAME wire entry needs both OID and encoding for
            var otherName = new OtherName(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                    new DERUTF8String("user@example.com"));
            X509Certificate certificate = CertificateTestUtil
                    .createCertificateWithSubjectAndSans("CN=host.example.com",
                            new GeneralName(GeneralName.otherName, otherName.toASN1Primitive()));

            // when
            X509RequestContent content = X509RequestContentParser.parse(certificate).content();

            // then
            assertThat(content.getSubjectAltNames()).singleElement().satisfies(s -> {
                assertThat(s.getType()).isEqualTo(GeneralNameType.OTHER_NAME);
                assertThat(s.getOtherNameOid()).isEqualTo("1.3.6.1.4.1.311.20.2.3");
                assertThat(s.getValue()).isEqualTo("user@example.com");
                assertThat(s.getValueEncoding()).isEqualTo(ExtensionValueEncoding.UTF8_STRING);
            });
        }

        @Test
        void yieldsEmptySans_whenCertificateHasNoSanExtension() throws Exception {
            // given
            X509Certificate certificate = CertificateTestUtil
                    .createCertificateWithSubjectAndSans("CN=host.example.com");

            // when
            ParsedRequestContent parsed = X509RequestContentParser.parse(certificate);

            // then
            assertThat(parsed.content().getSubjectAltNames()).isEmpty();
            assertThat(parsed.unsupportedSans()).isEmpty();
        }

        @Test
        void reportsUnrepresentableSanKind_insteadOfSilentlyDropping() throws Exception {
            // given — an x400Address SAN, which GeneralNameType cannot model
            X509Certificate certificate = CertificateTestUtil
                    .createCertificateWithSubjectAndSans("CN=host.example.com",
                            new GeneralName(GeneralName.dNSName, "host.example.com"),
                            new GeneralName(GeneralName.x400Address, new DERSequence()));

            // when
            ParsedRequestContent parsed = X509RequestContentParser.parse(certificate);

            // then — the representable entry is decoded, the other is surfaced for the caller's policy
            assertThat(parsed.content().getSubjectAltNames()).hasSize(1);
            assertThat(parsed.unsupportedSans()).containsExactly("x400Address");
        }

        @Test
        void seedsNoExtensions_notEvenKeyUsageOrExtendedKeyUsage() throws Exception {
            // given — the certificate carries an EKU, which is the CA's to set and must not be re-requested
            X509Certificate certificate = CertificateTestUtil.createCertificateWithEku(false);

            // when
            X509RequestContent content = X509RequestContentParser.parse(certificate).content();

            // then — left null so @JsonInclude(NON_NULL) keeps them off the wire entirely
            assertThat(content.getExtensions()).isNull();
            assertThat(content.getKeyUsage()).isNull();
            assertThat(content.getExtendedKeyUsage()).isNull();
        }

        @Test
        void keepsOtherNameStringType_forIa5AndPrintableValues() throws Exception {
            // given — a value recorded under the wrong encoding is re-encoded as that type when rendered back
            X509Certificate certificate = CertificateTestUtil
                    .createCertificateWithSubjectAndSans("CN=host.example.com", new GeneralName(GeneralName.otherName,
                            new OtherName(new ASN1ObjectIdentifier("1.2.3.4.1"), new DERIA5String("ia5@example.com"))
                                    .toASN1Primitive()),
                            new GeneralName(GeneralName.otherName, new OtherName(new ASN1ObjectIdentifier("1.2.3.4.2"),
                                    new DERPrintableString("PRINTABLE")).toASN1Primitive()));

            // when
            X509RequestContent content = X509RequestContentParser.parse(certificate).content();

            // then
            assertThat(content.getSubjectAltNames().get(0).getValueEncoding())
                    .isEqualTo(ExtensionValueEncoding.IA5_STRING);
            assertThat(content.getSubjectAltNames().get(0).getValue()).isEqualTo("ia5@example.com");
            assertThat(content.getSubjectAltNames().get(1).getValueEncoding())
                    .isEqualTo(ExtensionValueEncoding.PRINTABLE_STRING);
            assertThat(content.getSubjectAltNames().get(1).getValue()).isEqualTo("PRINTABLE");
        }

        @Test
        void fallsBackToDer_forAStringTypeTheEncodingsCannotName() throws Exception {
            // given — BMPString has no ExtensionValueEncoding counterpart, so only Base64(DER) preserves its type
            X509Certificate certificate = CertificateTestUtil
                    .createCertificateWithSubjectAndSans("CN=host.example.com",
                            new GeneralName(GeneralName.otherName,
                                    new OtherName(new ASN1ObjectIdentifier("1.2.3.4.3"), new DERBMPString("bmp"))
                                            .toASN1Primitive()));

            // when
            X509RequestContent content = X509RequestContentParser.parse(certificate).content();

            // then
            assertThat(content.getSubjectAltNames()).singleElement().satisfies(san -> {
                assertThat(san.getValueEncoding()).isEqualTo(ExtensionValueEncoding.DER);
                assertThat(san.getValue()).isNotEqualTo("bmp");
            });
        }

        @Test
        void otherNameSurvivesRenderAndReparse_forEveryStringType() throws Exception {
            // given — the rekey CSR is rendered from this content, so a coerced type would change the identity
            X509Certificate certificate = CertificateTestUtil
                    .createCertificateWithSubjectAndSans("CN=host.example.com",
                            new GeneralName(GeneralName.otherName,
                                    new OtherName(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                                            new DERUTF8String("user@example.com")).toASN1Primitive()),
                            new GeneralName(GeneralName.otherName,
                                    new OtherName(new ASN1ObjectIdentifier("1.2.3.4.1"),
                                            new DERIA5String("ia5@example.com")).toASN1Primitive()),
                            new GeneralName(GeneralName.otherName,
                                    new OtherName(new ASN1ObjectIdentifier("1.2.3.4.2"),
                                            new DERPrintableString("PRINTABLE")).toASN1Primitive()),
                            new GeneralName(GeneralName.otherName,
                                    new OtherName(new ASN1ObjectIdentifier("1.2.3.4.3"), new DERBMPString("bmp"))
                                            .toASN1Primitive()));
            X509RequestContent seeded = X509RequestContentParser.parse(certificate).content();

            // when
            Extensions rendered = X509RequestContentRenderer.toExtensions(seeded);
            GeneralNames renderedSans = GeneralNames.fromExtensions(rendered, Extension.subjectAlternativeName);

            // then — each otherName keeps the ASN.1 type it had in the certificate
            assertThat(OtherName.getInstance(renderedSans.getNames()[0].getName()).getValue())
                    .isInstanceOf(DERUTF8String.class);
            assertThat(OtherName.getInstance(renderedSans.getNames()[1].getName()).getValue())
                    .isInstanceOf(DERIA5String.class);
            assertThat(OtherName.getInstance(renderedSans.getNames()[2].getName()).getValue())
                    .isInstanceOf(DERPrintableString.class);
            assertThat(OtherName.getInstance(renderedSans.getNames()[3].getName()).getValue())
                    .isInstanceOf(DERBMPString.class);
        }

        @Test
        void flattensAMultiValuedRdn_fromACertificateSubject() throws Exception {
            // given — CN=host+O=Acme, one RDN carrying both attributes
            X509Certificate certificate = CertificateTestUtil
                    .createCertificateWithSubjectAndSans(new X500NameBuilder(BCStyle.INSTANCE)
                            .addMultiValuedRDN(new ASN1ObjectIdentifier[]{BCStyle.CN, BCStyle.O},
                                    new String[]{"host", "Acme"})
                            .build());

            // when
            X509RequestContent content = X509RequestContentParser.parse(certificate).content();

            // then — each component becomes its own entry, so the grouping is not expressible in typed content;
            // RenewContentSeeder refuses to seed such a subject rather than sending an altered DN
            assertThat(content.getSubject()).extracting("type").containsExactly("CN", "O");
            assertThat(content.getSubject()).extracting("value").containsExactly("host", "Acme");
        }

        @Test
        void seededSanSurvivesRenderAndReparse() throws Exception {
            // given — the seeder is the renderer's inverse; a drift between them loses SAN on rekey
            X509Certificate certificate = CertificateTestUtil
                    .createCertificateWithSubjectAndSans("CN=host.example.com",
                            new GeneralName(GeneralName.dNSName, "host.example.com"),
                            new GeneralName(GeneralName.iPAddress, "10.0.0.1"),
                            new GeneralName(GeneralName.rfc822Name, "admin@example.com"));
            X509RequestContent seeded = X509RequestContentParser.parse(certificate).content();

            // when
            Extensions rendered = X509RequestContentRenderer.toExtensions(seeded);
            X509RequestContent reparsed = X509RequestContentParser.parse(pkcs10WithExtensions(rendered)).content();

            // then
            assertThat(reparsed.getSubjectAltNames())
                    .usingRecursiveFieldByFieldElementComparator()
                    .containsExactlyElementsOf(seeded.getSubjectAltNames());
        }
    }

    @Nested
    class ExtensionParsing {

        @Test
        void parsesOpaqueExtensions_andExcludesDivertedOnes() throws Exception {
            // given — a CSR carrying SAN, extended key usage and an extension with no structured target
            var request = pkcs10WithRawExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"),
                    new DERSequence().getEncoded(ASN1Encoding.DER));

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then — only the opaque one stays in the extension list
            assertThat(content.getExtensions()).extracting("oid").contains("1.3.6.1.4.1.99999.1");
        }

        @Test
        void divertsExtendedKeyUsage_outOfTheExtensionList() throws Exception {
            // given
            var request = pkcs10("CN=host.example.com", true);

            // when
            ParsedRequestContent parsed = X509RequestContentParser.parse(request);

            // then — typed, and gone from the opaque list, exactly as SAN is
            assertThat(parsed.content().getExtendedKeyUsage()).containsExactly("1.3.6.1.5.5.7.3.1");
            assertThat(parsed.content().getExtensions())
                    .extracting("oid")
                    .doesNotContain(Extension.extendedKeyUsage.getId(), Extension.subjectAlternativeName.getId());
            assertThat(parsed.unrepresentableExtensionValues()).isEmpty();
        }

        @Test
        void divertsKeyUsage_outOfTheExtensionList() throws Exception {
            // given
            var request = pkcs10WithRawExtension(Extension.keyUsage,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment).getEncoded(ASN1Encoding.DER));

            // when
            ParsedRequestContent parsed = X509RequestContentParser.parse(request);

            // then
            assertThat(parsed.content().getKeyUsage())
                    .containsExactly(CertificateKeyUsage.DIGITAL_SIGNATURE, CertificateKeyUsage.KEY_ENCIPHERMENT);
            assertThat(parsed.content().getExtensions()).extracting("oid").doesNotContain(Extension.keyUsage.getId());
        }

        @Test
        void reportsAnUnmodelledKeyUsageBit_ratherThanDroppingIt() throws Exception {
            // given — bit 9. X.509 closes the vocabulary at nine bits, so this genuinely cannot be
            // represented; dropping it would let a strict policy pass a CSR the platform cannot even name.
            var request = pkcs10WithRawExtension(Extension.keyUsage, new byte[]{0x03, 0x03, 0x04, 0x00, 0x40});

            // when
            ParsedRequestContent parsed = X509RequestContentParser.parse(request);

            // then
            assertThat(parsed.content().getKeyUsage()).isEmpty();
            assertThat(parsed.unrepresentableExtensionValues()).containsExactly("Key Usage bit 9");
        }

        @Test
        void reportsAnUndecodableStructuredExtension() throws Exception {
            // given — 2.5.29.15 carrying a SEQUENCE where a BIT STRING belongs
            var request = pkcs10WithRawExtension(Extension.keyUsage, new byte[]{0x30, 0x00});

            // when
            ParsedRequestContent parsed = X509RequestContentParser.parse(request);

            // then — reported like an unsupported SAN, so a strict policy fails closed
            assertThat(parsed.unrepresentableExtensionValues())
                    .anySatisfy(item -> assertThat(item).contains("Key Usage"));
        }

        @Test
        void projectRenderParseReturnsTheSameTypedValues() throws Exception {
            // given — content as the projector would produce it
            X509RequestContent projected = new X509RequestContent();
            projected.setKeyUsage(List.of(CertificateKeyUsage.DIGITAL_SIGNATURE, CertificateKeyUsage.CRL_SIGN));
            projected.setExtendedKeyUsage(List.of("1.3.6.1.5.5.7.3.1"));

            // when — render into a real CSR and read it back
            ParsedRequestContent parsed = X509RequestContentParser
                    .parse(pkcs10WithExtensions(X509RequestContentRenderer.toExtensions(projected)));

            // then — this round trip is what replaces a byte-level wire regression
            assertThat(parsed.content().getKeyUsage()).containsExactlyElementsOf(projected.getKeyUsage());
            assertThat(parsed.content().getExtendedKeyUsage())
                    .containsExactlyElementsOf(projected.getExtendedKeyUsage());
            assertThat(parsed.unrepresentableExtensionValues()).isEmpty();
        }

        @Test
        void yieldsEmptyExtensions_whenNoExtensionRequestPresent() throws Exception {
            // given
            var request = pkcs10("CN=host.example.com", false);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then
            assertThat(content.getExtensions()).isEmpty();
        }

        @Test
        void skipsExtension_whenValueIsEmptyOctets() throws Exception {
            // given — a zero-length-octet extension value would base64 to "" and violate RequestedExtension's
            // @NotBlank REQUIRED contract, so the parser must not emit it
            var request = pkcs10WithRawExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"), new byte[0]);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

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
            X500Name subject = new X500NameBuilder().addRDN(BCStyle.CN, "").addRDN(BCStyle.O, "Example").build();
            var request = pkcs10(subject);

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then — no blank-valued RDN is emitted, and the populated O survives
            assertThat(content.getSubject()).noneMatch(e -> e.getValue() == null || e.getValue().isBlank());
            assertThat(content.getSubject()).anySatisfy(e -> assertThat(e.getValue()).isEqualTo("Example"));
        }
    }

    @Nested
    class Crmf {

        @Test
        void parsesSubject_andYieldsNoSansOrExtensions_whenCertTemplateHasNoExtensions() throws Exception {
            // given — a CRMF request whose CertTemplate carries a subject but no extensions
            var request = crmf("CN=host.example.com");

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then
            assertThat(content.getSubject()).extracting("type").contains("CN");
            assertThat(content.getSubjectAltNames()).isEmpty();
            assertThat(content.getExtensions()).isEmpty();
        }

        @Test
        void divertsSansAndStructuredExtensions_fromCertTemplate() throws Exception {
            // given — a CRMF request whose CertTemplate carries a SAN and an EKU extension
            var builder = CmpTestUtil.createCrmf(new X500Name("CN=issuer"), new X500Name("CN=host.example.com"));
            builder
                    .addExtension(Extension.subjectAlternativeName, false, new GeneralNames(
                            new GeneralName[]{new GeneralName(GeneralName.dNSName, "host.example.com")}));
            builder
                    .addExtension(Extension.extendedKeyUsage, false,
                            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
            CertReqMessages certReqMessages = new CertReqMessages(builder.build().toASN1Structure());
            var request = new CrmfCertificateRequest(certReqMessages.getEncoded());

            // when
            X509RequestContent content = X509RequestContentParser.parse(request).content();

            // then — SAN and EKU both typed, and neither duplicated into the opaque extension list
            assertThat(content.getSubjectAltNames()).anySatisfy(s -> {
                assertThat(s.getType()).isEqualTo(GeneralNameType.DNS);
                assertThat(s.getValue()).isEqualTo("host.example.com");
            });
            assertThat(content.getExtendedKeyUsage()).containsExactly("1.3.6.1.5.5.7.3.1");
            assertThat(content.getExtensions())
                    .extracting("oid")
                    .doesNotContain(Extension.extendedKeyUsage.getId(), Extension.subjectAlternativeName.getId());
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static CertificateRequest crmf(String subjectDn) throws Exception {
        var message = CmpTestUtil.createCrmf(new X500Name("CN=issuer"), new X500Name(subjectDn)).build();
        CertReqMessages certReqMessages = new CertReqMessages(message.toASN1Structure());
        return new CrmfCertificateRequest(certReqMessages.getEncoded());
    }

    private static CertificateRequest pkcs10(X500Name subject) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new Pkcs10CertificateRequest(builder.build(signer).getEncoded());
    }

    private static CertificateRequest pkcs10WithRawExtension(ASN1ObjectIdentifier oid, byte[] value) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=host.example.com"), kp.getPublic());
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(oid, false, value);
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new Pkcs10CertificateRequest(builder.build(signer).getEncoded());
    }

    private static CertificateRequest pkcs10WithExtensions(Extensions extensions) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=host.example.com"), kp.getPublic());
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new Pkcs10CertificateRequest(builder.build(signer).getEncoded());
    }

    private static CertificateRequest pkcs10(String dn, boolean withSanAndEku) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(dn),
                kp.getPublic());
        if (withSanAndEku) {
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            extGen
                    .addExtension(Extension.subjectAlternativeName, false,
                            new GeneralNames(new GeneralName[]{
                                    new GeneralName(GeneralName.dNSName, "host.example.com"),
                                    new GeneralName(GeneralName.rfc822Name, "admin@example.com")}));
            extGen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new Pkcs10CertificateRequest(builder.build(signer).getEncoded());
    }

    private static CertificateRequest pkcs10WithSan(GeneralName sanEntry) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=host.example.com"), kp.getPublic());
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{sanEntry}));
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new Pkcs10CertificateRequest(builder.build(signer).getEncoded());
    }
}
