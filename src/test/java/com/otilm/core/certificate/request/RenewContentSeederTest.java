package com.otilm.core.certificate.request;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.util.CertificateTestUtil;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
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
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RenewContentSeederTest {

    @BeforeAll
    static void addBouncyCastleProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void seedsFromPredecessorCertificate_whenTheRequestCarriesNoCsr() throws Exception {
        // given — the rekey path passes a null request DTO
        Certificate oldCertificate = certificateEntity(CertificateTestUtil
                .createCertificateWithSubjectAndSans("CN=old.example.com",
                        new GeneralName(GeneralName.dNSName, "old.example.com")));
        Certificate newCertificate = new Certificate();

        // when
        Optional<X509RequestContent> seeded = RenewContentSeeder.seed(oldCertificate, newCertificate, null);

        // then
        assertThat(seeded).isPresent();
        assertThat(seeded.get().getSubject().getFirst().getValue()).isEqualTo("old.example.com");
        assertThat(seeded.get().getSubjectAltNames()).singleElement().satisfies(s -> {
            assertThat(s.getType()).isEqualTo(GeneralNameType.DNS);
            assertThat(s.getValue()).isEqualTo("old.example.com");
        });
    }

    @Test
    void seedsFromPredecessorCertificate_whenRenewReusesTheStoredCsr() throws Exception {
        // given — a renew DTO with no CSR of its own; a CA-rewritten DN travels on the certificate, not the CSR
        Certificate oldCertificate = certificateEntity(
                CertificateTestUtil.createCertificateWithSubjectAndSans("CN=rewritten-by-ca.example.com"));
        Certificate newCertificate = new Certificate();
        newCertificate.setCertificateRequest(csrEntity(pkcs10("CN=as-requested.example.com")));

        // when
        Optional<X509RequestContent> seeded = RenewContentSeeder
                .seed(oldCertificate, newCertificate, ClientCertificateRenewRequestDto.builder().build());

        // then
        assertThat(seeded).isPresent();
        assertThat(seeded.get().getSubject().getFirst().getValue()).isEqualTo("rewritten-by-ca.example.com");
    }

    @Test
    void seedsFromSuppliedCsr_whenTheOperatorProvidedOneOnRenew() throws Exception {
        // given — renew validates only the public key, so a supplied CSR may carry a different identity.
        // Structured content must not override what the operator asked for.
        Certificate oldCertificate = certificateEntity(CertificateTestUtil
                .createCertificateWithSubjectAndSans("CN=old.example.com",
                        new GeneralName(GeneralName.dNSName, "old.example.com")));
        String supplied = pkcs10("CN=new.example.com");
        Certificate newCertificate = new Certificate();
        newCertificate.setCertificateRequest(csrEntity(supplied));

        // when
        Optional<X509RequestContent> seeded = RenewContentSeeder
                .seed(oldCertificate, newCertificate,
                        ClientCertificateRenewRequestDto.builder().request(supplied).build());

        // then
        assertThat(seeded).isPresent();
        assertThat(seeded.get().getSubject().getFirst().getValue()).isEqualTo("new.example.com");
    }

    @Test
    void seedsFromPredecessorCertificate_whenTheRequestNamesACsrTheSuccessorDoesNotCarry() throws Exception {
        // given — a request DTO carrying a CSR, but no stored request on the successor to read it back from
        Certificate oldCertificate = certificateEntity(
                CertificateTestUtil.createCertificateWithSubjectAndSans("CN=old.example.com"));
        Certificate newCertificate = new Certificate();

        // when
        Optional<X509RequestContent> seeded = RenewContentSeeder
                .seed(oldCertificate, newCertificate,
                        ClientCertificateRenewRequestDto.builder().request(pkcs10("CN=new.example.com")).build());

        // then — the predecessor is the fallback, never an unread CSR
        assertThat(seeded).isPresent();
        assertThat(seeded.get().getSubject().getFirst().getValue()).isEqualTo("old.example.com");
    }

    @Test
    void seedsNothing_whenAPredecessorSanCannotBeRepresented() throws Exception {
        // given — an x400Address SAN; sending the rest would be an identity narrower than the predecessor's
        Certificate oldCertificate = certificateEntity(CertificateTestUtil
                .createCertificateWithSubjectAndSans("CN=old.example.com",
                        new GeneralName(GeneralName.dNSName, "old.example.com"),
                        new GeneralName(GeneralName.x400Address, new DERSequence())));

        // when
        Optional<X509RequestContent> seeded = RenewContentSeeder.seed(oldCertificate, new Certificate(), null);

        // then — the connector falls back to parsing the CSR the wire already carries
        assertThat(seeded).isEmpty();
    }

    @Test
    void seedsNothing_whenTheStoredCertificateCannotBeParsed() {
        // given
        Certificate oldCertificate = new Certificate();
        CertificateContent content = new CertificateContent();
        content.setContent("bm90LWEtY2VydA==");
        oldCertificate.setCertificateContent(content);

        // when
        Optional<X509RequestContent> seeded = RenewContentSeeder.seed(oldCertificate, new Certificate(), null);

        // then — a broken predecessor must not fail a renew that works today
        assertThat(seeded).isEmpty();
    }

    @Test
    void rekeySanExtensions_carriesThePredecessorSan() throws Exception {
        // given
        X509Certificate oldCertificate = CertificateTestUtil
                .createCertificateWithSubjectAndSans("CN=old.example.com",
                        new GeneralName(GeneralName.dNSName, "old.example.com"),
                        new GeneralName(GeneralName.iPAddress, "10.0.0.1"));

        // when
        Extensions extensions = RenewContentSeeder.rekeySanExtensions(oldCertificate);

        // then
        assertThat(extensions).isNotNull();
        GeneralNames sans = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        assertThat(sans.getNames()).hasSize(2);
        assertThat(extensions.getExtensionOIDs()).containsExactly(Extension.subjectAlternativeName);
    }

    @Test
    void rekeySanExtensions_returnsNull_whenThePredecessorHasNoSan() throws Exception {
        // given
        X509Certificate oldCertificate = CertificateTestUtil.createCertificateWithSubjectAndSans("CN=old.example.com");

        // when
        Extensions extensions = RenewContentSeeder.rekeySanExtensions(oldCertificate);

        // then — a predecessor without SAN produces no extension block
        assertThat(extensions).isNull();
    }

    @Test
    void rekeySanExtensions_failsClosed_whenASanCannotBeRepresented() throws Exception {
        // given — the platform builds this CSR itself, so there is no CSR for the connector to fall back on
        X509Certificate oldCertificate = CertificateTestUtil
                .createCertificateWithSubjectAndSans("CN=old.example.com",
                        new GeneralName(GeneralName.x400Address, new DERSequence()));

        // when / then
        assertThatThrownBy(() -> RenewContentSeeder.rekeySanExtensions(oldCertificate))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("x400Address");
    }

    @Test
    void carriesTheSuppliedCsrExtensions_soAStructuredConnectorSeesWhatWasRequested() throws Exception {
        // given — a CSR whose extension block holds an EKU beside its SAN. The content is authoritative for a
        // structured connector, so operator-requested extensions have to travel in it, not only in the CSR.
        Certificate oldCertificate = certificateEntity(
                CertificateTestUtil.createCertificateWithSubjectAndSans("CN=old.example.com"));
        String supplied = pkcs10WithEku("CN=new.example.com");
        Certificate newCertificate = new Certificate();
        newCertificate.setCertificateRequest(csrEntity(supplied));

        // when
        Optional<X509RequestContent> seeded = RenewContentSeeder
                .seed(oldCertificate, newCertificate,
                        ClientCertificateRenewRequestDto.builder().request(supplied).build());

        // then
        assertThat(seeded).isPresent();
        assertThat(seeded.get().getSubject().getFirst().getValue()).isEqualTo("new.example.com");
        assertThat(seeded.get().getSubjectAltNames()).isNotEmpty();
        assertThat(seeded.get().getExtendedKeyUsage()).containsExactly(KeyPurposeId.id_kp_serverAuth.getId());
    }

    @Test
    void seedsNothing_whenASuppliedCsrRequestsAKeyUsageBitTheModelCannotName() throws Exception {
        // given — bit 9 is outside the nine X.509 names, so the codec drops it from the typed key usage while
        // reporting it; sending the rest would narrow the usage the operator asked for
        Certificate oldCertificate = certificateEntity(
                CertificateTestUtil.createCertificateWithSubjectAndSans("CN=old.example.com"));
        String supplied = pkcs10WithRawKeyUsage("CN=new.example.com",
                new DERBitString(new byte[]{(byte) 0x80, (byte) 0x40}, 6));
        Certificate newCertificate = new Certificate();
        newCertificate.setCertificateRequest(csrEntity(supplied));

        // when
        Optional<X509RequestContent> seeded = RenewContentSeeder
                .seed(oldCertificate, newCertificate,
                        ClientCertificateRenewRequestDto.builder().request(supplied).build());

        // then
        assertThat(seeded).isEmpty();
    }

    @Test
    void seedsNothing_whenThereIsNeitherSubjectNorSanToCarry() throws Exception {
        // given — an empty-subject certificate with no SAN; content carrying neither would fail the wire
        // model's own "at least one of" assertion
        Certificate oldCertificate = certificateEntity(CertificateTestUtil.createCertificateWithSubjectAndSans(""));

        // when
        Optional<X509RequestContent> seeded = RenewContentSeeder.seed(oldCertificate, new Certificate(), null);

        // then
        assertThat(seeded).isEmpty();
    }

    @Test
    void rekeySanExtensions_failsClosed_whenTheSanExtensionIsMalformed() throws Exception {
        // given — a SAN extension whose value is not a GeneralNames sequence at all
        X509Certificate oldCertificate = certificateWithRawSanExtension(new byte[]{0x01, 0x02, 0x03});

        // when / then — a controlled validation failure, not a raw decoding exception
        assertThatThrownBy(() -> RenewContentSeeder.rekeySanExtensions(oldCertificate))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("could not be decoded");
    }

    @Test
    void seedsNothing_whenTheSanExtensionIsMalformed() throws Exception {
        // given
        Certificate oldCertificate = certificateEntity(certificateWithRawSanExtension(new byte[]{0x01, 0x02, 0x03}));

        // when
        Optional<X509RequestContent> seeded = RenewContentSeeder.seed(oldCertificate, new Certificate(), null);

        // then — renew falls back to the CSR rather than failing
        assertThat(seeded).isEmpty();
    }

    @Test
    void seedsNothing_whenThePredecessorSubjectPacksAMultiValuedRdn() throws Exception {
        // given — CN=host+O=Acme is one RDN naming the entry by both attributes; a flat typed subject would be
        // rebuilt as CN=host,O=Acme, a different DER encoding that no DN comparison matches
        Certificate oldCertificate = certificateEntity(CertificateTestUtil
                .createCertificateWithSubjectAndSans(multiValuedSubject(),
                        new GeneralName(GeneralName.dNSName, "old.example.com")));

        // when
        Optional<X509RequestContent> seeded = RenewContentSeeder.seed(oldCertificate, new Certificate(), null);

        // then — the CSR beside the content carries the true subject
        assertThat(seeded).isEmpty();
    }

    @Test
    void seedsNothing_whenASuppliedCsrSubjectPacksAMultiValuedRdn() throws Exception {
        // given
        Certificate oldCertificate = certificateEntity(
                CertificateTestUtil.createCertificateWithSubjectAndSans("CN=old.example.com"));
        String supplied = pkcs10(multiValuedSubject());
        Certificate newCertificate = new Certificate();
        newCertificate.setCertificateRequest(csrEntity(supplied));

        // when
        Optional<X509RequestContent> seeded = RenewContentSeeder
                .seed(oldCertificate, newCertificate,
                        ClientCertificateRenewRequestDto.builder().request(supplied).build());

        // then
        assertThat(seeded).isEmpty();
    }

    @Test
    void seedsRepeatedAttributes_whichAreSeparateRdnsNotAMultiValuedOne() throws Exception {
        // given — OU=First,OU=Second is two RDNs, so the flat typed subject rebuilds it exactly
        Certificate oldCertificate = certificateEntity(
                CertificateTestUtil.createCertificateWithSubjectAndSans("CN=old.example.com,OU=First,OU=Second"));

        // when
        Optional<X509RequestContent> seeded = RenewContentSeeder.seed(oldCertificate, new Certificate(), null);

        // then
        assertThat(seeded).isPresent();
        assertThat(seeded.get().getSubject()).extracting("value").containsExactly("old.example.com", "First", "Second");
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static Certificate certificateEntity(X509Certificate certificate) throws Exception {
        CertificateContent content = new CertificateContent();
        content.setContent(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        Certificate entity = new Certificate();
        entity.setCertificateContent(content);
        return entity;
    }

    private static CertificateRequestEntity csrEntity(String base64Csr) throws NoSuchAlgorithmException {
        CertificateRequestEntity entity = new CertificateRequestEntity();
        entity.setContent(base64Csr);
        entity.setCertificateRequestFormat(CertificateRequestFormat.PKCS10);
        return entity;
    }

    private static X500Name multiValuedSubject() {
        return new X500NameBuilder(BCStyle.INSTANCE)
                .addMultiValuedRDN(new ASN1ObjectIdentifier[]{BCStyle.CN, BCStyle.O}, new String[]{"host", "Acme"})
                .build();
    }

    private static String pkcs10(String subjectDn) throws Exception {
        return pkcs10(new X500Name(subjectDn));
    }

    private static String pkcs10(X500Name subject) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen
                .addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.dNSName, "supplied.example.com")));
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return Base64.getEncoder().encodeToString(builder.build(signer).getEncoded());
    }

    private static String pkcs10WithRawKeyUsage(String subjectDn, DERBitString keyUsage) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectDn),
                kp.getPublic());
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen
                .addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.dNSName, "supplied.example.com")));
        extGen.addExtension(Extension.keyUsage, false, keyUsage);
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return Base64.getEncoder().encodeToString(builder.build(signer).getEncoded());
    }

    private static String pkcs10WithEku(String subjectDn) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectDn),
                kp.getPublic());
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen
                .addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.dNSName, "supplied.example.com")));
        extGen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return Base64.getEncoder().encodeToString(builder.build(signer).getEncoded());
    }

    /** A certificate whose SAN extension value is the given bytes verbatim, so decoding it fails. */
    private static X509Certificate certificateWithRawSanExtension(byte[] extensionValue) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name subject = new X500Name("CN=malformed.example.com");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, BigInteger.ONE, new Date(),
                new Date(System.currentTimeMillis() + 86400000L), subject, kp.getPublic());
        builder.addExtension(Extension.subjectAlternativeName, false, extensionValue);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(kp.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }
}
