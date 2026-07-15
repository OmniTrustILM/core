package com.otilm.core.certificate.request;

import com.otilm.api.model.connector.v3.certificate.GeneralNameEntry;
import com.otilm.api.model.connector.v3.certificate.RdnEntry;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.GeneralNameType;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

class RequestContentSeederTest {

    @Test
    void seedsOrderedSubjectRdns_includingRepeatedOus() throws Exception {
        // given
        X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, "renew-me")
                .addRDN(BCStyle.OU, "first")
                .addRDN(BCStyle.OU, "second")
                .addRDN(BCStyle.O, "ACME")
                .build();
        X509Certificate certificate = certificate(subject, null);

        // when
        X509RequestContent content = RequestContentSeeder.seedFromCertificate(certificate);

        // then
        assertThat(content.getSubject())
                .as("every RDN of the existing certificate must be seeded, repeated OUs included, in encoding order")
                .extracting(RdnEntry::getType, RdnEntry::getValue)
                .containsExactly(
                        tuple("CN", "renew-me"),
                        tuple("OU", "first"),
                        tuple("OU", "second"),
                        tuple("O", "ACME"));
    }

    @Test
    void rejectsNullCertificate_withNamedNpe() {
        // when / then
        assertThatThrownBy(() -> RequestContentSeeder.seedFromCertificate(null))
                .as("a null certificate must fail fast with a named contract, not a raw NPE from BouncyCastle internals")
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("certificate");
    }

    @Test
    void seedsDnsIpAndEmailSans() throws Exception {
        // given
        GeneralNames sans = new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "app.example.com"),
                new GeneralName(GeneralName.iPAddress, "10.1.2.3"),
                new GeneralName(GeneralName.rfc822Name, "ops@example.com")});
        X509Certificate certificate = certificate(subject("with-sans"), sans);

        // when
        X509RequestContent content = RequestContentSeeder.seedFromCertificate(certificate);

        // then
        assertThat(content.getSubjectAltNames())
                .as("DNS, IP and email SANs of the existing certificate must be seeded with their types")
                .extracting(GeneralNameEntry::getType, GeneralNameEntry::getValue)
                .containsExactly(
                        tuple(GeneralNameType.DNS, "app.example.com"),
                        tuple(GeneralNameType.IP, "10.1.2.3"),
                        tuple(GeneralNameType.EMAIL, "ops@example.com"));
    }

    @Test
    void returnsEmptySans_whenCertificateHasNoSanExtension() throws Exception {
        // given
        X509Certificate certificate = certificate(subject("no-sans"), null);

        // when
        X509RequestContent content = RequestContentSeeder.seedFromCertificate(certificate);

        // then
        assertThat(content.getSubjectAltNames())
                .as("a certificate without a SAN extension seeds an empty SAN list")
                .isEmpty();
    }

    @Test
    void leavesExtensionsEmpty_evenWhenCertificateCarriesExtensions() throws Exception {
        // given: the helper always adds BasicConstraints + KeyUsage to the certificate
        GeneralNames sans = new GeneralNames(new GeneralName(GeneralName.dNSName, "app.example.com"));
        X509Certificate certificate = certificate(subject("with-extensions"), sans);

        // when
        X509RequestContent content = RequestContentSeeder.seedFromCertificate(certificate);

        // then
        assertThat(content.getExtensions())
                .as("extension seeding is deferred: issued-certificate extensions must never be echoed")
                .isEmpty();
    }

    @Test
    void skipsSanKindsWithoutTypedRepresentation_keepingTypedOnes() throws Exception {
        // given: x400Address has no GeneralNameType counterpart
        GeneralNames sans = new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.x400Address, new DERSequence()),
                new GeneralName(GeneralName.dNSName, "kept.example.com")});
        X509Certificate certificate = certificate(subject("mixed-sans"), sans);

        // when
        X509RequestContent content = RequestContentSeeder.seedFromCertificate(certificate);

        // then
        assertThat(content.getSubjectAltNames())
                .as("SAN kinds the typed model cannot represent are skipped; typed ones survive")
                .extracting(GeneralNameEntry::getType, GeneralNameEntry::getValue)
                .containsExactly(tuple(GeneralNameType.DNS, "kept.example.com"));
    }

    @Test
    void seedsEmptySubject_forSanOnlyCertificate() throws Exception {
        // given: RFC 5280 §4.1.2.6 allows an empty subject when SAN carries the identity
        GeneralNames sans = new GeneralNames(new GeneralName(GeneralName.dNSName, "san-only.example.com"));
        X509Certificate certificate = certificate(new X500Name(new RDN[0]), sans);

        // when
        X509RequestContent content = RequestContentSeeder.seedFromCertificate(certificate);

        // then
        assertThat(content.getSubject()).as("SAN-only certificate seeds an empty subject").isEmpty();
        assertThat(content.getSubjectAltNames()).hasSize(1);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static X500Name subject(String commonName) {
        return new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, commonName).build();
    }

    /**
     * Certificate carrying BasicConstraints + KeyUsage and (optionally) a SAN extension. The issuer is
     * a fixed non-empty DN (never the subject) so a SAN-only certificate — RFC 5280 §4.1.2.6 permits an
     * empty subject — is still valid; the seeder reads only subject, SAN and extensions, never the issuer.
     */
    private static X509Certificate certificate(X500Name subject, GeneralNames sans) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        X500Name issuer = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "test-issuer").build();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.ONE,
                new Date(System.currentTimeMillis() - 1_000L),
                new Date(System.currentTimeMillis() + 86_400_000L),
                subject, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        if (sans != null) {
            // RFC 5280 §4.2.1.6: SAN must be critical when the subject is empty.
            boolean sanCritical = subject.getRDNs().length == 0;
            builder.addExtension(Extension.subjectAlternativeName, sanCritical, sans);
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
