package com.otilm.core.service.acme;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AriCertIdTest {

    private static final String RFC_EXAMPLE = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE";

    @Test
    void parsesKeyIdentifierAndSerial_whenGivenRfcExample() {
        // given
        String certId = RFC_EXAMPLE;

        // when
        AriCertId id = AriCertId.parse(certId);

        // then
        assertThat(id.keyIdentifier()).isEqualTo(Base64.getUrlDecoder().decode("aYhba4dGQEHhs3uEe6CuLN4ByNQ"));
        assertThat(id.serialHex()).isEqualTo("87654321");
    }

    @Test
    void keepsSerialWithoutSignOctet_whenSerialStartsWithLeadingZeroByte() {
        // given
        // DER INTEGER 0x00 0x8A 0x01 keeps the sign octet that the high bit of 0x8A requires
        String withLeadingZeroByte = "AQID."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[]{0x00, (byte) 0x8A, 0x01});

        // when
        AriCertId id = AriCertId.parse(withLeadingZeroByte);

        // then
        assertThat(id.serialHex()).isEqualTo("8a01");
    }

    @Test
    void mapsToTheSameHex_whenSerialHasNoSignOctet() {
        // given
        String withoutSignOctet = "AQID."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[]{0x0A, 0x01});

        // when
        AriCertId id = AriCertId.parse(withoutSignOctet);

        // then
        assertThat(id.serialHex()).isEqualTo("a01");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "nodothere",
            ".AIdlQyE",
            "aYhba4dGQEHhs3uEe6CuLN4ByNQ.",
            "AQID.AQID.AQID",
            "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE=",
            "AQID=.AIdlQyE",
            "AQ+D.AIdlQyE",
            "AQID.AI/lQyE",
            "AQ ID.AIdlQyE",
            "A.AIdlQyE"})
    void rejectsId_whenMalformed(String malformedCertId) {
        // given — a certId that is not two base64url segments separated by a single dot

        // when
        ThrowingCallable parse = () -> AriCertId.parse(malformedCertId);

        // then
        assertThatThrownBy(parse).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsId_whenNull() {
        // given
        String nullCertId = null;

        // when
        ThrowingCallable parse = () -> AriCertId.parse(nullCertId);

        // then
        assertThatThrownBy(parse).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void roundTripsKeyIdentifierAndSerial_whenBuildingIdOfCertificate() throws Exception {
        // given
        KeyPair issuerKeys = keyPair();
        byte[] keyIdentifier = new JcaX509ExtensionUtils()
                .createAuthorityKeyIdentifier(issuerKeys.getPublic())
                .getKeyIdentifier();
        X509Certificate certificate = certificate(issuerKeys, new BigInteger("8a01", 16),
                new AuthorityKeyIdentifier(keyIdentifier));

        // when
        AriCertId parsed = AriCertId.parse(AriCertId.of(certificate));

        // then
        assertThat(parsed.keyIdentifier()).isEqualTo(keyIdentifier);
        assertThat(parsed.serialHex()).isEqualTo("8a01");
    }

    @Test
    void refusesId_whenCertificateHasNoAuthorityKeyIdentifier() throws Exception {
        // given
        X509Certificate withoutAuthorityKeyIdentifier = certificate(keyPair(), BigInteger.TEN, null);

        // when
        ThrowingCallable buildId = () -> AriCertId.of(withoutAuthorityKeyIdentifier);

        // then
        assertThatThrownBy(buildId).isInstanceOf(IllegalArgumentException.class);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(KeyPair keys, BigInteger serial, AuthorityKeyIdentifier aki)
            throws Exception {
        X500Name name = new X500Name("CN=ari-test");
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, serial,
                new Date(System.currentTimeMillis() - 1000), new Date(System.currentTimeMillis() + 100000), name,
                keys.getPublic());
        if (aki != null) {
            builder.addExtension(Extension.authorityKeyIdentifier, false, aki);
        }
        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
    }
}
