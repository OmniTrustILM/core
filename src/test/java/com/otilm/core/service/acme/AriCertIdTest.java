package com.otilm.core.service.acme;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AriCertIdTest {

    private static final String RFC_EXAMPLE = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE";

    @Test
    void parsesRfcExample() {
        AriCertId id = AriCertId.parse(RFC_EXAMPLE);

        assertArrayEquals(Base64.getUrlDecoder().decode("aYhba4dGQEHhs3uEe6CuLN4ByNQ"), id.keyIdentifier());
        assertEquals("87654321", id.serialHex());
    }

    @Test
    void parsesSerialWithLeadingZeroByte() {
        // DER INTEGER 0x00 0x8A 0x01 keeps the sign octet that the high bit of 0x8A requires
        String certId = "AQID."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[]{0x00, (byte) 0x8A, 0x01});

        assertEquals("8a01", AriCertId.parse(certId).serialHex());
    }

    @Test
    void serialWithoutSignOctetMapsToTheSameHex() {
        String certId = "AQID." + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[]{0x0A, 0x01});

        assertEquals("a01", AriCertId.parse(certId).serialHex());
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
    void rejectsMalformedIds(String certId) {
        assertThrows(IllegalArgumentException.class, () -> AriCertId.parse(certId));
    }

    @Test
    void rejectsNull() {
        assertThrows(IllegalArgumentException.class, () -> AriCertId.parse(null));
    }

    @Test
    void buildsTheIdOfACertificate() throws Exception {
        KeyPair issuerKeys = keyPair();
        byte[] keyIdentifier = new JcaX509ExtensionUtils()
                .createAuthorityKeyIdentifier(issuerKeys.getPublic())
                .getKeyIdentifier();
        X509Certificate certificate = certificate(issuerKeys, new BigInteger("8a01", 16),
                new AuthorityKeyIdentifier(keyIdentifier));

        AriCertId parsed = AriCertId.parse(AriCertId.of(certificate));

        assertArrayEquals(keyIdentifier, parsed.keyIdentifier());
        assertEquals("8a01", parsed.serialHex());
    }

    @Test
    void refusesACertificateWithoutAuthorityKeyIdentifier() throws Exception {
        X509Certificate certificate = certificate(keyPair(), BigInteger.TEN, null);

        assertThrows(IllegalArgumentException.class, () -> AriCertId.of(certificate));
    }

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
