package com.otilm.core.service.acme.identifier;

import com.otilm.api.model.core.acme.Identifier;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Built against real certification requests rather than a stub of one, because what an ordered identifier is compared
 * with is whatever Bouncy Castle hands back for a subjectAltName, and that is the part worth pinning.
 */
class AcmeCsrIdentifiersTest {

    private static KeyPair keyPair;

    @BeforeAll
    static void generateKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
    }

    @Test
    void anIpv4AddressIsCarried() throws Exception {
        AcmeCsrIdentifiers offered = AcmeCsrIdentifiers.of(csr("host.example.com", address("192.0.2.1")));

        assertTrue(offered.carries(identifier("ip", "192.0.2.1")));
        assertFalse(offered.carries(identifier("ip", "192.0.2.2")));
    }

    @Test
    void anIpv6AddressIsCarriedHoweverItIsWritten() throws Exception {
        AcmeCsrIdentifiers offered = AcmeCsrIdentifiers.of(csr("host.example.com", address("2001:db8::1")));

        assertTrue(offered.carries(identifier("ip", "2001:db8::1")));
        assertTrue(offered.carries(identifier("ip", "2001:0db8:0000:0000:0000:0000:0000:0001")),
                "the same address written out in full");
        assertTrue(offered.carries(identifier("ip", "2001:DB8::1")), "and in upper case");
        assertFalse(offered.carries(identifier("ip", "2001:db8::2")));
    }

    @Test
    void anAddressIsNotCarriedByTheNameThatReadsTheSame() throws Exception {
        AcmeCsrIdentifiers byName = AcmeCsrIdentifiers
                .of(csr("192.0.2.1", new GeneralName(GeneralName.dNSName, "192.0.2.1")));

        assertFalse(byName.carries(identifier("ip", "192.0.2.1")),
                "RFC 8738 puts an address in a subjectAltName, and a common name is text that was never one");
        assertTrue(byName.carries(identifier("dns", "192.0.2.1")));
    }

    @Test
    void aDnsNameIsCarriedIgnoringCaseAndTheRootDot() throws Exception {
        AcmeCsrIdentifiers offered = AcmeCsrIdentifiers
                .of(csr("host.example.com", new GeneralName(GeneralName.dNSName, "web.example.com")));

        assertTrue(offered.carries(identifier("dns", "web.example.com")));
        assertTrue(offered.carries(identifier("dns", "WEB.example.com")), "an order accepts either casing");
        assertTrue(offered.carries(identifier("dns", "web.example.com.")));
        assertTrue(offered.carries(identifier("dns", "host.example.com")), "the common name counts as a name");
        assertFalse(offered.carries(identifier("dns", "other.example.com")));
    }

    @Test
    void anIdentifierTypeNothingCanProveIsNeverCarried() throws Exception {
        AcmeCsrIdentifiers offered = AcmeCsrIdentifiers
                .of(csr("host.example.com", new GeneralName(GeneralName.rfc822Name, "someone@example.com")));

        assertFalse(offered.carries(identifier("email", "someone@example.com")));
        assertFalse(offered.carries(identifier(null, "host.example.com")));
        assertFalse(offered.carries(identifier("dns", null)));
        assertFalse(offered.carries(null));
    }

    @Test
    void aCsrOfferingNothingCarriesNothing() throws Exception {
        AcmeCsrIdentifiers offered = AcmeCsrIdentifiers.of(csrWithoutExtensions());

        assertFalse(offered.carries(identifier("dns", "web.example.com")));
        assertFalse(offered.carries(identifier("ip", "192.0.2.1")));
        assertTrue(offered.carries(identifier("dns", "host.example.com")), "only the common name is left");
    }

    private static GeneralName address(String literal) {
        return new GeneralName(GeneralName.iPAddress, literal);
    }

    private static Identifier identifier(String type, String value) {
        Identifier identifier = new Identifier();
        identifier.setType(type);
        identifier.setValue(value);
        return identifier;
    }

    private static JcaPKCS10CertificationRequest csr(String commonName, GeneralName... sans) throws Exception {
        ExtensionsGenerator extensions = new ExtensionsGenerator();
        extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans));
        JcaPKCS10CertificationRequestBuilder builder = builder(commonName);
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
        return sign(builder);
    }

    private static JcaPKCS10CertificationRequest csrWithoutExtensions() throws Exception {
        return sign(builder("host.example.com"));
    }

    private static JcaPKCS10CertificationRequestBuilder builder(String commonName) {
        return new JcaPKCS10CertificationRequestBuilder(
                new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, commonName).build(), keyPair.getPublic());
    }

    private static JcaPKCS10CertificationRequest sign(JcaPKCS10CertificationRequestBuilder builder) throws Exception {
        return new JcaPKCS10CertificationRequest(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())).getEncoded());
    }
}
