package com.otilm.core.service.scep;

import com.otilm.api.model.core.scep.MessageType;
import com.otilm.core.service.scep.message.ScepConstants;
import com.otilm.core.util.CertificateUtil;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.PasswordRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * SCEP wire messages for tests. The material is a P-256 signer certificate with its private key and a PKCS#10 request
 * for {@code CN=x11}, so a message can be produced whose enveloped content is decryptable with
 * {@link #CHALLENGE_PASSWORD} through the RFC 8894 password recipient — no token connector needed.
 */
public final class ScepMessageTestData {

    public static final String CHALLENGE_PASSWORD = "mysecretpassword";
    public static final String SUBJECT_DN = "CN=x11";

    private static final String CSR_B64 = "MIICUzCCATsCAQAwDjEMMAoGA1UEAwwDeDExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx3yEn1ivUp4etk3kdNrRXNP5PeIpTYobGj4lQrW57rsj9hhOhY/SwaeCu6sYPVvYIXPWnlc4tTafjcen/8Ikc7pY2NuzD0HaIAOujblcMKT2KAKA/OU+RrI2o/swU9UmEQ2wYveNYCGobimt/foURrB9opeDCx3pFXkddYsXAziaWu3AQIF5gIf/b+r7hYRIXh8V/u01t6FCnpBWCtdmYVrJ5e8KZw0yqptNpgDK1plu+8AR5tviP/vgrpBquwzNsVREsnRZJxOM6rXq9rG5scoqO+gxdsm6+EqfRiGiBvcaIr+Zpv81ryfiABLdixvyhoZ//3o8rAU0O7Pjm7HTxwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAKM6lsrzME64G90fm98Zdgxe6IMBmIWTzA03V0OWGTYjYjYZbfsddAQAO1h3EMKjPl5nFaXkTVGoq8G4ZHvdu2fX72dyNJaGG+mG89uoW9iFd2US+nU5aN8xSpPx1k89DhPat/q5kdOwIIGAXvIbLWSXGx9A25DxdqvouuhDT7NJZqGTsPivHuFXgP3Mb1HTr/qnshx+shTnJ+FnYncARl3KmflCyCPC4NBKcorWl8kVFRDw2Y7aeg3a1hV3EJJfElFSwlmmT2Y/VDuZcMalFnnAKq2NqXByBlK9s7s67sMKzsqaAGwlg3TT37v6QN6L2q0zUU6egAuA4Av2LR6nJkw=";
    private static final String SIGNER_CERT_B64 = "MIIB5TCCAYqgAwIBAgIUQWJcNhcZ8rdJ8d+Y0/zjDauIDvAwCgYIKoZIzj0EAwIwNzELMAkGA1UEBhMCSU4xEzARBgNVBAgMClRhbWlsIE5hZHUxEzARBgNVBAcMCkNvaW1iYXRvcmUwHhcNMjMwNDE5MTAxNjI0WhcNMjQwNDE4MTAxNjI0WjA3MQswCQYDVQQGEwJJTjETMBEGA1UECAwKVGFtaWwgTmFkdTETMBEGA1UEBwwKQ29pbWJhdG9yZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1ILz/GLiGtx9JIoFesLv6ssTrBr5W1c+FUuCKUGjvZpM8l5wAbC9TJaYwcA3B45iuTAzmTTOoPCwrr/ALGhoyjdDByMB0GA1UdDgQWBBT4VuTPGMKzKGqAYgAtq7eFR+nPpzAfBgNVHSMEGDAWgBT4VuTPGMKzKGqAYgAtq7eFR+nPpzAOBgNVHQ8BAf8EBAMCBaAwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAoGCCqGSM49BAMCA0kAMEYCIQCUxvkZzxraytwbhhoCafIzHaj62EGVbxW5bUlvLTZPIwIhAJ6eFFyO8f9udwCHUt+4aMQGyBHCISbgvgvejMU6NSZU";
    private static final String SIGNER_KEY_B64 = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgR7jrC6SUkUlWEouD/5yVwazngKD0mHjA4YsOhesg+fShRANCAASNSC8/xi4hrcfSSKBXrC7+rLE6wa+VtXPhVLgilBo72aTPJecAGwvUyWmMHANweOYrkwM5k0zqDwsK6/wCxoaM";
    public static final String TRANSACTION_ID = "361ba25258bfc72fe6cf8aa70f75e21facd8fc3d";
    private static final String SENDER_NONCE_B64 = "cVpmdzRXdDBPV25JNVA0Y1pMcHZvSzJuUG9fUlR2cXhZT0RBOUdGdlE2cw==";

    private ScepMessageTestData() {
    }

    /** A signed PKCSReq whose PKCS#10 request is enveloped to a password recipient. */
    public static byte[] passwordEnvelopedPkcsReq() throws Exception {
        return signedMessage(envelopedPkcs10Request(Base64.getDecoder().decode(CSR_B64)), MessageType.PKCS_REQ)
                .getEncoded();
    }

    /**
     * The same message with a freshly generated PKCS#10 request for {@link #SUBJECT_DN}, optionally carrying a
     * challengePassword attribute — {@code null} reproduces a renewal request, which omits it (RFC 8894 §3.3.1.2).
     */
    public static byte[] passwordEnvelopedPkcsReq(String csrChallengePassword) throws Exception {
        return passwordEnvelopedMessage(MessageType.PKCS_REQ, csrChallengePassword);
    }

    /**
     * A PKCSReq enveloped to a different password than the profile holds, so the platform cannot open it.
     */
    public static byte[] pkcsReqEnvelopedWith(String envelopePassword) throws Exception {
        return signedMessage(envelopedPkcs10Request(generatedCsr(null), envelopePassword), MessageType.PKCS_REQ)
                .getEncoded();
    }

    /** The same message declared as an arbitrary SCEP message type. */
    public static byte[] passwordEnvelopedMessage(MessageType messageType, String csrChallengePassword)
            throws Exception {
        return signedMessage(envelopedPkcs10Request(generatedCsr(csrChallengePassword)), messageType).getEncoded();
    }

    /**
     * A signed PKCSReq whose PKCS#10 request — for an arbitrary subject, with optional dNSName SANs and an optional
     * challengePassword — is enveloped via RSA key transport to the recipient CA certificate, the way a client talks to
     * an RSA-keyed CA. Opening it requires the CA private key (in tests: a stubbed connector decrypt returning the
     * content-encryption key).
     */
    public static byte[] keyTransportEnvelopedPkcsReq(X509Certificate recipientCaCertificate, String subjectDn,
            List<String> dnsSans, String csrChallengePassword) throws Exception {
        return keyTransportEnvelopedPkcsReq(recipientCaCertificate, subjectDn, dnsSans, csrChallengePassword,
                TRANSACTION_ID);
    }

    /** As above but with an explicit transaction id, so a second enrolment is not folded into a poll by the dedup. */
    public static byte[] keyTransportEnvelopedPkcsReq(X509Certificate recipientCaCertificate, String subjectDn,
            List<String> dnsSans, String csrChallengePassword, String transactionId) throws Exception {
        byte[] csrBytes = generatedCsr(subjectDn, dnsSans, csrChallengePassword);
        return signedMessage(keyTransportEnvelopedRequest(csrBytes, recipientCaCertificate), MessageType.PKCS_REQ,
                transactionId).getEncoded();
    }

    private static CMSProcessableByteArray keyTransportEnvelopedRequest(byte[] csrBytes,
            X509Certificate recipientCaCertificate) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        CMSEnvelopedDataGenerator envelopedDataGenerator = new CMSEnvelopedDataGenerator();
        envelopedDataGenerator
                .addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCaCertificate)
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME));

        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                .setProvider("BC")
                .build();
        CMSEnvelopedData envelope = envelopedDataGenerator.generate(new CMSProcessableByteArray(csrBytes), encryptor);
        return new CMSProcessableByteArray(envelope.getEncoded());
    }

    private static byte[] generatedCsr(String subjectDn, List<String> dnsSans, String challengePassword)
            throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectDn),
                keyPair.getPublic());
        if (challengePassword != null) {
            builder
                    .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                            new DERPrintableString(challengePassword));
        }
        if (dnsSans != null && !dnsSans.isEmpty()) {
            ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
            extensionsGenerator
                    .addExtension(Extension.subjectAlternativeName, false,
                            new GeneralNames(dnsSans
                                    .stream()
                                    .map(dns -> new GeneralName(GeneralName.dNSName, dns))
                                    .toArray(GeneralName[]::new)));
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
        return builder.build(signer).getEncoded();
    }

    /**
     * A PKCSReq whose EnvelopedData carries no recipientInfo at all, so nothing can be decrypted from it.
     */
    public static byte[] recipientlessPkcsReq() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                .setProvider("BC")
                .build();
        CMSEnvelopedData envelope = new CMSEnvelopedDataGenerator()
                .generate(new CMSProcessableByteArray(generatedCsr(null)), encryptor);
        return signedMessage(new CMSProcessableByteArray(envelope.getEncoded()), MessageType.PKCS_REQ).getEncoded();
    }

    private static byte[] generatedCsr(String challengePassword) throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name(SUBJECT_DN), keyPair.getPublic());
        if (challengePassword != null) {
            builder
                    .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                            new DERPrintableString(challengePassword));
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
        return builder.build(signer).getEncoded();
    }

    /** The signer certificate the message above is signed with. */
    public static X509Certificate signerCertificate() throws Exception {
        return CertificateUtil.parseCertificate(SIGNER_CERT_B64);
    }

    private static CMSProcessableByteArray envelopedPkcs10Request(byte[] csrBytes) throws Exception {
        return envelopedPkcs10Request(csrBytes, CHALLENGE_PASSWORD);
    }

    private static CMSProcessableByteArray envelopedPkcs10Request(byte[] csrBytes, String envelopePassword)
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        PasswordRecipientInfoGenerator recipientGenerator = new JcePasswordRecipientInfoGenerator(
                CMSAlgorithm.AES128_CBC, envelopePassword.toCharArray());

        CMSEnvelopedDataGenerator envelopedDataGenerator = new CMSEnvelopedDataGenerator();
        envelopedDataGenerator.addRecipientInfoGenerator(recipientGenerator);

        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                .setProvider("BC")
                .build();
        CMSEnvelopedData envelope = envelopedDataGenerator.generate(new CMSProcessableByteArray(csrBytes), encryptor);
        return new CMSProcessableByteArray(envelope.getEncoded());
    }

    private static org.bouncycastle.cms.CMSSignedData signedMessage(CMSProcessableByteArray content,
            MessageType messageType) throws Exception {
        return signedMessage(content, messageType, TRANSACTION_ID);
    }

    private static org.bouncycastle.cms.CMSSignedData signedMessage(CMSProcessableByteArray content,
            MessageType messageType, String transactionId) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        X509Certificate signerCertificate = signerCertificate();
        PrivateKey signerPrivateKey = KeyFactory
                .getInstance("EC")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(SIGNER_KEY_B64)));

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithECDSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signerPrivateKey);
        JcaDigestCalculatorProviderBuilder digestProviderBuilder = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME);
        JcaSignerInfoGeneratorBuilder signerInfoBuilder = new JcaSignerInfoGeneratorBuilder(
                digestProviderBuilder.build());
        signerInfoBuilder
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(
                        new AttributeTable(scepAttributes(messageType, transactionId))));

        CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();
        signedDataGenerator.addSignerInfoGenerator(signerInfoBuilder.build(contentSigner, signerCertificate));
        signedDataGenerator.addCertificates(new JcaCertStore(Collections.singletonList(signerCertificate)));

        return signedDataGenerator.generate(content, true);
    }

    private static Hashtable<ASN1ObjectIdentifier, Attribute> scepAttributes(MessageType messageType,
            String transactionId) {
        Hashtable<ASN1ObjectIdentifier, Attribute> attributes = new Hashtable<>();
        addAttribute(attributes, ScepConstants.id_messageType,
                new DERSet(new DERPrintableString(Integer.toString(messageType.getValue()))));
        addAttribute(attributes, ScepConstants.id_transactionId, new DERSet(new DERPrintableString(transactionId)));
        addAttribute(attributes, ScepConstants.id_senderNonce,
                new DERSet(new DEROctetString(Base64.getDecoder().decode(SENDER_NONCE_B64))));
        return attributes;
    }

    private static void addAttribute(Hashtable<ASN1ObjectIdentifier, Attribute> attributes, String oid, DERSet value) {
        Attribute attribute = new Attribute(new ASN1ObjectIdentifier(oid), value);
        attributes.put(attribute.getAttrType(), attribute);
    }
}
