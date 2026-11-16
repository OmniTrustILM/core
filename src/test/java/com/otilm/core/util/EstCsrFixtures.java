package com.otilm.core.util;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.service.est.message.EstRequestDecoder;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * Enrollment bodies as an EST client sends them: the base64 text of a DER PKCS#10 certification request. Signing needs
 * the BouncyCastle provider to be registered, as it is in the application.
 */
public final class EstCsrFixtures {

    private static final String SUBJECT = "CN=device-1";
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private static final String CURVE = "secp256r1";
    private static final ASN1ObjectIdentifier CHANGE_SUBJECT_NAME = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.7.36");

    private EstCsrFixtures() {
    }

    /** A request whose signature verifies with the key it carries. */
    public static byte[] signedRequestBody() throws Exception {
        KeyPair keyPair = keyPair();
        return requestBody(keyPair.getPrivate(), keyPair.getPublic(), SUBJECT);
    }

    /** A request that carries one key and is signed with another, so its signature does not verify. */
    public static byte[] forgedRequestBody() throws Exception {
        return forgedRequestBody(SUBJECT);
    }

    /** A request for the subject that carries one key and is signed with another. */
    public static byte[] forgedRequestBody(String subject) throws Exception {
        PrivateKey signingKey = keyPair().getPrivate();
        PublicKey carriedKey = keyPair().getPublic();
        return requestBody(signingKey, carriedKey, subject);
    }

    /**
     * A request for the subject that asks for the DNS names as its subject alternative names, when there are any,
     * signed with the key it carries.
     */
    public static byte[] signedRequestBody(String subject, String... dnsNames) throws Exception {
        return signedRequestBodyWithNames(subject, dnsNameEntries(dnsNames));
    }

    /**
     * A request for the subject that asks for the DNS names as its subject alternative names, when there are any,
     * carrying the public key of the key pair and signed with its private key.
     */
    public static byte[] signedRequestBody(KeyPair keys, String subject, String... dnsNames) throws Exception {
        return signedRequestBodyWithNames(keys, subject, dnsNameEntries(dnsNames));
    }

    /**
     * A request for the subject that carries a {@code changeSubjectName} attribute (RFC 6402 section 2.1) holding the
     * subject, signed with the key pair.
     */
    public static byte[] signedRequestBodyWithChangeSubjectName(KeyPair keys, String subject) throws Exception {
        PKCS10CertificationRequestBuilder request = requestFor(subject, keys)
                .addAttribute(CHANGE_SUBJECT_NAME, new DERSequence(new X500Name(subject)));
        return signedBody(request, keys);
    }

    /**
     * A request for the subject that asks for the names as its subject alternative names, when there are any, signed
     * with the key it carries. The subject is written as {@link X500Name} reads it, so a value with a separator is
     * escaped.
     */
    public static byte[] signedRequestBodyWithNames(String subject, GeneralName... names) throws Exception {
        return signedRequestBodyWithNames(keyPair(), subject, names);
    }

    private static byte[] signedRequestBodyWithNames(KeyPair keys, String subject, GeneralName... names)
            throws Exception {
        PKCS10CertificationRequestBuilder request = requestFor(subject, keys);
        if (names.length > 0) {
            request.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, subjectAlternativeNames(names));
        }
        return signedBody(request, keys);
    }

    private static GeneralName[] dnsNameEntries(String... dnsNames) {
        return Arrays
                .stream(dnsNames)
                .map(dnsName -> new GeneralName(GeneralName.dNSName, dnsName))
                .toArray(GeneralName[]::new);
    }

    /**
     * The request for the subject that asks for the DNS names as its subject alternative names, as an authenticator
     * receives it once the body is decoded.
     */
    public static CertificateRequest decodedRequest(String subject, String... dnsNames) throws Exception {
        return EstRequestDecoder.decode(signedRequestBody(subject, dnsNames));
    }

    /** The request for the subject that asks for the names as its subject alternative names, once it is decoded. */
    public static CertificateRequest decodedRequestWithNames(String subject, GeneralName... names) throws Exception {
        return EstRequestDecoder.decode(signedRequestBodyWithNames(subject, names));
    }

    /**
     * An otherName that holds only its type, the five bytes {@code A0 03 06 01 00}: no value follows the OID, so the
     * name cannot be rendered.
     */
    public static GeneralName otherNameWithoutAValue() {
        return new GeneralName(GeneralName.otherName, new DERSequence(new ASN1ObjectIdentifier("0.0")));
    }

    /** A request that carries the public key, signed with an unrelated key, so that its signature does not verify. */
    public static byte[] requestBodyWithPublicKey(SubjectPublicKeyInfo publicKey) throws Exception {
        PKCS10CertificationRequestBuilder request = new PKCS10CertificationRequestBuilder(new X500Name(SUBJECT),
                publicKey);
        return signedBody(request, keyPair());
    }

    /**
     * A request that carries the RSA public key that {@link SignatureVerificationBoundsFixtures#rsaPublicKeyInfo} makes
     * of the same arguments.
     */
    public static byte[] requestBodyWithRsaPublicKey(ASN1ObjectIdentifier algorithm, int modulusBits,
            BigInteger publicExponent) throws Exception {
        return requestBodyWithPublicKey(
                SignatureVerificationBoundsFixtures.rsaPublicKeyInfo(algorithm, modulusBits, publicExponent));
    }

    /** A request for the subject that carries a {@code challengePassword} attribute, signed with the key it carries. */
    public static byte[] signedRequestBodyWithChallengePassword(String subject, String challengePassword)
            throws Exception {
        KeyPair keyPair = keyPair();
        PKCS10CertificationRequestBuilder request = requestFor(subject, keyPair)
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                        new DERPrintableString(challengePassword));
        return signedBody(request, keyPair);
    }

    /**
     * A request for the subject that asks for the DNS name as its subject alternative name and carries one more
     * attribute of the type, signed with the key it carries.
     */
    public static byte[] signedRequestBodyWithAttribute(String subject, String dnsName, ASN1ObjectIdentifier type,
            ASN1Encodable value) throws Exception {
        KeyPair keyPair = keyPair();
        PKCS10CertificationRequestBuilder request = requestFor(subject, keyPair)
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                        subjectAlternativeNames(dnsNameEntries(dnsName)))
                .addAttribute(type, value);
        return signedBody(request, keyPair);
    }

    /** A request for the subject that asks for the extensions, signed with the key it carries. */
    public static byte[] signedRequestBodyWithExtensions(String subject, Extensions extensions) throws Exception {
        KeyPair keyPair = keyPair();
        PKCS10CertificationRequestBuilder request = requestFor(subject, keyPair)
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
        return signedBody(request, keyPair);
    }

    private static KeyPair keyPair() throws Exception {
        return CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.ECDSA, new ECGenParameterSpec(CURVE));
    }

    private static byte[] requestBody(PrivateKey signingKey, PublicKey carriedKey, String subject) throws Exception {
        String base64 = CertificateGeneratorHelper
                .generateCsrBase64Der(signingKey, carriedKey, subject, SIGNATURE_ALGORITHM);
        return base64.getBytes(StandardCharsets.US_ASCII);
    }

    private static PKCS10CertificationRequestBuilder requestFor(String subject, KeyPair keyPair) {
        return new JcaPKCS10CertificationRequestBuilder(new X500Name(subject), keyPair.getPublic());
    }

    private static Extensions subjectAlternativeNames(GeneralName... names) throws Exception {
        ExtensionsGenerator extensions = new ExtensionsGenerator();
        extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
        return extensions.generate();
    }

    private static byte[] signedBody(PKCS10CertificationRequestBuilder request, KeyPair keyPair) throws Exception {
        byte[] der = request
                .build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(keyPair.getPrivate()))
                .getEncoded();
        return Base64.getEncoder().encodeToString(der).getBytes(StandardCharsets.US_ASCII);
    }
}
