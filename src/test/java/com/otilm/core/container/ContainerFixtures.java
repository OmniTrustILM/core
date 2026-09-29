package com.otilm.core.container;

import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.key.normalization.DerivationBudget;
import com.otilm.core.key.normalization.ExplicitCurveFixtures;
import com.otilm.core.key.normalization.KeyDescription;
import com.otilm.core.key.normalization.KeyNormalizer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.RoleSyntax;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509AttributeIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.AttributeCertificateIssuer;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2AttributeCertificateBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/** Certificates, keys and files made in the tests, in the encodings the container reader takes. */
public final class ContainerFixtures {

    public static final char[] PASSPHRASE = "correct horse battery".toCharArray();

    public static final String LF = "\n";

    static final String CRLF = "\r\n";

    /** Few iterations, so that a test file opens fast. */
    private static final int ITERATIONS = 2048;

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] BYTE_ORDER_MARK = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};

    private ContainerFixtures() {
    }

    /** The providers the reader names, which the application registers when it starts. */
    public static void registerProviders() {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    /** A reader of the formats this package holds, asked in their order. */
    static ContainerReader reader() {
        return new ContainerReader(List.of(new PemFormat(), new DerFormat()),
                new ContainerAssembler(new KeyNormalizer()));
    }

    /** A key normalizer that records each key it is asked to describe, in the order it is asked. */
    static final class RecordingNormalizer extends KeyNormalizer {

        private final List<byte[]> described = new ArrayList<>();

        @Override
        public KeyDescription describe(byte[] key, Passphrase passphrase, DerivationBudget budget) {
            described.add(key);
            return super.describe(key, passphrase, budget);
        }

        /** The keys described so far, as the arrays the normalizer was handed. */
        List<byte[]> described() {
            return described;
        }
    }

    static Passphrase passphrase() {
        return new Passphrase(PASSPHRASE);
    }

    static KeyPair rsa() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", BC);
        generator.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
        return generator.generateKeyPair();
    }

    /** An EC key pair on P-256, whose public key encodes with the curve's name. */
    public static KeyPair ec() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BC);
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    public static KeyPair ed25519() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("Ed25519", BC).generateKeyPair();
    }

    /**
     * An RSA root, an intermediate CA it issued and a leaf the intermediate issued.
     *
     * @param leafKey the leaf's key pair
     * @param intermediateKey the intermediate's key pair, which can issue further leaves
     */
    public record Chain(X509CertificateHolder root, X509CertificateHolder intermediate, X509CertificateHolder leaf,
            KeyPair leafKey, KeyPair intermediateKey) {
    }

    public static Chain rsaChain() throws Exception {
        KeyPair rootKey = rsa();
        KeyPair intermediateKey = rsa();
        KeyPair leafKey = rsa();
        X509CertificateHolder root = selfSigned(rootKey, "CN=Root");
        X509CertificateHolder intermediate = certificate("CN=Intermediate", intermediateKey.getPublic(), "CN=Root",
                rootKey.getPrivate(), daysAgo(1));
        X509CertificateHolder leaf = certificate("CN=Leaf", leafKey.getPublic(), "CN=Intermediate",
                intermediateKey.getPrivate(), daysAgo(1));
        return new Chain(root, intermediate, leaf, leafKey, intermediateKey);
    }

    /** A certificate for the public key, issued under the issuer's name and signed with the issuer's key. */
    public static X509CertificateHolder certificate(String subject, PublicKey publicKey, String issuer,
            PrivateKey issuerKey, Instant notBefore) throws OperatorCreationException {
        return builder(subject, publicKey, issuer, notBefore).build(signer(issuerKey));
    }

    /**
     * A certificate as {@link #certificate(String, PublicKey, String, PrivateKey, Instant)} makes it, carrying the key
     * identifiers given, each left out when {@code null}.
     */
    static X509CertificateHolder withKeyIdentifiers(String subject, PublicKey publicKey, String issuer,
            PrivateKey issuerKey, byte[] subjectKeyIdentifier, byte[] authorityKeyIdentifier) throws Exception {
        X509v3CertificateBuilder builder = builder(subject, publicKey, issuer, daysAgo(1));
        if (subjectKeyIdentifier != null) {
            builder.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(subjectKeyIdentifier));
        }
        if (authorityKeyIdentifier != null) {
            builder
                    .addExtension(Extension.authorityKeyIdentifier, false,
                            new AuthorityKeyIdentifier(authorityKeyIdentifier));
        }
        return builder.build(signer(issuerKey));
    }

    /** A certificate whose subject key identifier extension holds the value given, readable or not. */
    static X509CertificateHolder withSubjectKeyIdentifierValue(String subject, PublicKey publicKey, String issuer,
            PrivateKey issuerKey, byte[] value) throws Exception {
        return builder(subject, publicKey, issuer, daysAgo(1))
                .addExtension(Extension.subjectKeyIdentifier, false, value)
                .build(signer(issuerKey));
    }

    /** A self-signed certificate carrying the extension with the value given, readable or not. */
    static X509CertificateHolder selfSignedWithExtension(KeyPair keyPair, String subject,
            ASN1ObjectIdentifier extension, byte[] value) throws Exception {
        return builder(subject, keyPair.getPublic(), subject, daysAgo(1))
                .addExtension(extension, false, value)
                .build(signer(keyPair.getPrivate()));
    }

    public static X509CertificateHolder selfSigned(KeyPair keyPair, String subject) throws OperatorCreationException {
        return certificate(subject, keyPair.getPublic(), subject, keyPair.getPrivate(), daysAgo(1));
    }

    static Instant daysAgo(int days) {
        return NOW.minus(Duration.ofDays(days));
    }

    public static PKCS10CertificationRequest signingRequest(KeyPair keyPair) throws OperatorCreationException {
        return new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Request"), keyPair.getPublic())
                .build(signer(keyPair.getPrivate()));
    }

    /** The key as DER PKCS#8, without protection. */
    static byte[] pkcs8(KeyPair keyPair) {
        return keyPair.getPrivate().getEncoded();
    }

    /** The key as DER PKCS#8 under PBES2, PBKDF2 over HMAC-SHA256 and AES-256-CBC, with {@link #PASSPHRASE}. */
    static byte[] encryptedPkcs8(KeyPair keyPair) throws Exception {
        OutputEncryptor encryptor = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                .setProvider(BC)
                .setPRF(PKCS8Generator.PRF_HMACSHA256)
                .setIterationCount(ITERATIONS)
                .setPassword(PASSPHRASE)
                .build();
        return new PKCS8EncryptedPrivateKeyInfoBuilder(PrivateKeyInfo.getInstance(pkcs8(keyPair)))
                .build(encryptor)
                .getEncoded();
    }

    /** The EC key as DER PKCS#8 stating its curve by its parameters rather than its name. */
    static byte[] explicitCurvePkcs8(KeyPair ec) throws IOException {
        X9ECParameters curve = ECNamedCurveTable.getByName("P-256");
        ECPrivateKey named = ECPrivateKey.getInstance(PrivateKeyInfo.getInstance(pkcs8(ec)).parsePrivateKey());
        ECPrivateKey explicit = new ECPrivateKey(256, named.getKey(), named.getPublicKey(), curve);
        return new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curve), explicit)
                .getEncoded(ASN1Encoding.DER);
    }

    /**
     * A public key stating its curve by parameters: the generator of a curve {@link ExplicitCurveFixtures#madeUp} makes
     * over a prime field of the size given, stating an order of the size given and a cofactor of 2, for which Bouncy
     * Castle multiplies the generator by that order before it builds a key.
     */
    static SubjectPublicKeyInfo explicitCurvePublicKey(int fieldBits, int orderBits) {
        X9ECParameters curve = ExplicitCurveFixtures.madeUp(fieldBits, orderBits, BigInteger.TWO);
        return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curve),
                curve.getBaseEntry().getPointEncoding());
    }

    /** A certificate carrying the public key, signed with a key it does not carry, which nothing checks. */
    static X509CertificateHolder certificateOf(SubjectPublicKeyInfo publicKey)
            throws GeneralSecurityException, OperatorCreationException {
        X500Name name = new X500Name("CN=Explicit curve");
        return new X509v3CertificateBuilder(name, new BigInteger(64, RANDOM), Date.from(daysAgo(1)),
                Date.from(NOW.plus(Duration.ofDays(365))), name, publicKey).build(signer(ec().getPrivate()));
    }

    /** A certificate request carrying the public key, signed with a key it does not carry, which nothing checks. */
    static PKCS10CertificationRequest signingRequestOf(SubjectPublicKeyInfo publicKey)
            throws GeneralSecurityException, OperatorCreationException {
        return new PKCS10CertificationRequestBuilder(new X500Name("CN=Request"), publicKey)
                .build(signer(ec().getPrivate()));
    }

    public static PemObject privateKeyBlock(KeyPair keyPair) {
        return new PemObject("PRIVATE KEY", pkcs8(keyPair));
    }

    public static PemObject encryptedPrivateKeyBlock(KeyPair keyPair) throws Exception {
        return new PemObject("ENCRYPTED PRIVATE KEY", encryptedPkcs8(keyPair));
    }

    /** The curve OpenSSL writes before an EC key it generates. */
    static PemObject ecParametersBlock() throws IOException {
        return new PemObject("EC PARAMETERS", SECObjectIdentifiers.secp256r1.getEncoded());
    }

    /** The key as OpenSSL traditional PEM under the cipher, or without protection when {@code cipher} is null. */
    static byte[] traditional(KeyPair keyPair, String cipher) throws Exception {
        StringWriter pem = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(pem)) {
            writer
                    .writeObject(cipher == null
                            ? new JcaMiscPEMGenerator(keyPair.getPrivate())
                            : new JcaMiscPEMGenerator(keyPair.getPrivate(),
                                    new JcePEMEncryptorBuilder(cipher).setProvider(BC).build(PASSPHRASE)));
        }
        return pem.toString().getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * A binary PKCS#7 {@code SignedData} carrying the certificates and nothing else, in the order given: encoded with
     * definite lengths as DER is, but with the set of certificates left in that order, as OpenSSL writes it.
     */
    static byte[] pkcs7(X509CertificateHolder... certificates) throws Exception {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addCertificates(new CollectionStore<>(List.of(certificates)));
        return generator.generate(new CMSAbsentContent()).getEncoded(ASN1Encoding.DL);
    }

    /** A DER PKCS#7 carrying the certificate beside an attribute certificate and a CRL its issuer signed. */
    static byte[] pkcs7WithOtherContent(X509CertificateHolder certificate, X509CertificateHolder issuer,
            PrivateKey issuerKey) throws Exception {
        Date now = Date.from(NOW);
        X509AttributeCertificateHolder attributeCertificate = new X509v2AttributeCertificateBuilder(
                new AttributeCertificateHolder(certificate), new AttributeCertificateIssuer(issuer.getSubject()),
                BigInteger.ONE, now, Date.from(NOW.plus(Duration.ofDays(1))))
                .addAttribute(X509AttributeIdentifiers.id_at_role, new RoleSyntax("operator"))
                .build(signer(issuerKey));
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addCertificate(certificate);
        generator.addAttributeCertificate(attributeCertificate);
        generator.addCRL(new X509v2CRLBuilder(issuer.getSubject(), now).build(signer(issuerKey)));
        return generator.generate(new CMSAbsentContent()).getEncoded(ASN1Encoding.DER);
    }

    /** An empty key store of the type, as the JDK writes it under {@link #PASSPHRASE}. */
    static byte[] keyStore(String type) throws Exception {
        KeyStore store = KeyStore.getInstance(type);
        store.load(null, null);
        ByteArrayOutputStream file = new ByteArrayOutputStream();
        store.store(file, PASSPHRASE);
        return file.toByteArray();
    }

    /**
     * PEM text of the blocks in order, every line ended with the line ending. A block is a PEM object, a certificate, a
     * certificate request, PEM text already written, or a line of text around the blocks.
     */
    public static byte[] pem(String lineEnding, Object... blocks) throws IOException {
        StringBuilder text = new StringBuilder();
        for (Object block : blocks) {
            String written = switch (block) {
                case PemObject pemObject -> written(pemObject);
                case X509CertificateHolder certificate ->
                    written(new PemObject("CERTIFICATE", certificate.getEncoded()));
                case PKCS10CertificationRequest request ->
                    written(new PemObject("CERTIFICATE REQUEST", request.getEncoded()));
                case byte[] pemText -> new String(pemText, StandardCharsets.US_ASCII);
                case String line -> line + LF;
                default -> throw new IllegalArgumentException("Not a PEM block: " + block.getClass());
            };
            text.append(written.replace(CRLF, LF).replace(LF, lineEnding));
        }
        return text.toString().getBytes(StandardCharsets.US_ASCII);
    }

    /** The text preceded by the byte order mark editors on Windows write. */
    static byte[] withByteOrderMark(byte[] text) {
        byte[] marked = new byte[BYTE_ORDER_MARK.length + text.length];
        System.arraycopy(BYTE_ORDER_MARK, 0, marked, 0, BYTE_ORDER_MARK.length);
        System.arraycopy(text, 0, marked, BYTE_ORDER_MARK.length, text.length);
        return marked;
    }

    /** Constructed values nested {@code depth} deep. */
    static byte[] nested(int depth) throws IOException {
        ASN1Encodable value = DERNull.INSTANCE;
        for (int level = 0; level < depth; level++) {
            value = new DERSequence(value);
        }
        return value.toASN1Primitive().getEncoded(ASN1Encoding.DER);
    }

    /** The lowercase hex SHA-256 of the content, as an entry reference states it. */
    public static String sha256(byte[] content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509v3CertificateBuilder builder(String subject, PublicKey publicKey, String issuer,
            Instant notBefore) {
        return new JcaX509v3CertificateBuilder(new X500Name(issuer), new BigInteger(64, RANDOM), Date.from(notBefore),
                Date.from(notBefore.plus(Duration.ofDays(365))), new X500Name(subject), publicKey);
    }

    private static ContentSigner signer(PrivateKey key) throws OperatorCreationException {
        String algorithm = switch (key.getAlgorithm()) {
            case "RSA" -> "SHA256withRSA";
            case "EC", "ECDSA" -> "SHA256withECDSA";
            default -> key.getAlgorithm();
        };
        return new JcaContentSignerBuilder(algorithm).setProvider(BC).build(key);
    }

    private static String written(PemObject block) throws IOException {
        StringWriter pem = new StringWriter();
        try (PemWriter writer = new PemWriter(pem)) {
            writer.writeObject(block);
        }
        return pem.toString();
    }
}
