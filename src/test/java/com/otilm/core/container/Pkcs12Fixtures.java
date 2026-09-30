package com.otilm.core.container;

import com.otilm.core.key.normalization.KeyNormalizer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCS12SecretBag;
import org.bouncycastle.pkcs.PKCS12SecretBagBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBMac1CalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;

/**
 * PKCS#12 files for the tests: made bag by bag with Bouncy Castle's PKCS#12 builders, or written by OpenSSL and
 * committed under {@code container/pkcs12/}, each OpenSSL file holding the same throwaway RSA key and self-signed
 * certificate.
 */
public final class Pkcs12Fixtures {

    /** The name OpenSSL gave the key and the certificate of its files. */
    public static final String OPENSSL_ALIAS = "pkcs12-test";

    /** OpenSSL's legacy protections: the certificate under 40-bit RC2, the key under 3DES, and a SHA-1 MAC. */
    public static final String OPENSSL_LEGACY = "openssl-legacy.p12";

    /**
     * A PBMAC1 integrity check, PBKDF2 and an HMAC over SHA-256, and PBES2 with AES-256 for the key and certificate.
     */
    public static final String OPENSSL_PBMAC1 = "openssl-pbmac1.p12";

    /** OpenSSL's default protections under an empty password: a SHA-256 MAC, and PBES2 with AES-256. */
    public static final String OPENSSL_EMPTY_PASSWORD = "openssl-empty-password.p12";

    /** The certificate alone under OpenSSL's legacy protections and an empty password. */
    public static final String OPENSSL_LEGACY_EMPTY_PASSWORD = "openssl-legacy-empty-password.p12";

    /** PBES2 with PBKDF2 over HMAC-SHA256 and AES-256-CBC, as OpenSSL 3 and the JDK protect keys and safes. */
    public static final ASN1ObjectIdentifier PBES2_AES_256 = NISTObjectIdentifiers.id_aes256_CBC;

    /** Few iterations, so that a test file opens fast. */
    public static final int ITERATIONS = 2048;

    private static final char[] OPENSSL_PASSPHRASE = "pkcs12-test-passphrase".toCharArray();

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int SALT_BYTES = 16;

    private static final int PBMAC1_KEY_BYTES = 32;

    private static final int PBES1_SALT_BYTES = 8;

    private static final int PFX_VERSION = 3;

    /** The length of the segments an octet string of indefinite length is cut into. */
    private static final int SEGMENT_BYTES = 256;

    private static final String SUN_JCE = "SunJCE";

    /** The JDK's name of each HMAC over SHA-2, which also names its PBKDF2. */
    private static final Map<ASN1ObjectIdentifier, String> JDK_HMACS = Map
            .of(PKCSObjectIdentifiers.id_hmacWithSHA224, "HmacSHA224", PKCSObjectIdentifiers.id_hmacWithSHA256,
                    "HmacSHA256", PKCSObjectIdentifiers.id_hmacWithSHA384, "HmacSHA384",
                    PKCSObjectIdentifiers.id_hmacWithSHA512, "HmacSHA512");

    /** The JCA name of each PBES1 scheme a safe may use. */
    private static final Map<ASN1ObjectIdentifier, String> PBES1_CIPHERS = Map
            .of(PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC, "PBEWithMD5AndDES",
                    PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC, "PBEWithSHA1AndDES");

    private Pkcs12Fixtures() {
    }

    /**
     * A builder of a PKCS#12 file, whose bags go into safes without encryption until an encrypted safe is started.
     *
     * @return a builder of a file without bags and without a MAC
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * The passphrase of the OpenSSL files, but for those under an empty password.
     *
     * @return a copy of the passphrase
     */
    public static char[] openSslPassphrase() {
        return OPENSSL_PASSPHRASE.clone();
    }

    /**
     * A file OpenSSL wrote.
     *
     * @param name the file's name under {@code container/pkcs12/}
     * @return the file
     */
    public static byte[] openSsl(String name) throws IOException {
        try (InputStream in = Pkcs12Fixtures.class.getClassLoader().getResourceAsStream("container/pkcs12/" + name)) {
            if (in == null) {
                throw new IOException("No fixture " + name);
            }
            return in.readAllBytes();
        }
    }

    /** A reader of every format this package holds, asked in their order. */
    static ContainerReader reader() {
        return reader(new KeyNormalizer());
    }

    /** A reader as {@link #reader()} makes it, whose keys the normalizer given describes. */
    static ContainerReader reader(KeyNormalizer normalizer) {
        return new ContainerReader(List.of(new Pkcs12Format(), new PemFormat(), new DerFormat()),
                new ContainerAssembler(normalizer));
    }

    /** The file with the safes given after its own, and without its MAC, which would no longer verify. */
    static byte[] withSafes(byte[] file, ContentInfo... safes) throws IOException {
        Pfx pfx = Pfx.getInstance(file);
        ContentInfo[] own = AuthenticatedSafe
                .getInstance(ASN1OctetString.getInstance(pfx.getAuthSafe().getContent()).getOctets())
                .getContentInfo();
        ContentInfo[] all = Stream.concat(Stream.of(own), Stream.of(safes)).toArray(ContentInfo[]::new);
        return new Pfx(new ContentInfo(PKCSObjectIdentifiers.data, new DEROctetString(new AuthenticatedSafe(all))),
                null).getEncoded();
    }

    /** The file with its MAC stating the algorithm given, its MAC value, salt and iterations kept. */
    static byte[] withMacAlgorithm(byte[] file, AlgorithmIdentifier algorithm) throws IOException {
        MacData mac = Pfx.getInstance(file).getMacData();
        return withMac(file, new MacData(new DigestInfo(algorithm, mac.getMac().getDigest()), mac.getSalt(),
                mac.getIterationCount().intValueExact()));
    }

    /** The file with its MAC stating the iterations given, its MAC value and salt kept. */
    static byte[] withMacIterations(byte[] file, int iterations) throws IOException {
        MacData mac = Pfx.getInstance(file).getMacData();
        return withMac(file, new MacData(mac.getMac(), mac.getSalt(), iterations));
    }

    /**
     * A safe of the content encrypted under PBES2 with AES-256 and the password given, whatever the content is.
     *
     * @return the safe, as the authenticated safe holds it
     */
    static ContentInfo encryptedSafe(byte[] content, char[] password) throws IOException, OperatorCreationException {
        OutputEncryptor encryptor = new JcePKCSPBEOutputEncryptorBuilder(PBES2_AES_256)
                .setProvider(BC)
                .setPRF(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE))
                .setIterationCount(ITERATIONS)
                .build(password);
        ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
        try (OutputStream out = encryptor.getOutputStream(encrypted)) {
            out.write(content);
        }
        return new ContentInfo(PKCSObjectIdentifiers.encryptedData, new EncryptedData(PKCSObjectIdentifiers.data,
                encryptor.getAlgorithmIdentifier(), new DEROctetString(encrypted.toByteArray())));
    }

    /**
     * PBMAC1 parameters: PBKDF2 over the HMAC {@code prf} and the key length given, and the HMAC {@code mac}.
     *
     * @param keyLength the PBKDF2 key length in bytes, or {@code null} to leave it out
     */
    static AlgorithmIdentifier pbmac1(ASN1ObjectIdentifier prf, ASN1ObjectIdentifier mac, Integer keyLength) {
        return pbmac1(prf, mac, keyLength, ITERATIONS);
    }

    /**
     * PBMAC1 parameters over the HMACs, the key length and the PBKDF2 iterations given, encoded field by field, since
     * Bouncy Castle's parameters leave out a key length that is not positive and a PRF that is the default.
     */
    static AlgorithmIdentifier pbmac1(ASN1ObjectIdentifier prf, ASN1ObjectIdentifier mac, Integer keyLength,
            int iterations) {
        return pbmac1(prf, mac, keyLength, iterations, salt());
    }

    /**
     * The file with PBMAC1 over the HMAC given, for its PBKDF2 and its MAC alike, computed by the JDK's own PBKDF2 and
     * HMAC under the password given, the key as long as the HMAC's output.
     *
     * @param hmac an HMAC over SHA-2
     */
    static byte[] withJdkPbmac1(byte[] file, char[] password, ASN1ObjectIdentifier hmac)
            throws GeneralSecurityException, IOException {
        String name = JDK_HMACS.get(hmac);
        Mac mac = Mac.getInstance(name, SUN_JCE);
        byte[] salt = salt();
        byte[] key = SecretKeyFactory
                .getInstance("PBKDF2With" + name, SUN_JCE)
                .generateSecret(new PBEKeySpec(password, salt, ITERATIONS, mac.getMacLength() * Byte.SIZE))
                .getEncoded();
        mac.init(new SecretKeySpec(key, name));
        byte[] value = mac
                .doFinal(ASN1OctetString.getInstance(Pfx.getInstance(file).getAuthSafe().getContent()).getOctets());
        AlgorithmIdentifier algorithm = pbmac1(hmac, hmac, mac.getMacLength(), ITERATIONS, salt);
        return withMac(file, new MacData(new DigestInfo(algorithm, value), salt, 1));
    }

    /**
     * The file with its outer structures in BER of indefinite length, as writers such as NSS encode them: the PFX, the
     * content its MAC covers, and that content's octet string, cut into segments. The octets are kept, so the MAC still
     * verifies.
     */
    static byte[] withIndefiniteLengths(byte[] file) throws IOException {
        Pfx pfx = Pfx.getInstance(file);
        byte[] content = ASN1OctetString.getInstance(pfx.getAuthSafe().getContent()).getOctets();
        ASN1EncodableVector authenticatedSafe = new ASN1EncodableVector();
        authenticatedSafe.add(PKCSObjectIdentifiers.data);
        authenticatedSafe.add(new BERTaggedObject(true, 0, new BEROctetString(content, SEGMENT_BYTES)));
        ASN1EncodableVector fields = new ASN1EncodableVector();
        fields.add(new ASN1Integer(PFX_VERSION));
        fields.add(new BERSequence(authenticatedSafe));
        fields.add(pfx.getMacData());
        return new BERSequence(fields).getEncoded();
    }

    private static AlgorithmIdentifier pbmac1(ASN1ObjectIdentifier prf, ASN1ObjectIdentifier mac, Integer keyLength,
            int iterations, byte[] salt) {
        ASN1EncodableVector pbkdf2 = new ASN1EncodableVector();
        pbkdf2.add(new DEROctetString(salt));
        pbkdf2.add(new ASN1Integer(iterations));
        if (keyLength != null) {
            pbkdf2.add(new ASN1Integer(keyLength));
        }
        pbkdf2.add(new AlgorithmIdentifier(prf, DERNull.INSTANCE));
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1,
                new PBMAC1Params(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, new DERSequence(pbkdf2)),
                        new AlgorithmIdentifier(mac, DERNull.INSTANCE)));
    }

    /**
     * PBES2 with PBKDF2 over HMAC-SHA256, AES-256-CBC and the iterations given, for a protection nothing is meant to
     * decrypt.
     */
    static AlgorithmIdentifier pbes2(int iterations) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2,
                new PBES2Parameters(
                        new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2,
                                new PBKDF2Params(salt, iterations,
                                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256,
                                                DERNull.INSTANCE))),
                        new EncryptionScheme(PBES2_AES_256, new DEROctetString(new byte[SALT_BYTES]))));
    }

    private static byte[] salt() {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        return salt;
    }

    private static byte[] withMac(byte[] file, MacData mac) throws IOException {
        return new Pfx(Pfx.getInstance(file).getAuthSafe(), mac).getEncoded();
    }

    /** Builds a PKCS#12 file bag by bag; the bags keep the order they are added in. */
    public static final class Builder {

        private final PKCS12PfxPduBuilder pfx = new PKCS12PfxPduBuilder();

        private final List<PKCS12SafeBag> bags = new ArrayList<>();

        private OutputEncryptor safeEncryptor;

        private int iterations = ITERATIONS;

        private PKCS12MacCalculatorBuilder mac;

        private char[] macPassword;

        private Builder() {
        }

        /**
         * Sets the iterations of every protection and MAC made after it.
         *
         * @param iterations the key-derivation iterations
         * @return this builder
         */
        public Builder iterations(int iterations) {
            this.iterations = iterations;
            return this;
        }

        /**
         * Adds a key without protection.
         *
         * @param alias the bag's friendly name, or {@code null}
         * @param localKeyId the bag's local key identifier, or {@code null}
         * @return this builder
         */
        public Builder keyBag(PrivateKey key, String alias, byte[] localKeyId) {
            return bag(
                    named(new PKCS12SafeBagBuilder(PrivateKeyInfo.getInstance(key.getEncoded())), alias, localKeyId));
        }

        /**
         * Adds a key under PBES2 with AES-256 and the password given.
         *
         * @param alias the bag's friendly name, or {@code null}
         * @param localKeyId the bag's local key identifier, or {@code null}
         * @return this builder
         */
        public Builder shroudedKeyBag(PrivateKey key, char[] password, String alias, byte[] localKeyId)
                throws OperatorCreationException {
            return bag(named(new PKCS12SafeBagBuilder(PrivateKeyInfo.getInstance(key.getEncoded()),
                    encryptor(password, PBES2_AES_256)), alias, localKeyId));
        }

        /**
         * Adds a certificate.
         *
         * @param alias the bag's friendly name, or {@code null}
         * @param localKeyId the bag's local key identifier, or {@code null}
         * @return this builder
         */
        public Builder certBag(X509Certificate certificate, String alias, byte[] localKeyId)
                throws IOException, CertificateEncodingException {
            return certBag(new JcaX509CertificateHolder(certificate), alias, localKeyId);
        }

        /**
         * Adds a certificate.
         *
         * @param alias the bag's friendly name, or {@code null}
         * @param localKeyId the bag's local key identifier, or {@code null}
         * @return this builder
         */
        public Builder certBag(X509CertificateHolder certificate, String alias, byte[] localKeyId) throws IOException {
            return bag(named(new PKCS12SafeBagBuilder(certificate), alias, localKeyId));
        }

        /**
         * Adds an AES key as the JDK stores a secret key: in its PKCS#8 shape, under PBES2 with AES-256 and the
         * password given, or without protection when the password is {@code null}.
         *
         * @param alias the bag's friendly name, or {@code null}
         * @return this builder
         */
        public Builder secretBag(SecretKey key, char[] password, String alias)
                throws IOException, OperatorCreationException {
            PrivateKeyInfo shaped = PrivateKeyInfo
                    .getInstance(new DERSequence(new ASN1Encodable[]{
                            new ASN1Integer(0),
                            new AlgorithmIdentifier(NISTObjectIdentifiers.aes),
                            new DEROctetString(key.getEncoded())}));
            PKCS12SecretBag secret = password == null
                    ? new PKCS12SecretBagBuilder(PKCSObjectIdentifiers.keyBag, new DEROctetString(shaped.getEncoded()))
                            .build()
                    : new PKCS12SecretBagBuilder(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag,
                            new DEROctetString(new PKCS8EncryptedPrivateKeyInfoBuilder(shaped)
                                    .build(encryptor(password, PBES2_AES_256))
                                    .getEncoded()))
                            .build();
            return bag(named(new PKCS12SafeBagBuilder(secret), alias, null));
        }

        /**
         * Adds a bag as it is, of any type.
         *
         * @return this builder
         */
        public Builder bag(PKCS12SafeBag bag) {
            bags.add(bag);
            return this;
        }

        /**
         * Puts the bags added after it into one safe encrypted under the scheme and the password given.
         *
         * @param scheme a PKCS#12 scheme, or the cipher of PBES2 with PBKDF2 over HMAC-SHA256
         * @return this builder
         */
        public Builder encryptedSafe(char[] password, ASN1ObjectIdentifier scheme)
                throws IOException, OperatorCreationException {
            addSafe();
            safeEncryptor = encryptor(password, scheme);
            return this;
        }

        /**
         * Protects the file's integrity with the classic MAC: the PKCS#12 key derivation and an HMAC over the digest.
         *
         * @return this builder
         */
        public Builder mac(char[] password, ASN1ObjectIdentifier digest) throws OperatorCreationException {
            AlgorithmIdentifier algorithm = new AlgorithmIdentifier(digest, DERNull.INSTANCE);
            mac = new BcPKCS12MacCalculatorBuilder(digest(algorithm), algorithm).setIterationCount(iterations);
            macPassword = password;
            return this;
        }

        /**
         * Protects the file's integrity with PBMAC1: PBKDF2 and an HMAC, both over SHA-256.
         *
         * @return this builder
         */
        public Builder pbmac1(char[] password) throws IOException {
            return pbmac1(password, PKCSObjectIdentifiers.id_hmacWithSHA256);
        }

        /**
         * Protects the file's integrity with PBMAC1: PBKDF2 and an HMAC, both with the HMAC given.
         *
         * @return this builder
         */
        public Builder pbmac1(char[] password, ASN1ObjectIdentifier hmac) throws IOException {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            AlgorithmIdentifier hmacAlgorithm = new AlgorithmIdentifier(hmac, DERNull.INSTANCE);
            mac = new BcPKCS12PBMac1CalculatorBuilder(
                    new PBMAC1Params(
                            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2,
                                    new PBKDF2Params(salt, iterations, PBMAC1_KEY_BYTES, hmacAlgorithm)),
                            hmacAlgorithm));
            macPassword = password;
            return this;
        }

        /**
         * The file, encoded as the builders encode it.
         *
         * @return the file
         */
        public byte[] build() throws IOException, PKCSException {
            addSafe();
            return pfx.build(mac, macPassword).getEncoded();
        }

        /** Adds the bags added since the last safe as one safe, encrypted or not. */
        private void addSafe() throws IOException {
            if (bags.isEmpty()) {
                return;
            }
            if (safeEncryptor == null) {
                for (PKCS12SafeBag bag : bags) {
                    pfx.addData(bag);
                }
            } else {
                pfx.addEncryptedData(safeEncryptor, bags.toArray(PKCS12SafeBag[]::new));
            }
            bags.clear();
        }

        private OutputEncryptor encryptor(char[] password, ASN1ObjectIdentifier scheme)
                throws OperatorCreationException {
            if (PBES1_CIPHERS.containsKey(scheme)) {
                return pbes1Encryptor(password, scheme);
            }
            JcePKCSPBEOutputEncryptorBuilder encryptor = new JcePKCSPBEOutputEncryptorBuilder(scheme)
                    .setProvider(BC)
                    .setIterationCount(iterations);
            if (!scheme.on(PKCSObjectIdentifiers.pkcs_12PbeIds)) {
                encryptor.setPRF(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE));
            }
            return encryptor.build(password);
        }

        /** PBES1, which Bouncy Castle's PKCS#12 builders do not write, encrypted with the JCA cipher of the scheme. */
        private OutputEncryptor pbes1Encryptor(char[] password, ASN1ObjectIdentifier scheme)
                throws OperatorCreationException {
            byte[] salt = new byte[PBES1_SALT_BYTES];
            RANDOM.nextBytes(salt);
            AlgorithmIdentifier algorithm = new AlgorithmIdentifier(scheme, new PBEParameter(salt, iterations));
            Cipher cipher;
            try {
                String name = PBES1_CIPHERS.get(scheme);
                cipher = Cipher.getInstance(name, BC);
                cipher
                        .init(Cipher.ENCRYPT_MODE,
                                SecretKeyFactory.getInstance(name, BC).generateSecret(new PBEKeySpec(password)),
                                new PBEParameterSpec(salt, iterations));
            } catch (GeneralSecurityException e) {
                throw new OperatorCreationException("The PBES1 cipher is not available.", e);
            }
            return new OutputEncryptor() {

                @Override
                public AlgorithmIdentifier getAlgorithmIdentifier() {
                    return algorithm;
                }

                @Override
                public OutputStream getOutputStream(OutputStream encrypted) {
                    return new CipherOutputStream(encrypted, cipher);
                }

                @Override
                public GenericKey getKey() {
                    return new GenericKey(algorithm, new byte[0]);
                }
            };
        }

        /** The digest of the algorithm; Bouncy Castle's digest provider knows neither SHA-512/224 nor SHA-512/256. */
        private static ExtendedDigest digest(AlgorithmIdentifier algorithm) throws OperatorCreationException {
            if (NISTObjectIdentifiers.id_sha512_224.equals(algorithm.getAlgorithm())) {
                return new SHA512tDigest(224);
            }
            if (NISTObjectIdentifiers.id_sha512_256.equals(algorithm.getAlgorithm())) {
                return new SHA512tDigest(256);
            }
            return BcDefaultDigestProvider.INSTANCE.get(algorithm);
        }

        private static PKCS12SafeBag named(PKCS12SafeBagBuilder bag, String alias, byte[] localKeyId) {
            if (alias != null) {
                bag.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString(alias));
            }
            if (localKeyId != null) {
                bag.addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, new DEROctetString(localKeyId));
            }
            return bag.build();
        }
    }
}
