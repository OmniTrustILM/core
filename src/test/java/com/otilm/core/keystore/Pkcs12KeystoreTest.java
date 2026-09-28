package com.otilm.core.keystore;

import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.util.ExportEnvelopeFixtures;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagFactory;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilderProvider;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Pkcs12KeystoreTest {

    private static final int ITERATIONS = 100_000;
    private static final String PASSPHRASE = "keystore-test-passphrase";
    private static final byte[] MESSAGE = "the message the test key signs".getBytes(StandardCharsets.UTF_8);

    private static final AtomicLong SERIAL = new AtomicLong(1);

    private static KeyPair keyPair;
    private static KeyPair rootKeyPair;
    private static X509Certificate root;
    private static X509Certificate intermediate;
    private static X509Certificate leaf;

    @BeforeAll
    static void buildChain() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        rootKeyPair = rsaKeyPair();
        KeyPair intermediateKeyPair = rsaKeyPair();
        keyPair = rsaKeyPair();
        root = certificate("CN=Root CA", "CN=Root CA", rootKeyPair.getPublic(), rootKeyPair.getPrivate());
        intermediate = certificate("CN=Root CA", "CN=Intermediate CA", intermediateKeyPair.getPublic(),
                rootKeyPair.getPrivate());
        leaf = certificate("CN=Intermediate CA", "CN=tls.example.com", keyPair.getPublic(),
                intermediateKeyPair.getPrivate());
    }

    @Test
    void assemble_opensAsAKeyEntryWithItsChainInTheJdk() throws Exception {
        // given
        KeystoreEntry entry = entry("tls key", ITERATIONS, intermediate(), root());

        // when
        KeyStore keystore = jdkKeystore(Pkcs12Keystore.assemble(entry, passphrase()));

        // then
        String alias = keystore.aliases().nextElement();
        assertThat(alias).isEqualToIgnoringCase("tls key");
        assertThat(keystore.isKeyEntry(alias)).isTrue();
        assertThat(keystore.getCertificateChain(alias))
                .extracting(Certificate::getEncoded)
                .containsExactly(leaf().getEncoded(), intermediate().getEncoded(), root().getEncoded());
    }

    @Test
    void assemble_holdsTheKeyTheLeafCertifies() throws Exception {
        // given
        KeystoreEntry entry = entry("tls key", ITERATIONS, intermediate());
        KeyStore keystore = jdkKeystore(Pkcs12Keystore.assemble(entry, passphrase()));
        PrivateKey key = (PrivateKey) keystore.getKey("tls key", PASSPHRASE.toCharArray());

        // when
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        // then
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(leaf().getPublicKey());
        verifier.update(MESSAGE);
        assertThat(verifier.verify(signature)).isTrue();
    }

    @Test
    void assemble_wrapsTheConnectorsEnvelopeUnchanged() throws Exception {
        // given
        KeystoreEntry entry = entry("tls key", ITERATIONS);

        // when
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(Pkcs12Keystore.assemble(entry, passphrase()));

        // then
        assertThat(pfx.getContentInfos())
                .extracting(ContentInfo::getContentType)
                .containsExactly(PKCSObjectIdentifiers.encryptedData, PKCSObjectIdentifiers.data);
        SafeBag keyBag = dataBags(pfx).getFirst();
        assertThat(keyBag.getBagId()).isEqualTo(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag);
        assertThat(keyBag.getBagValue().toASN1Primitive().getEncoded(ASN1Encoding.DER))
                .isEqualTo(entry.encryptedPrivateKeyInfo());
    }

    @Test
    void assemble_protectsTheCertificatesAsTheKeyIsProtected() throws Exception {
        // given
        KeystoreEntry entry = entry("tls key", ITERATIONS, intermediate());

        // when
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(Pkcs12Keystore.assemble(entry, passphrase()));

        // then
        AlgorithmIdentifier protection = encryptedData(pfx).getEncryptionAlgorithm();
        PBES2Parameters pbes2 = PBES2Parameters.getInstance(protection.getParameters());
        PBKDF2Params pbkdf2 = PBKDF2Params.getInstance(pbes2.getKeyDerivationFunc().getParameters());
        assertThat(protection.getAlgorithm()).isEqualTo(PKCSObjectIdentifiers.id_PBES2);
        assertThat(pbkdf2.getIterationCount().intValueExact()).isEqualTo(ITERATIONS);
        assertThat(pbkdf2.getPrf().getAlgorithm()).isEqualTo(PKCSObjectIdentifiers.id_hmacWithSHA256);
        assertThat(pbkdf2.getSalt()).hasSize(16);
        assertThat(pbes2.getEncryptionScheme().getAlgorithm()).isEqualTo(NISTObjectIdentifiers.id_aes256_CBC);
    }

    @Test
    void assemble_macsTheFileWithSha256AtTheKeysIterations() throws Exception {
        // given
        KeystoreEntry entry = entry("tls key", ITERATIONS);

        // when
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(Pkcs12Keystore.assemble(entry, passphrase()));

        // then
        assertThat(pfx.getMacAlgorithmID().getAlgorithm()).isEqualTo(NISTObjectIdentifiers.id_sha256);
        assertThat(iterations(pfx)).isEqualTo(ITERATIONS);
        assertThat(pfx
                .isMacValid(new BcPKCS12MacCalculatorBuilderProvider(BcDefaultDigestProvider.INSTANCE),
                        PASSPHRASE.toCharArray()))
                .isTrue();
    }

    @Test
    void assemble_refusesAWrongPassphraseAtTheMac() throws Exception {
        // given
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(Pkcs12Keystore.assemble(entry("tls key", ITERATIONS), passphrase()));

        // when
        boolean valid = pfx
                .isMacValid(new BcPKCS12MacCalculatorBuilderProvider(BcDefaultDigestProvider.INSTANCE),
                        "a wrong passphrase".toCharArray());

        // then
        assertThat(valid).isFalse();
    }

    @Test
    void assemble_pairsOnlyTheKeyAndTheLeaf() throws Exception {
        // given
        KeystoreEntry entry = entry("tls key", ITERATIONS, intermediate());

        // when
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(Pkcs12Keystore.assemble(entry, passphrase()));

        // then
        byte[] expected = MessageDigest.getInstance("SHA-256").digest(leaf().getEncoded());
        List<SafeBag> certificates = certificateBags(pfx, PASSPHRASE);
        assertThat(localKeyId(dataBags(pfx).getFirst())).isEqualTo(expected);
        assertThat(localKeyId(certificates.get(0))).isEqualTo(expected);
        assertThat(localKeyId(certificates.get(1))).isNull();
    }

    @Test
    void assemble_namesIssuersUniquely() throws Exception {
        // given two issuers with the same common name
        KeystoreEntry entry = entry("tls key", ITERATIONS, issuer("CN=Issuing CA,O=One"),
                issuer("CN=Issuing CA,O=Two"));

        // when
        List<SafeBag> certificates = certificateBags(new PKCS12PfxPdu(Pkcs12Keystore.assemble(entry, passphrase())),
                PASSPHRASE);

        // then
        assertThat(certificates)
                .extracting(Pkcs12KeystoreTest::friendlyName)
                .containsExactly("tls key", "Issuing CA", "Issuing CA (2)");
    }

    @Test
    void assemble_namesAnIssuerWithoutACommonNameByItsDn() throws Exception {
        // given
        KeystoreEntry entry = entry("tls key", ITERATIONS, issuer("O=Example,C=CZ"));

        // when
        List<SafeBag> certificates = certificateBags(new PKCS12PfxPdu(Pkcs12Keystore.assemble(entry, passphrase())),
                PASSPHRASE);

        // then
        assertThat(friendlyName(certificates.get(1))).isEqualTo("O=Example,C=CZ");
    }

    @Test
    void assemble_namesTheCommonNameOfAMultiValuedRdn() throws Exception {
        // given a multi-valued RDN whose common name is not its first attribute
        KeystoreEntry entry = entry("tls key", ITERATIONS, issuer("O=One+CN=Issuing CA"));

        // when
        List<SafeBag> certificates = certificateBags(new PKCS12PfxPdu(Pkcs12Keystore.assemble(entry, passphrase())),
                PASSPHRASE);

        // then
        assertThat(friendlyName(certificates.get(1))).isEqualTo("Issuing CA");
    }

    @Test
    void assemble_namesAnIssuerThatReusesTheKeysName() throws Exception {
        // given
        KeystoreEntry entry = entry("Issuing CA", ITERATIONS, issuer("CN=Issuing CA"));

        // when
        List<SafeBag> certificates = certificateBags(new PKCS12PfxPdu(Pkcs12Keystore.assemble(entry, passphrase())),
                PASSPHRASE);

        // then
        assertThat(certificates)
                .extracting(Pkcs12KeystoreTest::friendlyName)
                .containsExactly("Issuing CA", "Issuing CA (2)");
    }

    @Test
    void assemble_namesAnIssuerThatReusesASuffixedName() throws Exception {
        // given two issuers named "CA" and a third named as the second one is suffixed
        KeystoreEntry entry = entry("tls key", ITERATIONS, issuer("CN=CA,O=One"), issuer("CN=CA,O=Two"),
                issuer("CN=CA (2)"));

        // when
        List<SafeBag> certificates = certificateBags(new PKCS12PfxPdu(Pkcs12Keystore.assemble(entry, passphrase())),
                PASSPHRASE);

        // then
        assertThat(certificates).extracting(Pkcs12KeystoreTest::friendlyName).doesNotHaveDuplicates();
    }

    @Test
    void assemble_namesIssuersApartFromASuffixedKeyName() throws Exception {
        // given a key named as the second of two issuers named "CA" is suffixed
        KeystoreEntry entry = entry("CA (2)", ITERATIONS, issuer("CN=CA,O=One"), issuer("CN=CA,O=Two"));

        // when
        List<SafeBag> certificates = certificateBags(new PKCS12PfxPdu(Pkcs12Keystore.assemble(entry, passphrase())),
                PASSPHRASE);

        // then
        assertThat(certificates).extracting(Pkcs12KeystoreTest::friendlyName).doesNotHaveDuplicates();
    }

    @Test
    void assemble_namesIssuersUniquelyIgnoringCase() throws Exception {
        // given two issuers whose common names differ only in case
        KeystoreEntry entry = entry("tls key", ITERATIONS, issuer("CN=CA,O=One"), issuer("CN=ca,O=Two"));

        // when
        List<SafeBag> certificates = certificateBags(new PKCS12PfxPdu(Pkcs12Keystore.assemble(entry, passphrase())),
                PASSPHRASE);

        // then
        assertThat(friendlyName(certificates.get(1))).isNotEqualToIgnoringCase(friendlyName(certificates.get(2)));
    }

    /** A malformed envelope is a server fault, not the IllegalArgumentException the advice answers with 400. */
    @Test
    void assemble_failsOnAMalformedEnvelopeAsAServerFault() throws Exception {
        // given an envelope cut short by one byte
        byte[] envelope = ExportEnvelopeFixtures.envelope(keyPair.getPrivate(), PASSPHRASE.toCharArray(), ITERATIONS);
        KeystoreEntry entry = new KeystoreEntry("tls key", Arrays.copyOf(envelope, envelope.length - 1),
                leaf().getEncoded(), List.of());
        Passphrase passphrase = passphrase();

        // when
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> Pkcs12Keystore.assemble(entry, passphrase));

        // then
        assertThat(failure).hasCauseInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void assemble_takesAHighIterationCountFromTheKey() throws Exception {
        // given
        KeystoreEntry entry = entry("tls key", 600_000);

        // when
        byte[] file = Pkcs12Keystore.assemble(entry, passphrase());

        // then
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(file);
        assertThat(iterations(pfx)).isEqualTo(600_000);
        assertThat(certificateSafeIterations(pfx)).isEqualTo(600_000);
        assertThat(jdkKeystore(file).isKeyEntry("tls key")).isTrue();
    }

    @Test
    void assemble_keepsANonAsciiKeyName() throws Exception {
        // given
        KeystoreEntry entry = entry("Klíč für TLS", ITERATIONS);

        // when
        KeyStore keystore = jdkKeystore(Pkcs12Keystore.assemble(entry, passphrase()));

        // then
        assertThat(keystore.aliases().nextElement()).isEqualToIgnoringCase("Klíč für TLS");
    }

    private static X509Certificate root() {
        return root;
    }

    private static X509Certificate intermediate() {
        return intermediate;
    }

    private static X509Certificate leaf() {
        return leaf;
    }

    private static Passphrase passphrase() {
        return new Passphrase(PASSPHRASE.toCharArray());
    }

    private static KeystoreEntry entry(String name, int iterations, X509Certificate... issuers) throws Exception {
        byte[] envelope = ExportEnvelopeFixtures.envelope(keyPair.getPrivate(), PASSPHRASE.toCharArray(), iterations);
        List<byte[]> issuerDer = new ArrayList<>();
        for (X509Certificate issuer : issuers) {
            issuerDer.add(issuer.getEncoded());
        }
        return new KeystoreEntry(name, envelope, leaf().getEncoded(), issuerDer);
    }

    /**
     * A certificate with that subject, signed by the root and carrying no basicConstraints; the leaf's issuer is always
     * the intermediate, never this certificate.
     */
    private static X509Certificate issuer(String dn) throws Exception {
        return certificate("CN=Root CA", dn, rsaKeyPair().getPublic(), rootKeyPair.getPrivate());
    }

    private static KeyStore jdkKeystore(byte[] file) throws Exception {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new ByteArrayInputStream(file), PASSPHRASE.toCharArray());
        return keystore;
    }

    /** The SafeBags of the file's unencrypted `data` content info: the key bag. */
    private static List<SafeBag> dataBags(PKCS12PfxPdu pfx) {
        ASN1OctetString content = ASN1OctetString.getInstance(contentOf(pfx, PKCSObjectIdentifiers.data));
        List<SafeBag> bags = new ArrayList<>();
        for (ASN1Encodable bag : ASN1Sequence.getInstance(content.getOctets())) {
            bags.add(SafeBag.getInstance(bag));
        }
        return bags;
    }

    /** The file's `encryptedData` content info: the certificate safe. */
    private static EncryptedData encryptedData(PKCS12PfxPdu pfx) {
        return EncryptedData.getInstance(contentOf(pfx, PKCSObjectIdentifiers.encryptedData));
    }

    private static ASN1Encodable contentOf(PKCS12PfxPdu pfx, ASN1ObjectIdentifier contentType) {
        for (ContentInfo info : pfx.getContentInfos()) {
            if (info.getContentType().equals(contentType)) {
                return info.getContent();
            }
        }
        throw new IllegalStateException("The file has no " + contentType + " content info.");
    }

    /** The MAC's PKCS#12 iteration count, read from the file's ASN.1 structure. */
    private static int iterations(PKCS12PfxPdu pfx) {
        return pfx.toASN1Structure().getMacData().getIterationCount().intValueExact();
    }

    /** The certificate safe's own PBKDF2 iteration count, independent of the MAC's. */
    private static int certificateSafeIterations(PKCS12PfxPdu pfx) {
        PBES2Parameters pbes2 = PBES2Parameters
                .getInstance(encryptedData(pfx).getEncryptionAlgorithm().getParameters());
        return PBKDF2Params
                .getInstance(pbes2.getKeyDerivationFunc().getParameters())
                .getIterationCount()
                .intValueExact();
    }

    /** The certificate safe's bags, decrypted under the passphrase. */
    private static List<SafeBag> certificateBags(PKCS12PfxPdu pfx, String passphrase) throws Exception {
        for (ContentInfo info : pfx.getContentInfos()) {
            if (info.getContentType().equals(PKCSObjectIdentifiers.encryptedData)) {
                PKCS12SafeBagFactory factory = new PKCS12SafeBagFactory(info,
                        new JcePKCSPBEInputDecryptorProviderBuilder()
                                .setProvider("BC")
                                .build(passphrase.toCharArray()));
                List<SafeBag> bags = new ArrayList<>();
                for (PKCS12SafeBag bag : factory.getSafeBags()) {
                    bags.add(bag.toASN1Structure());
                }
                return bags;
            }
        }
        throw new IllegalStateException("The file has no encryptedData content info.");
    }

    private static byte[] localKeyId(SafeBag bag) {
        return attribute(bag, PKCSObjectIdentifiers.pkcs_9_at_localKeyId)
                .map(value -> DEROctetString.getInstance(value).getOctets())
                .orElse(null);
    }

    private static String friendlyName(SafeBag bag) {
        return attribute(bag, PKCSObjectIdentifiers.pkcs_9_at_friendlyName)
                .map(value -> DERBMPString.getInstance(value).getString())
                .orElse(null);
    }

    private static Optional<ASN1Encodable> attribute(SafeBag bag, ASN1ObjectIdentifier type) {
        if (bag.getBagAttributes() == null) {
            return Optional.empty();
        }
        for (ASN1Encodable element : bag.getBagAttributes()) {
            Attribute attribute = Attribute.getInstance(element);
            if (attribute.getAttrType().equals(type)) {
                return Optional.of(attribute.getAttrValues().getObjectAt(0));
            }
        }
        return Optional.empty();
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(String issuerDn, String subjectDn, PublicKey publicKey,
            PrivateKey signerKey) throws Exception {
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name(issuerDn),
                BigInteger.valueOf(SERIAL.getAndIncrement()), notBefore, notAfter, new X500Name(subjectDn), publicKey);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signerKey);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }
}
