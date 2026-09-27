package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.material.EncryptedKeyMaterialV2Dto;
import com.otilm.api.model.core.secret.Passphrase;
import jakarta.validation.Validation;
import jakarta.validation.ValidatorFactory;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.stream.Stream;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.ScryptParams;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class KeyNormalizerTest {

    private static final KeyNormalizer NORMALIZER = new KeyNormalizer();

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static KeyPair rsa;

    private static KeyPair ec;

    @BeforeAll
    static void keys() throws GeneralSecurityException {
        KeyFiles.registerProviders();
        rsa = KeyFiles.rsa();
        ec = KeyFiles.ec();
    }

    @ParameterizedTest
    @MethodSource("acceptedFiles")
    void normalize_protectsTheKeyOfEveryAcceptedFileForTheConnector(byte[] file, KeyPair keyPair) throws Exception {
        // when
        NormalizedKey key = NORMALIZER.normalize(file, KeyFiles.passphrase(), KeyRequestType.KEY_PAIR);

        // then
        assertThat(key.subjectPublicKeyInfo()).isEqualTo(keyPair.getPublic().getEncoded());
        assertThat(KeyFiles.opened(key)).isEqualTo(keyPair.getPrivate().getEncoded());
    }

    @ParameterizedTest
    @MethodSource("platformKeys")
    void normalize_namesTheAlgorithmOfEveryPlatformKey(KeyPair keyPair, KeyAlgorithm algorithm) throws Exception {
        // when
        NormalizedKey key = NORMALIZER.normalize(KeyFiles.pkcs8(keyPair), null, KeyRequestType.KEY_PAIR);

        // then
        assertThat(key.algorithm()).isEqualTo(algorithm);
        assertThat(key.subjectPublicKeyInfo()).isEqualTo(keyPair.getPublic().getEncoded());
        assertThat(KeyFiles.opened(key)).isEqualTo(keyPair.getPrivate().getEncoded());
    }

    @Test
    void normalize_opensAFileWithoutProtectionWithoutAPassphrase() {
        // when
        NormalizedKey key = NORMALIZER.normalize(KeyFiles.pkcs8(ec), null, KeyRequestType.KEY_PAIR);

        // then
        assertThat(key.subjectPublicKeyInfo()).isEqualTo(ec.getPublic().getEncoded());
    }

    @Test
    void normalize_protectsTheKeyInThePinnedProfileWithTheRecommendedIterations() {
        // when
        NormalizedKey key = NORMALIZER.normalize(KeyFiles.pkcs8(ec), null, KeyRequestType.KEY_PAIR);

        // then
        EncryptedKeyMaterialV2Dto material = new EncryptedKeyMaterialV2Dto();
        material.setEncryptedPrivateKeyInfo(key.encryptedPrivateKeyInfo());
        try (ValidatorFactory validators = Validation.buildDefaultValidatorFactory()) {
            assertThat(validators.getValidator().validate(material)).isEmpty();
        }
        PBES2Parameters protection = PBES2Parameters
                .getInstance(EncryptedPrivateKeyInfo
                        .getInstance(key.encryptedPrivateKeyInfo())
                        .getEncryptionAlgorithm()
                        .getParameters());
        assertThat(PBKDF2Params.getInstance(protection.getKeyDerivationFunc().getParameters()).getIterationCount())
                .isEqualTo(BigInteger.valueOf(600_000));
    }

    @Test
    void normalize_generatesAFreshTransportPassphraseForEveryKey() {
        // when
        NormalizedKey first = NORMALIZER.normalize(KeyFiles.pkcs8(ec), null, KeyRequestType.KEY_PAIR);
        NormalizedKey second = NORMALIZER.normalize(KeyFiles.pkcs8(ec), null, KeyRequestType.KEY_PAIR);

        // then
        assertThat(new String(first.transportPassphrase().characters())).matches("[A-Za-z0-9_-]{43}");
        assertThat(first.transportPassphrase()).isNotEqualTo(second.transportPassphrase());
    }

    @ParameterizedTest
    @MethodSource("protectedFiles")
    void normalize_refusesAWrongPassphraseTheSameWayInEveryScheme(byte[] file) {
        // given
        Passphrase wrong = new Passphrase("not the passphrase".toCharArray());

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.normalize(file, wrong, KeyRequestType.KEY_PAIR));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @ParameterizedTest
    @MethodSource("missingPassphrases")
    void normalize_refusesAProtectedFileWithoutItsPassphrase(Passphrase passphrase) throws Exception {
        // given
        byte[] file = KeyFiles.encrypted(ec, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA256);

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.normalize(file, passphrase, KeyRequestType.KEY_PAIR));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void normalize_refusesDamagedCipherTextAsUnreadable() throws Exception {
        // given
        byte[] file = KeyFiles.encrypted(ec, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA256);
        file[file.length - 1] ^= 0x01;
        Passphrase passphrase = KeyFiles.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.normalize(file, passphrase, KeyRequestType.KEY_PAIR));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void normalize_refusesDecryptedContentNestedTooDeeplyAsUnreadable() throws Exception {
        // given
        byte[] file = KeyFiles.encryptedContent(KeyFiles.nested(KeyFileReader.MAXIMUM_NESTING_DEPTH + 1));
        Passphrase passphrase = KeyFiles.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.normalize(file, passphrase, KeyRequestType.KEY_PAIR));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void normalize_opensAPbes2FileUnderAPassphraseThatIsNotAscii() throws Exception {
        // given
        char[] passphrase = "pässwörd 漢字".toCharArray();
        byte[] file = KeyFiles.encrypted(ec, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA256, passphrase);

        // when
        NormalizedKey key = NORMALIZER.normalize(file, new Passphrase(passphrase), KeyRequestType.KEY_PAIR);

        // then
        assertThat(key.subjectPublicKeyInfo()).isEqualTo(ec.getPublic().getEncoded());
    }

    @Test
    void normalize_refusesToImportAKeyFileAsASecretKey() {
        // given
        byte[] file = KeyFiles.pkcs8(ec);

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.normalize(file, null, KeyRequestType.SECRET));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.NOT_OF_TYPE.formatted("secret key"));
    }

    @ParameterizedTest
    @MethodSource("costlyProtections")
    @Timeout(5)
    void normalize_refusesCostlyProtectionBeforeDerivingAnyKey(byte[] file, String limit) {
        // given
        Passphrase passphrase = KeyFiles.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.normalize(file, passphrase, KeyRequestType.KEY_PAIR));

        // then
        assertThat(refusal.getMessage()).isEqualTo(limit);
    }

    @ParameterizedTest
    @ValueSource(strings = {"correct horse", "p\u00e4ssw\u00f6rd"})
    void normalize_opensAPbes1FileAsOpenSslWritesIt(String passphrase) throws Exception {
        // given
        byte[] file = KeyFiles.opensslPbes1(ec, passphrase.toCharArray());

        // when
        NormalizedKey key = NORMALIZER
                .normalize(file, new Passphrase(passphrase.toCharArray()), KeyRequestType.KEY_PAIR);

        // then
        assertThat(key.subjectPublicKeyInfo()).isEqualTo(ec.getPublic().getEncoded());
    }

    @Test
    void normalize_refusesAKeyTooLargeForItsEnvelope() throws Exception {
        // given
        byte[] file = oversized().getEncoded();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.normalize(file, null, KeyRequestType.KEY_PAIR));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo(KeyFileRefusal.LIMIT_EXCEEDED.formatted("protected key size", "65536 bytes"));
    }

    @ParameterizedTest
    @MethodSource("refusalsBehindAPassphrase")
    void normalize_namesNothingThatOnlyTheRightPassphraseReveals(byte[] file) {
        // given
        Passphrase passphrase = KeyFiles.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.normalize(file, passphrase, KeyRequestType.KEY_PAIR));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void clear_overwritesTheEnvelopeAndTheTransportPassphrase() {
        // given
        NormalizedKey key = NORMALIZER.normalize(KeyFiles.pkcs8(ec), null, KeyRequestType.KEY_PAIR);

        // when
        key.clear();

        // then
        assertThat(key.encryptedPrivateKeyInfo()).containsOnly((byte) 0);
        assertThat(key.transportPassphrase().characters()).isEmpty();
    }

    static Stream<Arguments> acceptedFiles() throws Exception {
        byte[] pbes2 = KeyFiles.encrypted(ec, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA256);
        return Stream
                .of(arguments(named("PKCS#8 as DER", KeyFiles.pkcs8(ec)), ec),
                        arguments(named("PKCS#8 as PEM", KeyFiles.pem("PRIVATE KEY", KeyFiles.pkcs8(ec))), ec),
                        arguments(named("traditional RSA", KeyFiles.traditional(rsa, null)), rsa),
                        arguments(named("traditional EC", KeyFiles.traditional(ec, null)), ec),
                        arguments(named("PBES2 HMAC-SHA224",
                                KeyFiles.encrypted(ec, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA224)), ec),
                        arguments(named("PBES2 HMAC-SHA256", pbes2), ec),
                        arguments(named("PBES2 HMAC-SHA384",
                                KeyFiles.encrypted(ec, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA384)), ec),
                        arguments(named("PBES2 HMAC-SHA512",
                                KeyFiles.encrypted(ec, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA512)), ec),
                        arguments(named("PBES2 AES-128-CBC",
                                KeyFiles.encrypted(ec, PKCS8Generator.AES_128_CBC, PKCS8Generator.PRF_HMACSHA256)), ec),
                        arguments(named("PBES2 AES-192-CBC",
                                KeyFiles.encrypted(ec, PKCS8Generator.AES_192_CBC, PKCS8Generator.PRF_HMACSHA256)), ec),
                        arguments(
                                named("PBES2 DES-EDE3-CBC",
                                        KeyFiles.encrypted(ec, PKCS8Generator.DES3_CBC, PKCS8Generator.PRF_HMACSHA256)),
                                ec),
                        arguments(named("PBES2 with scrypt", KeyFiles.scrypt(ec)), ec),
                        arguments(named("PBES2 as PEM", KeyFiles.pem("ENCRYPTED PRIVATE KEY", pbes2)), ec),
                        arguments(
                                named("PBES1 MD2 and DES", KeyFiles
                                        .pbes1(ec, "PBEWithMD2AndDES", PKCSObjectIdentifiers.pbeWithMD2AndDES_CBC)),
                                ec),
                        arguments(
                                named("PBES1 MD5 and DES", KeyFiles
                                        .pbes1(ec, "PBEWithMD5AndDES", PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC)),
                                ec),
                        arguments(
                                named("PBES1 SHA1 and DES", KeyFiles
                                        .pbes1(ec, "PBEWithSHA1AndDES", PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC)),
                                ec),
                        arguments(
                                named("PBES1 MD5 and RC2", KeyFiles
                                        .pbes1(ec, "PBEWithMD5AndRC2", PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC)),
                                ec),
                        arguments(
                                named("PBES1 SHA1 and RC2", KeyFiles
                                        .pbes1(ec, "PBEWithSHA1AndRC2", PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC)),
                                ec),
                        arguments(named("PKCS#12 128-bit RC4",
                                KeyFiles.encrypted(ec, PKCS8Generator.PBE_SHA1_RC4_128, null)), ec),
                        arguments(named("PKCS#12 40-bit RC4",
                                KeyFiles.encrypted(ec, PKCS8Generator.PBE_SHA1_RC4_40, null)), ec),
                        arguments(named("PKCS#12 three-key triple DES",
                                KeyFiles.encrypted(ec, PKCS8Generator.PBE_SHA1_3DES, null)), ec),
                        arguments(named("PKCS#12 two-key triple DES",
                                KeyFiles.encrypted(ec, PKCS8Generator.PBE_SHA1_2DES, null)), ec),
                        arguments(named("PKCS#12 128-bit RC2",
                                KeyFiles.encrypted(ec, PKCS8Generator.PBE_SHA1_RC2_128, null)), ec),
                        arguments(named("PKCS#12 40-bit RC2",
                                KeyFiles.encrypted(ec, PKCS8Generator.PBE_SHA1_RC2_40, null)), ec),
                        arguments(named("traditional AES-128-CBC", KeyFiles.traditional(rsa, "AES-128-CBC")), rsa),
                        arguments(named("traditional AES-192-CBC", KeyFiles.traditional(rsa, "AES-192-CBC")), rsa),
                        arguments(named("traditional AES-256-CBC", KeyFiles.traditional(rsa, "AES-256-CBC")), rsa),
                        arguments(named("traditional DES-EDE3-CBC", KeyFiles.traditional(rsa, "DES-EDE3-CBC")), rsa),
                        arguments(named("traditional DES-CBC", KeyFiles.traditional(rsa, "DES-CBC")), rsa),
                        arguments(named("traditional EC AES-256-CBC", KeyFiles.traditional(ec, "AES-256-CBC")), ec));
    }

    static Stream<Arguments> platformKeys() throws Exception {
        return Stream
                .of(arguments(named("RSA", rsa), KeyAlgorithm.RSA), arguments(named("EC", ec), KeyAlgorithm.ECDSA),
                        arguments(named("ML-DSA-44", KeyFiles.keyPair("ML-DSA", MLDSAParameterSpec.ml_dsa_44, BC)),
                                KeyAlgorithm.MLDSA),
                        arguments(
                                named("SLH-DSA-SHA2-128F",
                                        KeyFiles.keyPair("SLH-DSA", SLHDSAParameterSpec.slh_dsa_sha2_128f, BC)),
                                KeyAlgorithm.SLHDSA),
                        arguments(named("ML-KEM-512", KeyFiles.keyPair("ML-KEM", MLKEMParameterSpec.ml_kem_512, BC)),
                                KeyAlgorithm.MLKEM),
                        arguments(named("Falcon-512",
                                KeyFiles
                                        .keyPair("FALCON", FalconParameterSpec.falcon_512,
                                                BouncyCastlePQCProvider.PROVIDER_NAME)),
                                KeyAlgorithm.FALCON));
    }

    static Stream<Named<byte[]>> protectedFiles() throws Exception {
        return Stream
                .of(named("PBES2", KeyFiles.encrypted(ec, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA256)),
                        named("PBES2 with scrypt", KeyFiles.scrypt(ec)),
                        named("PBES1",
                                KeyFiles.pbes1(ec, "PBEWithMD5AndDES", PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC)),
                        named("PKCS#12 with a stream cipher",
                                KeyFiles.encrypted(ec, PKCS8Generator.PBE_SHA1_RC4_128, null)),
                        named("PKCS#12 with a block cipher",
                                KeyFiles.encrypted(ec, PKCS8Generator.PBE_SHA1_3DES, null)),
                        named("traditional PEM", KeyFiles.traditional(rsa, "AES-256-CBC")));
    }

    static Stream<Named<Passphrase>> missingPassphrases() {
        return Stream.of(named("none", null), named("an empty one", new Passphrase(new char[0])));
    }

    static Stream<Arguments> costlyProtections() throws Exception {
        EncryptionScheme aes = new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CBC,
                new DEROctetString(new byte[16]));
        KeyDerivationFunc pbkdf2 = new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2,
                new PBKDF2Params(new byte[16], Integer.MAX_VALUE, PKCS8Generator.PRF_HMACSHA256));
        KeyDerivationFunc scrypt = new KeyDerivationFunc(MiscObjectIdentifiers.id_scrypt,
                new ScryptParams(new byte[16], 1 << 30, 8, 1, 32));
        return Stream
                .of(arguments(
                        named("PBKDF2 with 2^31 - 1 iterations", KeyFiles.envelope(pbes2(pbkdf2, aes), new byte[32])),
                        KeyFileRefusal.LIMIT_EXCEEDED.formatted("key derivation iteration", 10_000_000)),
                        arguments(
                                named("scrypt asking for a terabyte",
                                        KeyFiles.envelope(pbes2(scrypt, aes), new byte[32])),
                                KeyFileRefusal.LIMIT_EXCEEDED.formatted("scrypt memory", "32 MiB")));
    }

    static Stream<Named<byte[]>> refusalsBehindAPassphrase() throws Exception {
        AlgorithmIdentifier rsaEncryption = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption,
                DERNull.INSTANCE);
        return Stream
                .of(named("a key of an algorithm the platform does not hold",
                        KeyFiles
                                .encrypted(KeyFiles.keyPair("Ed25519", null, BC), PKCS8Generator.AES_256_CBC,
                                        PKCS8Generator.PRF_HMACSHA256)),
                        named("a key whose payload nests too deeply",
                                KeyFiles
                                        .encryptedContent(KeyFiles
                                                .privateKeyInfo(rsaEncryption,
                                                        KeyFiles.nested(KeyFileReader.MAXIMUM_NESTING_DEPTH + 1))
                                                .getEncoded())),
                        named("a key too large for its envelope", KeyFiles.encryptedContent(oversized().getEncoded())));
    }

    /** An EC key carrying an attribute too large for the envelope a connector accepts. */
    private static PrivateKeyInfo oversized() throws IOException {
        PrivateKeyInfo key = PrivateKeyInfo.getInstance(KeyFiles.pkcs8(ec));
        return new PrivateKeyInfo(key.getPrivateKeyAlgorithm(), key.parsePrivateKey(),
                new DERSet(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                        new DERSet(new DEROctetString(new byte[70_000])))));
    }

    private static AlgorithmIdentifier pbes2(KeyDerivationFunc derivation, EncryptionScheme encryption) {
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, new PBES2Parameters(derivation, encryption));
    }
}
