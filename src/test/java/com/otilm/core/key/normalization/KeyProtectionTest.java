package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import java.math.BigInteger;
import java.time.Duration;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.ScryptParams;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class KeyProtectionTest {

    private static final String ITERATION_LIMIT = KeyFileRefusal.LIMIT_EXCEEDED
            .formatted("key derivation iteration", 10_000_000);

    private static final String SCRYPT_MEMORY_LIMIT = KeyFileRefusal.LIMIT_EXCEEDED
            .formatted("scrypt memory", "32 MiB");

    private static final String SCRYPT_PARALLELIZATION_LIMIT = KeyFileRefusal.LIMIT_EXCEEDED
            .formatted("scrypt parallelization", 1);

    private static final ASN1ObjectIdentifier SHA256 = PKCSObjectIdentifiers.id_hmacWithSHA256;

    private static final ASN1ObjectIdentifier AES256 = NISTObjectIdentifiers.id_aes256_CBC;

    @ParameterizedTest
    @MethodSource("acceptedProtections")
    void requireAccepted_acceptsEveryProtectionInTheSet(AlgorithmIdentifier protection) {
        // when, then
        assertThatCode(() -> KeyProtection.requireAccepted(protection, DerivationBudget.forFile()))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @MethodSource("unsupportedProtections")
    void requireAccepted_namesThePartThatIsNotSupported(AlgorithmIdentifier protection, String named) {
        // given
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> KeyProtection.requireAccepted(protection, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNSUPPORTED_PROTECTION.formatted(named));
    }

    @ParameterizedTest
    @MethodSource("protectionsOverTheirCeiling")
    void requireAccepted_refusesWorkOverTheCeiling(AlgorithmIdentifier protection, String limit) {
        // given
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> KeyProtection.requireAccepted(protection, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(limit);
    }

    /**
     * scrypt parameters of a million bytes each, of either sign, would make the check itself costly were they
     * multiplied first; one below 1 makes the protection damaged.
     */
    @ParameterizedTest
    @MethodSource("attackerSizedScrypt")
    void requireAccepted_refusesScryptParametersOutOfBoundsBeforeMultiplyingThem(AlgorithmIdentifier protection,
            String refused) {
        // given
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertTimeoutPreemptively(Duration.ofMillis(100),
                () -> assertThrows(ValidationException.class, () -> KeyProtection.requireAccepted(protection, budget)));

        // then
        assertThat(refusal.getMessage()).isEqualTo(refused);
    }

    @ParameterizedTest
    @MethodSource("chargedProtections")
    void requireAccepted_chargesTheKeyDerivationToTheFilesBudget(AlgorithmIdentifier protection, int iterations) {
        // given
        DerivationBudget budget = DerivationBudget.forFile();
        BigInteger rest = BigInteger.valueOf(DerivationBudget.FILE_ITERATIONS - iterations);

        // when
        KeyProtection.requireAccepted(protection, budget);

        // then
        assertThatCode(() -> budget.charge(rest)).doesNotThrowAnyException();
        assertThrows(ValidationException.class, () -> budget.charge(BigInteger.ONE));
    }

    @ParameterizedTest
    @MethodSource("damagedProtections")
    void requireAccepted_refusesParametersItCannotRead(AlgorithmIdentifier protection) {
        // given
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> KeyProtection.requireAccepted(protection, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "DES-EDE3-CBC", "DES-CBC"})
    void requireAcceptedCipher_acceptsTheCiphersOpenSslOffers(String cipher) {
        // when, then
        assertThatCode(() -> KeyProtection.requireAcceptedCipher(cipher)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @CsvSource({
            "BF-CBC, BF-CBC",
            "AES-256-CFB, AES-256-CFB",
            "AES 256, an unrecognized cipher",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx, an unrecognized cipher"})
    void requireAcceptedCipher_namesACipherItDoesNotAcceptWhenTheNameIsPlain(String cipher, String named) {
        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> KeyProtection.requireAcceptedCipher(cipher));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNSUPPORTED_PROTECTION.formatted(named));
    }

    static Stream<Named<AlgorithmIdentifier>> acceptedProtections() {
        return Stream
                .of(named("PBES2 HMAC-SHA224", pbes2(PKCSObjectIdentifiers.id_hmacWithSHA224, 2048, AES256)),
                        named("PBES2 HMAC-SHA256", pbes2(SHA256, 2048, AES256)),
                        named("PBES2 HMAC-SHA384", pbes2(PKCSObjectIdentifiers.id_hmacWithSHA384, 2048, AES256)),
                        named("PBES2 HMAC-SHA512", pbes2(PKCSObjectIdentifiers.id_hmacWithSHA512, 2048, AES256)),
                        named("PBES2 AES-128-CBC", pbes2(SHA256, 2048, NISTObjectIdentifiers.id_aes128_CBC)),
                        named("PBES2 AES-192-CBC", pbes2(SHA256, 2048, NISTObjectIdentifiers.id_aes192_CBC)),
                        named("PBES2 DES-EDE3-CBC", pbes2(SHA256, 2048, PKCSObjectIdentifiers.des_EDE3_CBC)),
                        named("PBES2 at the iteration ceiling", pbes2(SHA256, 10_000_000, AES256)),
                        named("scrypt at the memory ceiling", scrypt(1 << 15, 8, 1)),
                        named("scrypt at the memory ceiling with a block size of 1", scrypt(1 << 18, 1, 1)),
                        named("PBES1 MD2 and DES", pbes1(PKCSObjectIdentifiers.pbeWithMD2AndDES_CBC, 2048)),
                        named("PBES1 MD5 and DES", pbes1(PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC, 10_000_000)),
                        named("PBES1 SHA1 and DES", pbes1(PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC, 2048)),
                        named("PBES1 MD5 and RC2", pbes1(PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC, 2048)),
                        named("PBES1 SHA1 and RC2", pbes1(PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC, 2048)),
                        named("PKCS#12 128-bit RC4", pkcs12(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4, 2048)),
                        named("PKCS#12 40-bit RC4", pkcs12(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC4, 2048)),
                        named("PKCS#12 three-key triple DES",
                                pkcs12(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, 10_000_000)),
                        named("PKCS#12 two-key triple DES",
                                pkcs12(PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC, 2048)),
                        named("PKCS#12 128-bit RC2", pkcs12(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC, 2048)),
                        named("PKCS#12 40-bit RC2", pkcs12(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC, 2048)));
    }

    static Stream<Arguments> unsupportedProtections() {
        return Stream
                .of(arguments(named("PBES2 without a PRF, which is HMAC-SHA1",
                        pbes2(new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2,
                                new PBKDF2Params(new byte[16], 2048)), AES256)),
                        "1.2.840.113549.2.7"),
                        arguments(
                                named("PBES2 HMAC-SHA512/224",
                                        pbes2(PKCSObjectIdentifiers.id_hmacWithSHA512_224, 2048, AES256)),
                                "1.2.840.113549.2.12"),
                        arguments(
                                named("PBES2 HMAC-SHA3-256",
                                        pbes2(NISTObjectIdentifiers.id_hmacWithSHA3_256, 2048, AES256)),
                                "2.16.840.1.101.3.4.2.14"),
                        arguments(named("PBES2 AES-256-GCM", pbes2(SHA256, 2048, NISTObjectIdentifiers.id_aes256_GCM)),
                                "2.16.840.1.101.3.4.1.46"),
                        arguments(named("PBES2 with an unknown key derivation",
                                pbes2(new KeyDerivationFunc(new ASN1ObjectIdentifier("1.2.3.4"), DERNull.INSTANCE),
                                        AES256)),
                                "1.2.3.4"),
                        arguments(named("PBES1 MD2 and RC2", pbes1(PKCSObjectIdentifiers.pbeWithMD2AndRC2_CBC, 2048)),
                                "1.2.840.113549.1.5.4"),
                        arguments(named("an unknown scheme",
                                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.5"))), "1.2.3.5"),
                        arguments(
                                named("an unknown scheme named in 64 characters, as many as a refusal repeats",
                                        new AlgorithmIdentifier(KeyFiles.identifierOfLength(64))),
                                KeyFiles.identifierOfLength(64).getId()),
                        arguments(
                                named("an unknown scheme named in 65 characters",
                                        new AlgorithmIdentifier(KeyFiles.identifierOfLength(65))),
                                "an unrecognized scheme"),
                        arguments(
                                named("PBES2 with a PRF named in 65 characters",
                                        pbes2(KeyFiles.identifierOfLength(65), 2048, AES256)),
                                "an unrecognized scheme"));
    }

    static Stream<Arguments> protectionsOverTheirCeiling() {
        return Stream
                .of(arguments(named("PBES2", pbes2(SHA256, 10_000_001, AES256)), ITERATION_LIMIT),
                        arguments(named("PBES1", pbes1(PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC, 10_000_001)),
                                ITERATION_LIMIT),
                        arguments(named("PKCS#12", pkcs12(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC4, 10_000_001)),
                                ITERATION_LIMIT),
                        arguments(named("scrypt memory by its cost", scrypt(1 << 16, 8, 1)), SCRYPT_MEMORY_LIMIT),
                        arguments(named("scrypt memory by its block size", scrypt(1 << 14, 17, 1)),
                                SCRYPT_MEMORY_LIMIT),
                        arguments(named("scrypt memory by its cost with a block size of 1", scrypt(1 << 19, 1, 1)),
                                SCRYPT_MEMORY_LIMIT),
                        arguments(named("scrypt parallelization", scrypt(1 << 14, 8, 2)),
                                SCRYPT_PARALLELIZATION_LIMIT));
    }

    static Stream<Arguments> attackerSizedScrypt() {
        BigInteger huge = BigInteger.ONE.shiftLeft(8 * 1_000_000).subtract(BigInteger.ONE);
        BigInteger alsoHuge = huge.subtract(BigInteger.TWO);
        return Stream
                .of(arguments(named("huge r and N", scrypt(alsoHuge, huge, BigInteger.ONE)), SCRYPT_MEMORY_LIMIT),
                        arguments(
                                named("huge negative r and N",
                                        scrypt(alsoHuge.negate(), huge.negate(), BigInteger.ONE)),
                                KeyFileRefusal.UNREADABLE),
                        arguments(
                                named("huge negative r and p, with N = 2",
                                        scrypt(BigInteger.TWO, huge.negate(), alsoHuge.negate())),
                                KeyFileRefusal.UNREADABLE));
    }

    static Stream<Arguments> chargedProtections() {
        return Stream
                .of(arguments(named("scrypt, as r·N·p", scrypt(1 << 15, 8, 1)), 262_144),
                        arguments(named("PBES1", pbes1(PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC, 2048)), 2048),
                        arguments(named("PKCS#12", pkcs12(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, 4096)),
                                4096),
                        arguments(named("PBKDF2", pbes2(SHA256, 600_000, AES256)), 600_000));
    }

    static Stream<Named<AlgorithmIdentifier>> damagedProtections() {
        return Stream
                .of(named("PBES2 with NULL parameters",
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, DERNull.INSTANCE)),
                        named("PBES1 without parameters",
                                new AlgorithmIdentifier(PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC)),
                        named("scrypt with a cost of 0", scrypt(0, 8, 1)),
                        named("scrypt with a parallelization of 0", scrypt(1 << 14, 8, 0)));
    }

    private static AlgorithmIdentifier pbes2(ASN1ObjectIdentifier prf, int iterations, ASN1ObjectIdentifier cipher) {
        return pbes2(
                new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2,
                        new PBKDF2Params(new byte[16], iterations, new AlgorithmIdentifier(prf, DERNull.INSTANCE))),
                cipher);
    }

    private static AlgorithmIdentifier pbes2(KeyDerivationFunc derivation, ASN1ObjectIdentifier cipher) {
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2,
                new PBES2Parameters(derivation, new EncryptionScheme(cipher, new DEROctetString(new byte[16]))));
    }

    private static AlgorithmIdentifier scrypt(int cost, int blockSize, int parallelization) {
        return scrypt(BigInteger.valueOf(cost), BigInteger.valueOf(blockSize), BigInteger.valueOf(parallelization));
    }

    private static AlgorithmIdentifier scrypt(BigInteger cost, BigInteger blockSize, BigInteger parallelization) {
        return pbes2(
                new KeyDerivationFunc(MiscObjectIdentifiers.id_scrypt,
                        new ScryptParams(new byte[16], cost, blockSize, parallelization, BigInteger.valueOf(32))),
                AES256);
    }

    private static AlgorithmIdentifier pbes1(ASN1ObjectIdentifier scheme, int iterations) {
        return new AlgorithmIdentifier(scheme, new PBEParameter(new byte[8], iterations));
    }

    private static AlgorithmIdentifier pkcs12(ASN1ObjectIdentifier scheme, int iterations) {
        return new AlgorithmIdentifier(scheme, new PKCS12PBEParams(new byte[8], iterations));
    }
}
