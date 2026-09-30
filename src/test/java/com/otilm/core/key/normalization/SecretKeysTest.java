package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.secret.Passphrase;
import java.security.KeyPair;
import java.util.stream.Stream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.openssl.PKCS8Generator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class SecretKeysTest {

    private static final KeyNormalizer NORMALIZER = new KeyNormalizer();

    private static final AlgorithmIdentifier AES = new AlgorithmIdentifier(NISTObjectIdentifiers.aes);

    private static KeyPair rsa;

    @BeforeAll
    static void keys() throws Exception {
        KeyFiles.registerProviders();
        rsa = KeyFiles.rsa();
    }

    @ParameterizedTest
    @ValueSource(ints = {128, 192, 256})
    void describe_readsAnAesKeyAsAJdkPkcs12StoreProtectsIt(int bits) throws Exception {
        // given
        byte[] file = SecretKeyFiles.pkcs12SecretBagValue(SecretKeyFiles.aes(bits));
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        KeyDescription description = NORMALIZER.describe(file, passphrase, budget);

        // then
        assertThat(description)
                .extracting(KeyDescription::type, KeyDescription::algorithm, KeyDescription::length,
                        KeyDescription::subjectPublicKeyInfo, KeyDescription::unsupportedAlgorithm)
                .containsExactly(KeyRequestType.SECRET, KeyAlgorithm.AES, bits, null, null);
    }

    @ParameterizedTest
    @ValueSource(ints = {128, 192, 256})
    void normalize_protectsAnAesKeyInThePinnedProfile(int bits) throws Exception {
        // given
        SecretKey aes = SecretKeyFiles.aes(bits);
        byte[] file = SecretKeyFiles.pkcs12SecretBagValue(aes);
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        NormalizedKey key = NORMALIZER.normalize(file, passphrase, KeyRequestType.SECRET, budget);

        // then
        assertThat(key)
                .extracting(NormalizedKey::type, NormalizedKey::algorithm, NormalizedKey::length,
                        NormalizedKey::subjectPublicKeyInfo)
                .containsExactly(KeyRequestType.SECRET, KeyAlgorithm.AES, bits, null);
        assertThat(KeyFiles.opened(key))
                .isEqualTo(SecretKeyFiles.opened(file))
                .isEqualTo(SecretKeyFiles.pkcs8Shaped(AES, aes.getEncoded()));
    }

    @ParameterizedTest
    @MethodSource("secretKeysThePlatformDoesNotHold")
    void describe_namesTheAlgorithmOfASecretKeyThePlatformDoesNotHoldAsUnsupported(byte[] file, String algorithm) {
        // given
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        KeyDescription description = NORMALIZER.describe(file, passphrase, budget);

        // then
        assertThat(description.supported()).isFalse();
        assertThat(description.unsupportedAlgorithm()).isEqualTo(algorithm);
        assertThat(description)
                .extracting(KeyDescription::type, KeyDescription::algorithm, KeyDescription::length,
                        KeyDescription::subjectPublicKeyInfo)
                .containsExactly(null, null, 0, null);
    }

    @ParameterizedTest
    @MethodSource("secretKeysWithoutProtection")
    void describe_refusesASecretKeyWithoutProtection(byte[] file) {
        // given
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(file, null, budget));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo("The file holds a secret key without protection, which is not supported.");
    }

    @Test
    void normalize_refusesAnAesKeyWithoutProtection() throws Exception {
        // given
        byte[] file = SecretKeyFiles.pkcs8Shaped(AES, SecretKeyFiles.aes(256).getEncoded());
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.normalize(file, null, KeyRequestType.SECRET, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNPROTECTED_SECRET);
    }

    @Test
    void normalize_refusesToImportAnAesKeyAsAKeyPair() throws Exception {
        // given
        byte[] file = SecretKeyFiles.pkcs12SecretBagValue(SecretKeyFiles.aes(256));
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.normalize(file, passphrase, KeyRequestType.KEY_PAIR, budget));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo("A key file holds a secret key, so it cannot be imported as a key pair.");
    }

    @ParameterizedTest
    @MethodSource("rsaKeys")
    void normalize_refusesToImportAnRsaKeyAsASecretKey(byte[] file, Passphrase passphrase) {
        // given
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.normalize(file, passphrase, KeyRequestType.SECRET, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.NOT_OF_TYPE.formatted("key pair", "secret key"));
    }

    @Test
    void normalize_refusesASecretKeyOfAnotherAlgorithmAsUnreadable() throws Exception {
        // given
        byte[] file = SecretKeyFiles.pkcs12SecretBagValue(KeyGenerator.getInstance("DESede").generateKey());
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.normalize(file, passphrase, KeyRequestType.SECRET, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    static Stream<Arguments> secretKeysThePlatformDoesNotHold() throws Exception {
        SecretKey desede = KeyGenerator.getInstance("DESede").generateKey();
        return Stream
                .of(arguments(
                        named("an AES key of 160 bits",
                                KeyFiles.encryptedContent(SecretKeyFiles.pkcs8Shaped(AES, new byte[20]))),
                        NISTObjectIdentifiers.aes.getId()),
                        arguments(named("DESede as PKCS#5 names it", KeyFiles
                                .encryptedContent(SecretKeyFiles
                                        .pkcs8Shaped(new AlgorithmIdentifier(PKCSObjectIdentifiers.des_EDE3_CBC),
                                                desede.getEncoded()))),
                                "1.2.840.113549.3.7"),
                        arguments(named("DESede as the JDK names it", SecretKeyFiles.pkcs12SecretBagValue(desede)),
                                "1.3.14.3.2.17"),
                        arguments(
                                named("an HMAC key", SecretKeyFiles
                                        .pkcs12SecretBagValue(KeyGenerator.getInstance("HmacSHA256").generateKey())),
                                "1.2.840.113549.2.9"));
    }

    static Stream<Named<byte[]>> secretKeysWithoutProtection() throws Exception {
        byte[] aes = SecretKeyFiles.pkcs8Shaped(AES, SecretKeyFiles.aes(128).getEncoded());
        return Stream
                .of(named("AES as DER", aes), named("AES as PEM", KeyFiles.pem("PRIVATE KEY", aes)),
                        named("DESede",
                                SecretKeyFiles
                                        .pkcs8Shaped(new AlgorithmIdentifier(PKCSObjectIdentifiers.des_EDE3_CBC),
                                                KeyGenerator.getInstance("DESede").generateKey().getEncoded())));
    }

    static Stream<Arguments> rsaKeys() throws Exception {
        return Stream
                .of(arguments(named("without protection", KeyFiles.pkcs8(rsa)), null), arguments(
                        named("behind a passphrase",
                                KeyFiles.encrypted(rsa, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA256)),
                        KeyFiles.passphrase()));
    }
}
