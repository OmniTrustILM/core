package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.secret.Passphrase;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Stream;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class OpenSshKeyTest {

    private static final Passphrase PASSPHRASE = new Passphrase("openssh-test-passphrase".toCharArray());

    private static final byte[] MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII);

    private static final KeyNormalizer NORMALIZER = new KeyNormalizer();

    /** The {@code .pub} companion of {@code rsa-bcrypt}; only the private key fixtures are committed. */
    private static final String RSA_BCRYPT_PUBLIC = "AAAAB3NzaC1yc2EAAAADAQABAAABAQCu0kw6giKf1eNRIE7PgaY+cV2Df+fVD2"
            + "Lj0N1gVbWOMDDnNoKVUTIduXQDr9Z/wSjx+5avoKiRWqQzPWBkw6biQa5+jKxYAeooQtPYr/YdMkHPLjSqqs5f6SSPSOjeqyi1l8Z/"
            + "Iz+Y7pQuh7a2/poXFa0RoKm9icqZBcICNV/qg/dMmy6dRbQw6A29Iis6a+mJRWtR+pgXyAQn6wyAtS+sO+n9oqGkvO+uSD+WNDBCGp"
            + "8SO+huZxVGQiUgYH2UxCVgW/+XmfOGyQK5ia74j8oMCClrDHPlT3hC9Pel+bsskImCCP/xXvD9fcg6CXGFaU9O6SOkUQZsWEyQl3mS"
            + "VCOD";

    /** The {@code .pub} companion of {@code ecdsa-p256-bcrypt}. */
    private static final String ECDSA_P256_BCRYPT_PUBLIC = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB"
            + "EmL3vRMbWRyipGRDTzUgYJkxFG33zTC/36H//+G56MoKRjYTNWPJbIVVr9X/nIRo6Bp7vDulH6wOSCaGSa3M+4=";

    @BeforeAll
    static void providers() {
        KeyFiles.registerProviders();
    }

    @Test
    void describe_readsAPlainOpenSshKey() throws Exception {
        // given
        byte[] file = fixture("rsa-plain");

        // when
        KeyDescription description = NORMALIZER.describe(file, null, DerivationBudget.forFile());

        // then
        assertThat(description.supported()).isTrue();
        assertThat(description.type()).isEqualTo(KeyRequestType.KEY_PAIR);
        assertThat(description.algorithm()).isEqualTo(KeyAlgorithm.RSA);
        assertThat(description.length()).isEqualTo(2048);
    }

    @ParameterizedTest
    @MethodSource("bcryptProtectedKeys")
    void describe_readsABcryptProtectedOpenSshKey(String fixtureName, String publicKey, KeyAlgorithm algorithm,
            int length) throws Exception {
        // given
        byte[] file = fixture(fixtureName);

        // when
        KeyDescription description = NORMALIZER.describe(file, PASSPHRASE, DerivationBudget.forFile());

        // then
        assertThat(description.supported()).isTrue();
        assertThat(description.algorithm()).isEqualTo(algorithm);
        assertThat(description.length()).isEqualTo(length);
        assertSamePublicKey(description.subjectPublicKeyInfo(), publicKey, algorithm);
    }

    @Test
    void describe_namesEd25519AsUnsupported() throws Exception {
        // given
        byte[] file = fixture("ed25519-bcrypt");

        // when
        KeyDescription description = NORMALIZER.describe(file, PASSPHRASE, DerivationBudget.forFile());

        // then
        assertThat(description.supported()).isFalse();
        assertThat(description.unsupportedAlgorithm()).isEqualTo("1.3.101.112");
    }

    @Test
    void describe_refusesAWrongPassphraseAsUnreadable() throws Exception {
        // given
        byte[] file = fixture("rsa-bcrypt");
        Passphrase wrong = new Passphrase("not the passphrase".toCharArray());
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(file, wrong, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void describe_refusesMoreBcryptRoundsThanTheLimit() throws Exception {
        // given
        byte[] file = fixture("rsa-bcrypt-300-rounds");
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(file, PASSPHRASE, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo("The file exceeds the bcrypt rounds limit of 256.");
    }

    @Test
    void describe_refusesBcryptRoundsAboveTheLimitEvenWhenUnsigned() throws Exception {
        // given
        byte[] file = withRounds(fixture("rsa-bcrypt"), 0xFFFFFFFF);
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(file, PASSPHRASE, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo("The file exceeds the bcrypt rounds limit of 256.");
    }

    @Test
    void describe_refusesZeroBcryptRoundsAsUnreadable() throws Exception {
        // given
        byte[] file = withRounds(fixture("rsa-bcrypt"), 0);
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(file, PASSPHRASE, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void describe_refusesAnUnknownCipherNamingIt() throws Exception {
        // given
        byte[] file = withCipher(fixture("rsa-bcrypt"), "twofish256-ctr");
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(file, PASSPHRASE, budget));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo("The file is protected with twofish256-ctr, which is not supported.");
    }

    @Test
    void describe_refusesACipherWithoutAKdfNamingIt() throws Exception {
        // given
        byte[] file = withCipher(fixture("rsa-plain"), "aes256-ctr");
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(file, null, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo("The file is protected with aes256-ctr, which is not supported.");
    }

    @Test
    void describe_refusesAnUnknownKdfNamingIt() throws Exception {
        // given
        byte[] file = withKdf(fixture("rsa-plain"), "unknown-kdf");
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(file, null, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo("The file is protected with unknown-kdf, which is not supported.");
    }

    @Test
    void header_refusesAWrongMagicAsUnreadable() throws Exception {
        // given
        byte[] blob = pemContent(fixture("rsa-plain"));
        blob[0] = 'O';

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> OpenSshKey.header(blob));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void describe_refusesANegativeFieldLengthAsUnreadable() throws Exception {
        // given
        byte[] file = KeyFiles
                .pem("OPENSSH PRIVATE KEY",
                        concatenated(MAGIC, new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(file, null, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void describe_refusesAHeaderTruncatedInsideALengthPrefixAsUnreadable() throws Exception {
        // given
        byte[] file = KeyFiles.pem("OPENSSH PRIVATE KEY", concatenated(MAGIC, new byte[]{0, 0}));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(file, null, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void cursor_refusesAFieldLengthRunningPastTheBlobAsUnreadable() {
        // given
        OpenSshKey.Cursor cursor = new OpenSshKey.Cursor(new byte[]{0, 0, 0, 100, 1, 2, 3, 4, 5}); // length 100, 5 left

        // when
        ValidationException refusal = assertThrows(ValidationException.class, cursor::block);

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void header_acceptsTheMaximumBcryptRounds() throws Exception {
        // given
        byte[] blob = pemContent(withRounds(fixture("rsa-bcrypt"), 256));

        // when
        OpenSshKey.Header header = OpenSshKey.header(blob);

        // then
        assertThat(header.rounds()).isEqualTo(256);
    }

    @Test
    void describe_refusesAFileWithTwoKeys() throws Exception {
        // given
        byte[] file = withTwoKeys(fixture("rsa-plain"));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(file, null, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.NOT_A_KEY_FILE);
    }

    @Test
    void normalize_protectsAnOpenSshKeyInThePinnedProfile() throws Exception {
        // given
        byte[] file = fixture("rsa-bcrypt");

        // when
        NormalizedKey key = NORMALIZER.normalize(file, PASSPHRASE, KeyRequestType.KEY_PAIR, DerivationBudget.forFile());

        // then
        assertThat(key.algorithm()).isEqualTo(KeyAlgorithm.RSA);
        assertThat(key.length()).isEqualTo(2048);
        assertSamePublicKey(key.subjectPublicKeyInfo(), RSA_BCRYPT_PUBLIC, KeyAlgorithm.RSA);
        RSAPrivateKey opened = (RSAPrivateKey) KeyFactory
                .getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(KeyFiles.opened(key)));
        RSAKeyParameters reference = (RSAKeyParameters) referencePublicKey(RSA_BCRYPT_PUBLIC);
        assertThat(opened.getModulus()).isEqualTo(reference.getModulus());
    }

    @Test
    void normalize_refusesAnUnprotectedEd25519KeyNamingItsAlgorithm() throws Exception {
        // given
        byte[] file = fixture("ed25519-plain");
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.normalize(file, null, KeyRequestType.KEY_PAIR, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.unsupportedAlgorithm("1.3.101.112").getMessage());
    }

    static Stream<Arguments> bcryptProtectedKeys() {
        return Stream
                .of(arguments(named("RSA", "rsa-bcrypt"), RSA_BCRYPT_PUBLIC, KeyAlgorithm.RSA, 2048), arguments(
                        named("ECDSA P-256", "ecdsa-p256-bcrypt"), ECDSA_P256_BCRYPT_PUBLIC, KeyAlgorithm.ECDSA, 256));
    }

    /** The key Bouncy Castle's own OpenSSH public-key reader derives from a {@code .pub} blob. */
    private static AsymmetricKeyParameter referencePublicKey(String publicKeyBlob) {
        return OpenSSHPublicKeyUtil.parsePublicKey(Base64.getDecoder().decode(publicKeyBlob));
    }

    private static void assertSamePublicKey(byte[] subjectPublicKeyInfo, String publicKeyBlob, KeyAlgorithm algorithm)
            throws Exception {
        AsymmetricKeyParameter reference = referencePublicKey(publicKeyBlob);
        if (algorithm == KeyAlgorithm.RSA) {
            RSAPublicKey ours = (RSAPublicKey) KeyFactory
                    .getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(subjectPublicKeyInfo));
            RSAKeyParameters expected = (RSAKeyParameters) reference;
            assertThat(ours.getModulus()).isEqualTo(expected.getModulus());
            assertThat(ours.getPublicExponent()).isEqualTo(expected.getExponent());
        } else {
            ECPublicKey ours = (ECPublicKey) KeyFactory
                    .getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(subjectPublicKeyInfo));
            ECPublicKeyParameters expected = (ECPublicKeyParameters) reference;
            assertThat(ours.getW().getAffineX()).isEqualTo(expected.getQ().getAffineXCoord().toBigInteger());
            assertThat(ours.getW().getAffineY()).isEqualTo(expected.getQ().getAffineYCoord().toBigInteger());
        }
    }

    private static byte[] concatenated(byte[] first, byte[] second) {
        byte[] both = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, both, first.length, second.length);
        return both;
    }

    private static byte[] fixture(String name) throws IOException {
        try (InputStream in = OpenSshKeyTest.class.getClassLoader().getResourceAsStream("key/openssh/" + name)) {
            return in.readAllBytes();
        }
    }

    /** The fixture with its cipher name field rewritten, everything after it kept as it was. */
    private static byte[] withCipher(byte[] file, String cipher) throws IOException {
        return KeyFiles.pem("OPENSSH PRIVATE KEY", withField(pemContent(file), MAGIC.length, cipher));
    }

    /** The fixture with its KDF name field rewritten, its cipher name kept as it was. */
    private static byte[] withKdf(byte[] file, String kdf) throws IOException {
        byte[] blob = pemContent(file);
        int kdfStart = MAGIC.length + 4 + u32(blob, MAGIC.length);
        return KeyFiles.pem("OPENSSH PRIVATE KEY", withField(blob, kdfStart, kdf));
    }

    /** The string field starting at the position replaced by the value, everything after it kept as it was. */
    private static byte[] withField(byte[] blob, int fieldStart, String value) {
        int length = u32(blob, fieldStart);
        int after = fieldStart + 4 + length;
        byte[] replacement = value.getBytes(StandardCharsets.US_ASCII);
        byte[] mutated = new byte[fieldStart + 4 + replacement.length + (blob.length - after)];
        System.arraycopy(blob, 0, mutated, 0, fieldStart);
        writeU32(mutated, fieldStart, replacement.length);
        System.arraycopy(replacement, 0, mutated, fieldStart + 4, replacement.length);
        System.arraycopy(blob, after, mutated, fieldStart + 4 + replacement.length, blob.length - after);
        return mutated;
    }

    /** The bcrypt-protected fixture with its round count rewritten, everything else kept as it was. */
    private static byte[] withRounds(byte[] file, int rounds) throws IOException {
        byte[] blob = pemContent(file).clone();
        int position = MAGIC.length;
        position += 4 + u32(blob, position); // cipher name
        position += 4 + u32(blob, position); // KDF name
        position += 4; // past the KDF options length prefix
        position += 4 + u32(blob, position); // salt
        writeU32(blob, position, rounds);
        return KeyFiles.pem("OPENSSH PRIVATE KEY", blob);
    }

    /** The fixture with its key count field rewritten from one to two. */
    private static byte[] withTwoKeys(byte[] file) throws IOException {
        byte[] blob = pemContent(file).clone();
        int position = MAGIC.length;
        position += 4 + u32(blob, position); // cipher name
        position += 4 + u32(blob, position); // KDF name
        position += 4 + u32(blob, position); // KDF options
        blob[position + 3] = 2;
        return KeyFiles.pem("OPENSSH PRIVATE KEY", blob);
    }

    private static byte[] pemContent(byte[] file) throws IOException {
        try (PemReader reader = new PemReader(
                new InputStreamReader(new ByteArrayInputStream(file), StandardCharsets.US_ASCII))) {
            return reader.readPemObject().getContent();
        }
    }

    private static int u32(byte[] buffer, int position) {
        return ((buffer[position] & 0xFF) << 24) | ((buffer[position + 1] & 0xFF) << 16)
                | ((buffer[position + 2] & 0xFF) << 8) | (buffer[position + 3] & 0xFF);
    }

    private static void writeU32(byte[] buffer, int position, int value) {
        buffer[position] = (byte) (value >>> 24);
        buffer[position + 1] = (byte) (value >>> 16);
        buffer[position + 2] = (byte) (value >>> 8);
        buffer[position + 3] = (byte) value;
    }
}
