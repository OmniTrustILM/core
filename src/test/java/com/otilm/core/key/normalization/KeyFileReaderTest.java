package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.util.io.pem.PemHeader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class KeyFileReaderTest {

    private static final String NESTING_LIMIT = KeyFileRefusal.LIMIT_EXCEEDED.formatted("nesting depth", 32);

    private static final PemHeader PROTECTED = new PemHeader("Proc-Type", "4,ENCRYPTED");

    private static KeyPair rsa;

    private static KeyPair ec;

    @BeforeAll
    static void keys() throws GeneralSecurityException {
        KeyFiles.registerProviders();
        rsa = KeyFiles.rsa();
        ec = KeyFiles.ec();
    }

    @ParameterizedTest
    @MethodSource("keysWithoutProtection")
    void read_takesAKeyWithoutProtectionAsPkcs8(byte[] file, KeyPair keyPair) throws Exception {
        // when
        KeyFile read = KeyFileReader.read(file);

        // then
        assertThat(read).isInstanceOf(KeyFile.Plain.class);
        assertThat(((KeyFile.Plain) read).privateKeyInfo().getEncoded()).isEqualTo(keyPair.getPrivate().getEncoded());
    }

    @ParameterizedTest
    @MethodSource("protectedPkcs8Keys")
    void read_takesAProtectedPkcs8KeyInDerOrPem(byte[] file) {
        // when
        KeyFile read = KeyFileReader.read(file);

        // then
        assertThat(read).isInstanceOf(KeyFile.Pkcs8Protected.class);
    }

    @Test
    void read_takesAProtectedTraditionalKeyWithItsCipherAndInitializationVector() throws Exception {
        // when
        KeyFile read = KeyFileReader.read(KeyFiles.traditional(rsa, "AES-256-CBC"));

        // then
        assertThat(read).isInstanceOfSatisfying(KeyFile.TraditionalProtected.class, key -> {
            assertThat(key.kind()).isEqualTo(TraditionalKey.RSA);
            assertThat(key.cipher()).isEqualTo("AES-256-CBC");
            assertThat(key.iv()).hasSize(16);
        });
    }

    @ParameterizedTest
    @MethodSource("filesThatAreNotASingleKey")
    void read_refusesAFileThatDoesNotHoldExactlyOneKey(byte[] file) {
        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> KeyFileReader.read(file));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.NOT_A_KEY_FILE);
    }

    @ParameterizedTest
    @MethodSource("damagedKeys")
    void read_refusesADamagedKeyAsUnreadable(byte[] file) {
        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> KeyFileReader.read(file));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @ParameterizedTest
    @MethodSource("unsupportedProtections")
    void read_namesAnUnsupportedProtectionBeforeAnyPassphraseIsUsed(byte[] file, String named) {
        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> KeyFileReader.read(file));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNSUPPORTED_PROTECTION.formatted(named));
    }

    @ParameterizedTest
    @MethodSource("deeplyNestedFiles")
    void read_refusesNestingDeeperThanAKeyFileMay(byte[] file) {
        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> KeyFileReader.read(file));

        // then
        assertThat(refusal.getMessage()).isEqualTo(NESTING_LIMIT);
    }

    @Test
    void parse_overwritesTheBytesItReads() throws Exception {
        // given
        byte[] der = KeyFiles.pkcs8(ec).clone();

        // when
        PrivateKeyInfo parsed = KeyFileReader.parse(der, PrivateKeyInfo::getInstance);

        // then
        assertThat(parsed.getEncoded()).isEqualTo(ec.getPrivate().getEncoded());
        assertThat(der).containsOnly((byte) 0);
    }

    @Test
    void parse_overwritesTheBytesEvenWhenItCannotReadThem() {
        // given
        byte[] notDer = ascii("not DER");

        // when
        assertThrows(ValidationException.class, () -> KeyFileReader.parse(notDer, PrivateKeyInfo::getInstance));

        // then
        assertThat(notDer).containsOnly((byte) 0);
    }

    static Stream<Arguments> keysWithoutProtection() throws Exception {
        String pem = new String(KeyFiles.pem("PRIVATE KEY", KeyFiles.pkcs8(ec)), StandardCharsets.US_ASCII);
        return Stream
                .of(arguments(named("PKCS#8 as DER", KeyFiles.pkcs8(ec)), ec),
                        arguments(named("PKCS#8 as PEM", ascii(pem)), ec),
                        arguments(named("traditional RSA", KeyFiles.traditional(rsa, null)), rsa),
                        arguments(named("traditional EC", KeyFiles.traditional(ec, null)), ec),
                        arguments(named("PEM with Windows line endings", ascii(pem.replace("\n", "\r\n"))), ec),
                        arguments(
                                named("PEM after a byte order mark",
                                        concatenated(new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF}, ascii(pem))),
                                ec),
                        arguments(named("PEM after the text OpenSSL writes around a key",
                                ascii("Bag Attributes\n    localKeyID: 01 02 03\nKey Attributes: <No Attributes>\n"
                                        + pem)),
                                ec),
                        arguments(named("traditional EC after the curve openssl ecparam writes",
                                concatenated(KeyFiles.pem("EC PARAMETERS", X9ObjectIdentifiers.prime256v1.getEncoded()),
                                        KeyFiles.traditional(ec, null))),
                                ec));
    }

    static Stream<Named<byte[]>> protectedPkcs8Keys() throws Exception {
        byte[] envelope = KeyFiles.encrypted(ec, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA256);
        return Stream.of(named("DER", envelope), named("PEM", KeyFiles.pem("ENCRYPTED PRIVATE KEY", envelope)));
    }

    static Stream<Named<byte[]>> filesThatAreNotASingleKey() throws Exception {
        byte[] key = KeyFiles.pem("PRIVATE KEY", KeyFiles.pkcs8(ec));
        byte[] certificate = KeyFiles.pem("CERTIFICATE", new byte[]{1, 2, 3});
        return Stream
                .of(named("text", ascii("not a key")), named("an empty file", new byte[0]),
                        named("a certificate", certificate),
                        named("a public key", KeyFiles.pem("PUBLIC KEY", ec.getPublic().getEncoded())),
                        named("an OpenSSH key", KeyFiles.pem("OPENSSH PRIVATE KEY", new byte[]{1, 2, 3})),
                        named("a key with its certificate", concatenated(key, certificate)),
                        named("two keys", concatenated(key, KeyFiles.pem("PRIVATE KEY", KeyFiles.pkcs8(rsa)))),
                        named("PKCS#12", pkcs12()),
                        named("a traditional key as DER",
                                PrivateKeyInfo
                                        .getInstance(KeyFiles.pkcs8(rsa))
                                        .parsePrivateKey()
                                        .toASN1Primitive()
                                        .getEncoded()));
    }

    static Stream<Named<byte[]>> damagedKeys() throws Exception {
        byte[] notDer = ascii("not DER");
        return Stream
                .of(named("PEM that is not base64",
                        ascii("-----BEGIN PRIVATE KEY-----\n@@@@\n-----END PRIVATE KEY-----\n")),
                        named("a key that is not DER", KeyFiles.pem("PRIVATE KEY", notDer)),
                        named("a protected key that is not DER", KeyFiles.pem("ENCRYPTED PRIVATE KEY", notDer)),
                        named("a traditional key that is not DER", KeyFiles.pem("EC PRIVATE KEY", notDer)),
                        named("a protected traditional key without DEK-Info",
                                KeyFiles.pem("RSA PRIVATE KEY", List.of(PROTECTED), new byte[32])),
                        named("a protected traditional key with an initialization vector that is not hex",
                                KeyFiles
                                        .pem("RSA PRIVATE KEY",
                                                List.of(PROTECTED, new PemHeader("DEK-Info", "AES-256-CBC,XYZ")),
                                                new byte[32])));
    }

    static Stream<Arguments> unsupportedProtections() throws Exception {
        return Stream
                .of(arguments(
                        named("PBES2 with HMAC-SHA1",
                                KeyFiles.encrypted(ec, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA1)),
                        "1.2.840.113549.2.7"),
                        arguments(named("traditional SEED-CBC",
                                KeyFiles
                                        .pem("RSA PRIVATE KEY",
                                                List
                                                        .of(PROTECTED,
                                                                new PemHeader("DEK-Info",
                                                                        "SEED-CBC,00112233445566778899AABBCCDDEEFF")),
                                                new byte[32])),
                                "SEED-CBC"));
    }

    static Stream<Named<byte[]>> deeplyNestedFiles() throws Exception {
        byte[] nested = KeyFiles.nested(KeyFileReader.MAXIMUM_NESTING_DEPTH + 1);
        return Stream
                .of(named("DER", nested), named("PKCS#8 as PEM", KeyFiles.pem("PRIVATE KEY", nested)),
                        named("traditional PEM", KeyFiles.pem("EC PRIVATE KEY", nested)));
    }

    private static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] concatenated(byte[] first, byte[] second) {
        byte[] both = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, both, first.length, second.length);
        return both;
    }

    private static byte[] pkcs12() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        ByteArrayOutputStream file = new ByteArrayOutputStream();
        store.store(file, KeyFiles.PASSPHRASE);
        return file.toByteArray();
    }
}
