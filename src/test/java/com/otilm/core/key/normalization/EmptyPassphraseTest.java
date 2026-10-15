package com.otilm.core.key.normalization;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.openssl.PKCS8Generator;
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

class EmptyPassphraseTest {

    private static final byte[] CONTENT = "content under an empty passphrase".getBytes(StandardCharsets.US_ASCII);

    @BeforeAll
    static void providers() {
        KeyFiles.registerProviders();
    }

    @ParameterizedTest
    @MethodSource("protections")
    void decrypt_opensContentTheJdkProtectedUnderAnEmptyPassphrase(ASN1ObjectIdentifier prf,
            ASN1ObjectIdentifier cipher) throws Exception {
        // given
        EncryptedPrivateKeyInfo envelope = KeyFiles.underAnEmptyPassphrase(CONTENT, prf, cipher);

        // when
        byte[] content = EmptyPassphrase.decrypt(envelope.getEncryptionAlgorithm(), envelope.getEncryptedData());

        // then
        assertThat(content).isEqualTo(CONTENT);
    }

    @Test
    void decrypts_takesPbes2UnderPbkdf2Only() throws Exception {
        // given
        AlgorithmIdentifier pbkdf2 = KeyFiles
                .underAnEmptyPassphrase(CONTENT, PKCSObjectIdentifiers.id_hmacWithSHA256,
                        NISTObjectIdentifiers.id_aes256_CBC)
                .getEncryptionAlgorithm();
        AlgorithmIdentifier scrypt = EncryptedPrivateKeyInfo
                .getInstance(KeyFiles.scrypt(KeyFiles.ec()))
                .getEncryptionAlgorithm();
        AlgorithmIdentifier pkcs12 = EncryptedPrivateKeyInfo
                .getInstance(KeyFiles.encrypted(KeyFiles.ec(), PKCS8Generator.PBE_SHA1_3DES, null))
                .getEncryptionAlgorithm();

        // when, then
        assertThat(EmptyPassphrase.decrypts(pbkdf2)).isTrue();
        assertThat(EmptyPassphrase.decrypts(scrypt)).isFalse();
        assertThat(EmptyPassphrase.decrypts(pkcs12)).isFalse();
    }

    @ParameterizedTest
    @MethodSource("protectionsNoKeyProtectionAccepts")
    void decrypt_refusesAPrfOrCipherNoKeyProtectionAccepts(AlgorithmIdentifier protection) {
        // given
        byte[] encrypted = new byte[16];

        // when, then
        assertThrows(GeneralSecurityException.class, () -> EmptyPassphrase.decrypt(protection, encrypted));
    }

    static Stream<Arguments> protections() {
        return Stream
                .of(arguments(named("HMAC-SHA224", PKCSObjectIdentifiers.id_hmacWithSHA224),
                        named("AES-128-CBC", NISTObjectIdentifiers.id_aes128_CBC)),
                        arguments(named("HMAC-SHA256", PKCSObjectIdentifiers.id_hmacWithSHA256),
                                named("AES-256-CBC", NISTObjectIdentifiers.id_aes256_CBC)),
                        arguments(named("HMAC-SHA384", PKCSObjectIdentifiers.id_hmacWithSHA384),
                                named("AES-192-CBC", NISTObjectIdentifiers.id_aes192_CBC)),
                        arguments(named("HMAC-SHA512", PKCSObjectIdentifiers.id_hmacWithSHA512),
                                named("DES-EDE3-CBC", PKCSObjectIdentifiers.des_EDE3_CBC)));
    }

    static Stream<Named<AlgorithmIdentifier>> protectionsNoKeyProtectionAccepts() {
        return Stream
                .of(named("a PRF over SHA-1",
                        pbes2(PKCSObjectIdentifiers.id_hmacWithSHA1, NISTObjectIdentifiers.id_aes256_CBC)),
                        named("RC2 as the cipher",
                                pbes2(PKCSObjectIdentifiers.id_hmacWithSHA256, PKCSObjectIdentifiers.RC2_CBC)));
    }

    private static AlgorithmIdentifier pbes2(ASN1ObjectIdentifier prf, ASN1ObjectIdentifier cipher) {
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2,
                new PBES2Parameters(
                        new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2,
                                new PBKDF2Params(new byte[16], KeyFiles.ITERATIONS,
                                        new AlgorithmIdentifier(prf, DERNull.INSTANCE))),
                        new EncryptionScheme(cipher, new DEROctetString(new byte[16]))));
    }
}
