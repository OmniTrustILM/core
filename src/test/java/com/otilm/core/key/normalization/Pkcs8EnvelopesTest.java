package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.secret.Passphrase;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.openssl.PKCS8Generator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Pkcs8EnvelopesTest {

    private static KeyPair keyPair;

    @BeforeAll
    static void createKeyPair() throws Exception {
        KeyFiles.registerProviders();
        keyPair = KeyFiles.ec();
    }

    @Test
    void returnsTheKey_whenThePassphraseOpensAPbes2Envelope() throws Exception {
        // given
        byte[] envelope = KeyFiles.encrypted(keyPair, KeyFiles.ITERATIONS);

        // when
        PrivateKeyInfo opened = Pkcs8Envelopes.decrypt(envelope, KeyFiles.passphrase(), DerivationBudget.forFile());

        // then
        assertThat(opened.getEncoded()).isEqualTo(KeyFiles.pkcs8(keyPair));
    }

    @Test
    void refusesWithTheUniformMessage_whenThePassphraseIsWrong() throws Exception {
        // given
        byte[] envelope = KeyFiles.encrypted(keyPair, KeyFiles.ITERATIONS);
        Passphrase wrongPassphrase = new Passphrase("not the passphrase".toCharArray());

        // when
        ThrowingCallable decrypt = () -> Pkcs8Envelopes.decrypt(envelope, wrongPassphrase, DerivationBudget.forFile());

        // then
        assertThatThrownBy(decrypt)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void refusesWithTheUniformMessage_whenThereIsNoPassphrase() throws Exception {
        // given
        byte[] envelope = KeyFiles.encrypted(keyPair, KeyFiles.ITERATIONS);

        // when
        ThrowingCallable decrypt = () -> Pkcs8Envelopes.decrypt(envelope, null, DerivationBudget.forFile());

        // then
        assertThatThrownBy(decrypt)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(KeyFileRefusal.UNREADABLE);
    }

    @Test
    @Timeout(5)
    void refusesTheIterationLimit_whenTheEnvelopeAsksForMoreThanTheBudget() throws Exception {
        // given
        EncryptionScheme aes = new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CBC,
                new DEROctetString(new byte[16]));
        KeyDerivationFunc pbkdf2 = new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2,
                new PBKDF2Params(new byte[16], Integer.MAX_VALUE, PKCS8Generator.PRF_HMACSHA256));
        byte[] overBudget = KeyFiles
                .envelope(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, new PBES2Parameters(pbkdf2, aes)),
                        new byte[32]);

        // when
        ThrowingCallable decrypt = () -> Pkcs8Envelopes
                .decrypt(overBudget, KeyFiles.passphrase(), DerivationBudget.forFile());

        // then
        assertThatThrownBy(decrypt)
                .isInstanceOf(ValidationException.class)
                .hasMessage(KeyFileRefusal.LIMIT_EXCEEDED
                        .formatted("key derivation iteration", DerivationBudget.FILE_ITERATIONS));
    }

    @Test
    void refusesAsNotAKeyFile_whenTheBytesAreNotAnEnvelope() {
        // given
        byte[] notAnEnvelope = {0x04, 0x01, 0x00};

        // when
        ThrowingCallable decrypt = () -> Pkcs8Envelopes
                .decrypt(notAnEnvelope, KeyFiles.passphrase(), DerivationBudget.forFile());

        // then
        assertThatThrownBy(decrypt)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(KeyFileRefusal.NOT_A_KEY_FILE);
    }

    @Test
    void zeroesThePassphraseCharacters_whenTheDecryptionFails() {
        // given
        var handedOut = new AtomicReference<char[]>();
        Pkcs8Envelopes.Decryption failing = characters -> {
            handedOut.set(characters);
            throw new IllegalStateException("fails");
        };

        // when
        ThrowingCallable decrypt = () -> Pkcs8Envelopes.decryptWith(KeyFiles.passphrase(), failing);

        // then
        assertThatThrownBy(decrypt).isInstanceOf(ValidationException.class);
        assertThat(handedOut.get()).containsOnly('\0').hasSize(KeyFiles.PASSPHRASE.length);
    }

    @Test
    void zeroesThePlaintext_whenItIsNestedTooDeeply() throws Exception {
        // given
        byte[] tooDeep = KeyFiles.nested(KeyNormalizer.MAXIMUM_NESTING_DEPTH + 1);
        Pkcs8Envelopes.Decryption returningTooDeep = characters -> tooDeep;

        // when
        ThrowingCallable decrypt = () -> Pkcs8Envelopes.decryptWith(KeyFiles.passphrase(), returningTooDeep);

        // then
        assertThatThrownBy(decrypt).isInstanceOf(ValidationException.class);
        assertThat(tooDeep).containsOnly(0);
    }

    @Test
    void zeroesThePrivateKey_whenOverwritten() throws Exception {
        // given
        PrivateKeyInfo key = PrivateKeyInfo.getInstance(KeyFiles.pkcs8(keyPair));

        // when
        Pkcs8Envelopes.overwrite(key);

        // then
        assertThat(key.getPrivateKey().getOctets()).containsOnly(0);
    }

    @Test
    void generatesA43CharacterUrlSafePassphrase_perCall() {
        // given
        var random = new SecureRandom();

        // when
        char[] first = Pkcs8Envelopes.transportPassphrase(random);
        char[] second = Pkcs8Envelopes.transportPassphrase(random);

        // then
        assertThat(new String(first)).matches("[A-Za-z0-9_-]{43}");
        assertThat(Arrays.equals(first, second)).isFalse();
    }
}
