package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.secret.Passphrase;
import java.math.BigInteger;
import java.security.KeyRep;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.stream.Stream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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

class JceksSealedKeyTest {

    private static final KeyNormalizer NORMALIZER = new KeyNormalizer();

    private static final String ITERATION_LIMIT = KeyFileRefusal.LIMIT_EXCEEDED
            .formatted("key derivation iteration", 10_000_000);

    private static final String SEALED_KEY_CLASS = "com.sun.crypto.provider.SealedObjectForKeyProtector";

    private static final String SEALED_OBJECT_CLASS = "javax.crypto.SealedObject";

    private static final String PBE_KEY_ALGORITHM = "PBEWithHmacSHA256AndAES_256";

    private static final String SEAL_ALGORITHM = "PBEWithMD5AndTripleDES";

    private static final String OTHER_SEAL_ALGORITHM = "PBEWithMD5AndTripleDEX";

    private static SecretKey aes;

    private static byte[] aesStore;

    private static byte[] pbeStore;

    private static byte[] aesSealedKey;

    @BeforeAll
    static void keyStores() throws Exception {
        KeyFiles.registerProviders();
        aes = SecretKeyFiles.aes(256);
        aesStore = SecretKeyFiles.jceks(aes);
        pbeStore = SecretKeyFiles
                .jceks(SecretKeyFactory
                        .getInstance(PBE_KEY_ALGORITHM)
                        .generateSecret(new PBEKeySpec("a stored password".toCharArray())));
        aesSealedKey = SecretKeyFiles.sealedKey(aesStore);
    }

    @ParameterizedTest
    @MethodSource("stores")
    void read_takesAsManyBytesAsTheJdkReadsForTheSealedKey(byte[] store) throws Exception {
        // given
        int offset = SecretKeyFiles.sealedKeyOffset(store);

        // when
        JceksSealedKey sealed = JceksSealedKey.read(store, offset);

        // then
        assertThat(sealed.encodedLength()).isEqualTo(SecretKeyFiles.bytesTheJdkReads(store, offset));
    }

    @Test
    void describe_readsAnAesKeyAJceksStoreSeals() {
        // given
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        KeyDescription description = NORMALIZER.describe(aesSealedKey, passphrase, budget);

        // then
        assertThat(description)
                .extracting(KeyDescription::type, KeyDescription::algorithm, KeyDescription::length,
                        KeyDescription::subjectPublicKeyInfo, KeyDescription::unsupportedAlgorithm)
                .containsExactly(KeyRequestType.SECRET, KeyAlgorithm.AES, 256, null, null);
    }

    @Test
    void describe_listsASecretKeyOfAnAlgorithmThePlatformDoesNotSupport() throws Exception {
        // given
        byte[] file = SecretKeyFiles.sealedKey(pbeStore);
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        KeyDescription description = NORMALIZER.describe(file, passphrase, budget);

        // then
        assertThat(description.supported()).isFalse();
        assertThat(description.unsupportedAlgorithm()).isEqualTo(KeyDescription.UNRECOGNIZED_ALGORITHM);
        assertThat(description)
                .extracting(KeyDescription::type, KeyDescription::algorithm, KeyDescription::length,
                        KeyDescription::subjectPublicKeyInfo)
                .containsExactly(null, null, 0, null);
    }

    @ParameterizedTest
    @MethodSource("sealedContents")
    void describe_readsTheFormsTheJdkSealsAKeyIn(byte[] content, KeyAlgorithm algorithm, String unsupported)
            throws Exception {
        // given
        byte[] file = SecretKeyFiles.resealed(aesSealedKey, content);
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        KeyDescription description = NORMALIZER.describe(file, passphrase, budget);

        // then
        assertThat(description.algorithm()).isEqualTo(algorithm);
        assertThat(description.unsupportedAlgorithm()).isEqualTo(unsupported);
    }

    @Test
    void normalize_protectsAJceksAesKeyInThePinnedProfile() throws Exception {
        // given
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        NormalizedKey key = NORMALIZER.normalize(aesSealedKey, passphrase, KeyRequestType.SECRET, budget);

        // then
        assertThat(key)
                .extracting(NormalizedKey::type, NormalizedKey::algorithm, NormalizedKey::length,
                        NormalizedKey::subjectPublicKeyInfo)
                .containsExactly(KeyRequestType.SECRET, KeyAlgorithm.AES, 256, null);
        assertThat(KeyFiles.opened(key))
                .isEqualTo(SecretKeyFiles
                        .pkcs8Shaped(new AlgorithmIdentifier(NISTObjectIdentifiers.aes), aes.getEncoded()));
    }

    @Test
    void normalize_refusesToImportAJceksKeyAsAKeyPair() {
        // given
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.normalize(aesSealedKey, passphrase, KeyRequestType.KEY_PAIR, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.NOT_OF_TYPE.formatted("secret key", "key pair"));
    }

    @Test
    void normalize_refusesAKeyOfAnAlgorithmThePlatformDoesNotSupportAsUnreadable() throws Exception {
        // given
        byte[] file = SecretKeyFiles.sealedKey(pbeStore);
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.normalize(file, passphrase, KeyRequestType.SECRET, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @ParameterizedTest
    @MethodSource("streamsOtherThanTheJdkWrites")
    void read_refusesAStreamOtherThanTheJdkWritesAsUnreadable(byte[] stream) {
        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> JceksSealedKey.read(stream, 0));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @ParameterizedTest
    @MethodSource("offsetsWithoutRoomForAStream")
    void read_refusesAnOffsetThatLeavesNoRoomForAStream(int offset) {
        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> JceksSealedKey.read(aesSealedKey, offset));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @ParameterizedTest
    @MethodSource("contentsOtherThanTheJdkSeals")
    void describe_refusesContentOtherThanTheJdkSealsAsUnreadable(byte[] content) throws Exception {
        // given
        byte[] file = SecretKeyFiles.resealed(aesSealedKey, content);
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(file, passphrase, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void describe_refusesMoreIterationsThanTheFilesBudget() throws Exception {
        // given
        byte[] file = SecretKeyFiles
                .withParameters(aesSealedKey,
                        new PBEParameter(new byte[8], DerivationBudget.FILE_ITERATIONS + 1).getEncoded());
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(file, passphrase, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ITERATION_LIMIT);
    }

    @Test
    void describe_chargesTheSealedKeysIterationsToTheFilesBudget() {
        // given
        BigInteger iterations = JceksSealedKey.read(aesSealedKey, 0).iterations();
        DerivationBudget budget = DerivationBudget.forFile();
        budget.charge(BigInteger.valueOf(DerivationBudget.FILE_ITERATIONS).subtract(iterations).add(BigInteger.ONE));
        Passphrase passphrase = KeyFiles.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(aesSealedKey, passphrase, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ITERATION_LIMIT);
    }

    @ParameterizedTest
    @MethodSource("passphrasesThatDoNotOpenTheKey")
    void describe_refusesAPassphraseThatDoesNotOpenTheKeyAsUnreadable(Passphrase passphrase) {
        // given
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(aesSealedKey, passphrase, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void describe_refusesAFileWithBytesAfterTheSealedKeyAsUnreadable() {
        // given
        byte[] file = Arrays.copyOf(aesSealedKey, aesSealedKey.length + 1);
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(file, passphrase, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    static Stream<Named<byte[]>> stores() {
        return Stream.of(named("an AES key", aesStore), named("a PBE key, sealed as a KeyRep", pbeStore));
    }

    static Stream<Arguments> sealedContents() throws Exception {
        byte[] key = aes.getEncoded();
        return Stream
                .of(arguments(
                        named("a KeyRep of an AES key",
                                SecretKeyFiles.serialized(new KeyRep(KeyRep.Type.SECRET, "AES", "RAW", key))),
                        KeyAlgorithm.AES, null),
                        arguments(
                                named("an AES key named in lower case",
                                        SecretKeyFiles.serialized(new SecretKeySpec(key, "aes"))),
                                KeyAlgorithm.AES, null),
                        arguments(
                                named("an AES key of another length",
                                        SecretKeyFiles.serialized(new SecretKeySpec(new byte[20], "AES"))),
                                null, NISTObjectIdentifiers.aes.getId()),
                        arguments(
                                named("a DESede key",
                                        SecretKeyFiles.serialized(KeyGenerator.getInstance("DESede").generateKey())),
                                null, "DESede"),
                        arguments(
                                named("an HMAC key",
                                        SecretKeyFiles
                                                .serialized(KeyGenerator.getInstance("HmacSHA256").generateKey())),
                                null, "HmacSHA256"));
    }

    static Stream<Named<byte[]>> streamsOtherThanTheJdkWrites() throws Exception {
        byte[] sealed = aesSealedKey;
        // after the 4-byte header come the object's tag and its class's; a class gives its flags after its name and
        // serialVersionUID, then its field count and its fields
        int sealedKeyFlags = SecretKeyFiles.after(sealed, SEALED_KEY_CLASS) + Long.BYTES;
        int sealedObjectFlags = SecretKeyFiles.after(sealed, SEALED_OBJECT_CLASS) + Long.BYTES;
        byte[] longSalt = new DERSequence(
                new ASN1Encodable[]{new DEROctetString(new byte[16]), new ASN1Integer(200_000)})
                .getEncoded(ASN1Encoding.DER);
        return Stream
                .of(named("another class", SecretKeyFiles
                        .replaced(sealed, SEALED_KEY_CLASS, SEALED_KEY_CLASS.replace("Protector", "Protectox"))),
                        named("another serialVersionUID",
                                SecretKeyFiles.withByte(sealed, sealedKeyFlags - 1, sealed[sealedKeyFlags - 1] ^ 1)),
                        named("another field", SecretKeyFiles.replaced(sealed, "encryptedContent", "encryptedContenu")),
                        named("a field of another type", SecretKeyFiles.replaced(sealed, "t\0\2[B", "t\0\2[C")),
                        named("a field fewer",
                                SecretKeyFiles
                                        .withByte(sealed, sealedObjectFlags + 2, sealed[sealedObjectFlags + 2] - 1)),
                        named("another seal algorithm",
                                SecretKeyFiles.replacedLast(sealed, SEAL_ALGORITHM, OTHER_SEAL_ALGORITHM)),
                        named("another parameters algorithm",
                                SecretKeyFiles.replaced(sealed, SEAL_ALGORITHM, OTHER_SEAL_ALGORITHM)),
                        named("block data in a class's annotations",
                                SecretKeyFiles.inserted(sealed, sealedKeyFlags + 3, HexFormat.of().parseHex("770100"))),
                        named("a class that writes its own data",
                                SecretKeyFiles.withByte(sealed, sealedObjectFlags, 0x03)),
                        named("an externalizable class", SecretKeyFiles.withByte(sealed, sealedKeyFlags, 0x0C)),
                        named("a proxy class", SecretKeyFiles.withByte(sealed, 5, 0x7D)),
                        named("another stream version", SecretKeyFiles.withByte(sealed, 3, 0x04)),
                        named("a reset before the object", SecretKeyFiles.inserted(sealed, 4, new byte[]{0x79})),
                        named("a reference to a handle not yet assigned",
                                SecretKeyFiles.replaced(sealed, "q\0~\0\2", "q\0~\0\11")),
                        named("a reference to a class where a string belongs",
                                SecretKeyFiles.replaced(sealed, "q\0~\0\2", "q\0~\0\1")),
                        named("a reference to another class where byte[] belongs",
                                SecretKeyFiles.replaced(sealed, "uq\0~\0\5", "uq\0~\0\1")),
                        named("an array of a negative length", SecretKeyFiles.withParametersLength(sealed, -1)),
                        named("an array longer than the stream",
                                SecretKeyFiles.withParametersLength(sealed, sealed.length)),
                        named("sealing parameters that are not a PBE parameter",
                                SecretKeyFiles.withParameters(sealed, new byte[]{0x05, 0x00})),
                        named("sealing parameters with a salt of another length",
                                SecretKeyFiles.withParameters(sealed, longSalt)),
                        named("sealing parameters in BER",
                                SecretKeyFiles.withParameters(sealed, ber(SecretKeyFiles.parametersOf(sealed)))),
                        named("a truncated stream", Arrays.copyOf(sealed, sealed.length - 1)),
                        named("an empty stream", Arrays.copyOf(sealed, 4)));
    }

    static Stream<Named<Integer>> offsetsWithoutRoomForAStream() {
        return Stream
                .of(named("before the data", -1), named("three bytes before its end", aesSealedKey.length - 3),
                        named("past its end", aesSealedKey.length + 1));
    }

    static Stream<Named<byte[]>> contentsOtherThanTheJdkSeals() throws Exception {
        byte[] key = aes.getEncoded();
        byte[] spec = SecretKeyFiles.serialized(new SecretKeySpec(key, "AES"));
        return Stream
                .of(named("a KeyRep of a public key",
                        SecretKeyFiles.serialized(new KeyRep(KeyRep.Type.PUBLIC, "AES", "RAW", key))),
                        named("a KeyRep in another format",
                                SecretKeyFiles.serialized(new KeyRep(KeyRep.Type.SECRET, "AES", "PKCS#8", key))),
                        named("another object", SecretKeyFiles.serialized(BigInteger.TEN)),
                        named("a string", SecretKeyFiles.serialized("AES")),
                        named("a key followed by more", Arrays.copyOf(spec, spec.length + 1)),
                        named("no stream at all", new byte[16]));
    }

    static Stream<Named<Passphrase>> passphrasesThatDoNotOpenTheKey() {
        return Stream
                .of(named("a wrong one", new Passphrase("not the passphrase".toCharArray())), named("none", null),
                        named("one that is not ASCII", new Passphrase("pässwörd".toCharArray())));
    }

    /** A DER sequence of short length encoded again with an indefinite length, which BER allows and DER does not. */
    private static byte[] ber(byte[] der) {
        byte[] ber = new byte[der.length + 2];
        ber[0] = der[0];
        ber[1] = (byte) 0x80;
        System.arraycopy(der, 2, ber, 2, der.length - 2);
        return ber;
    }
}
