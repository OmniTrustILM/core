package com.otilm.core.container;

import com.otilm.api.exception.ValidationException;
import com.otilm.core.key.normalization.DerivationBudget;
import com.otilm.core.key.normalization.KeyFileRefusal;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import java.util.function.Supplier;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.util.Strings;

/**
 * The MAC that protects a PKCS#12 file's integrity, verified with the passphrase before the file's content is read: the
 * classic MAC, the PKCS#12 key derivation and an HMAC over SHA-1 or SHA-2, or PBMAC1, PBKDF2 and an HMAC over SHA-2.
 * Each key derivation is charged to the file's budget before it runs.
 *
 * <p>
 * The key is derived with Bouncy Castle's lightweight derivations, which take the password as bytes, so that an empty
 * password is derived as each writer encodes it.
 * </p>
 */
final class Pkcs12Mac {

    /** The digests of the classic MAC: SHA-1 and SHA-2. */
    private static final Map<ASN1ObjectIdentifier, Supplier<Digest>> CLASSIC_MAC_DIGESTS = Map
            .of(OIWObjectIdentifiers.idSHA1, DigestFactory::createSHA1, NISTObjectIdentifiers.id_sha224,
                    DigestFactory::createSHA224, NISTObjectIdentifiers.id_sha256, DigestFactory::createSHA256,
                    NISTObjectIdentifiers.id_sha384, DigestFactory::createSHA384, NISTObjectIdentifiers.id_sha512,
                    DigestFactory::createSHA512, NISTObjectIdentifiers.id_sha512_224, DigestFactory::createSHA512_224,
                    NISTObjectIdentifiers.id_sha512_256, DigestFactory::createSHA512_256);

    /** The HMACs PBMAC1 may use for its PBKDF2 and its MAC alike: over SHA-224, SHA-256, SHA-384 and SHA-512. */
    private static final Map<ASN1ObjectIdentifier, Supplier<Digest>> PBMAC1_HMACS = Map
            .of(PKCSObjectIdentifiers.id_hmacWithSHA224, DigestFactory::createSHA224,
                    PKCSObjectIdentifiers.id_hmacWithSHA256, DigestFactory::createSHA256,
                    PKCSObjectIdentifiers.id_hmacWithSHA384, DigestFactory::createSHA384,
                    PKCSObjectIdentifiers.id_hmacWithSHA512, DigestFactory::createSHA512);

    /** The longest PBMAC1 key, an HMAC-SHA512 key; beyond its iterations, PBKDF2's work grows with the key's length. */
    private static final BigInteger MAXIMUM_PBMAC1_KEY_BYTES = BigInteger.valueOf(64);

    /** An empty password as OpenSSL and the JDK derive a PKCS#12 key from it: its BMPString terminator alone. */
    private static final int TERMINATOR_BYTES = 2;

    private Pkcs12Mac() {
    }

    /**
     * Verifies the file's MAC with the passphrase; a file without a MAC is read without an integrity check. An empty
     * passphrase is tried for the classic MAC as its BMPString terminator alone, as OpenSSL and the JDK encode an empty
     * password, then as no bytes at all, as Bouncy Castle does.
     *
     * @param mac the file's MAC, or {@code null} when it has none
     * @param authenticatedSafe the content the MAC covers
     * @param password the passphrase's characters, none for an empty passphrase
     * @param budget the budget of the file, charged each key derivation before it runs
     * @return how the file's integrity was verified
     * @throws ValidationException when the MAC does not verify, or its scheme is not one of those above
     */
    static Integrity verify(MacData mac, byte[] authenticatedSafe, char[] password, DerivationBudget budget) {
        if (mac == null) {
            return Integrity.NONE;
        }
        ASN1ObjectIdentifier scheme = mac.getMac().getAlgorithmId().getAlgorithm();
        if (PKCSObjectIdentifiers.id_PBMAC1.equals(scheme)) {
            return verified(pbmac1Verifies(mac, authenticatedSafe, password, budget), Integrity.PASSPHRASE);
        }
        Supplier<Digest> digest = CLASSIC_MAC_DIGESTS.get(scheme);
        if (digest == null) {
            throw ContainerRefusal.integrityUnsupported(scheme.getId());
        }
        if (password.length > 0) {
            byte[] bmpString = PBEParametersGenerator.PKCS12PasswordToBytes(password);
            try {
                return verified(classicMacVerifies(mac, digest, authenticatedSafe, bmpString, budget),
                        Integrity.PASSPHRASE);
            } finally {
                Arrays.fill(bmpString, (byte) 0);
            }
        }
        if (classicMacVerifies(mac, digest, authenticatedSafe, new byte[TERMINATOR_BYTES], budget)) {
            return Integrity.TERMINATED_EMPTY_PASSWORD;
        }
        return verified(classicMacVerifies(mac, digest, authenticatedSafe, new byte[0], budget), Integrity.PASSPHRASE);
    }

    private static Integrity verified(boolean verified, Integrity integrity) {
        if (!verified) {
            throw ContainerRefusal.integrityFailed();
        }
        return integrity;
    }

    /** Whether the classic MAC, the PKCS#12 key derivation and an HMAC, verifies with the password's bytes. */
    private static boolean classicMacVerifies(MacData mac, Supplier<Digest> digest, byte[] authenticatedSafe,
            byte[] password, DerivationBudget budget) {
        budget.charge(mac.getIterationCount());
        return computed(() -> {
            Digest derivation = digest.get();
            PKCS12ParametersGenerator generator = new PKCS12ParametersGenerator(derivation);
            generator.init(password, mac.getSalt(), mac.getIterationCount().intValueExact());
            return macVerifies(new HMac(digest.get()),
                    (KeyParameter) generator.generateDerivedMacParameters(derivation.getDigestSize() * Byte.SIZE),
                    authenticatedSafe, mac.getMac().getDigest());
        });
    }

    /**
     * Whether PBMAC1, PBKDF2 over the password's UTF-8 bytes and an HMAC, verifies; its parameters are checked first.
     */
    private static boolean pbmac1Verifies(MacData mac, byte[] authenticatedSafe, char[] password,
            DerivationBudget budget) {
        PBMAC1Params parameters = integrityParameters(mac.getMac().getAlgorithmId().getParameters(),
                PBMAC1Params::getInstance);
        AlgorithmIdentifier derivation = parameters.getKeyDerivationFunc();
        if (!PKCSObjectIdentifiers.id_PBKDF2.equals(derivation.getAlgorithm())) {
            throw ContainerRefusal.integrityUnsupported(derivation.getAlgorithm().getId());
        }
        PBKDF2Params pbkdf2 = integrityParameters(derivation.getParameters(), PBKDF2Params::getInstance);
        Supplier<Digest> prf = pbmac1Hmac(pbkdf2.getPrf());
        Supplier<Digest> hmac = pbmac1Hmac(parameters.getMessageAuthScheme());
        BigInteger keyBytes = pbkdf2.getKeyLength();
        if (keyBytes == null || keyBytes.signum() <= 0 || keyBytes.compareTo(MAXIMUM_PBMAC1_KEY_BYTES) > 0) {
            throw ContainerRefusal.integrityFailed();
        }
        budget.charge(pbkdf2.getIterationCount());
        return computed(() -> {
            byte[] utf8 = Strings.toUTF8ByteArray(password);
            try {
                PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(prf.get());
                generator.init(utf8, pbkdf2.getSalt(), pbkdf2.getIterationCount().intValueExact());
                return macVerifies(new HMac(hmac.get()),
                        (KeyParameter) generator.generateDerivedMacParameters(keyBytes.intValueExact() * Byte.SIZE),
                        authenticatedSafe, mac.getMac().getDigest());
            } finally {
                Arrays.fill(utf8, (byte) 0);
            }
        });
    }

    private static Supplier<Digest> pbmac1Hmac(AlgorithmIdentifier hmac) {
        Supplier<Digest> digest = PBMAC1_HMACS.get(hmac.getAlgorithm());
        if (digest == null) {
            throw ContainerRefusal.integrityUnsupported(hmac.getAlgorithm().getId());
        }
        return digest;
    }

    /**
     * Whether the MAC keyed as given over the content is the expected one; the key is overwritten once the MAC holds
     * it.
     */
    private static boolean macVerifies(HMac mac, KeyParameter key, byte[] content, byte[] expected) {
        mac.init(key);
        Arrays.fill(key.getKey(), (byte) 0);
        mac.update(content, 0, content.length);
        byte[] computed = new byte[mac.getMacSize()];
        mac.doFinal(computed, 0);
        return MessageDigest.isEqual(computed, expected);
    }

    /**
     * The outcome of a MAC computation. What Bouncy Castle cannot compute, such as a passphrase with no UTF-8 encoding,
     * fails the integrity check; it signals that with a range of unchecked exceptions, each meaning the same here.
     */
    private static boolean computed(BooleanSupplier verification) {
        try {
            return verification.getAsBoolean();
        } catch (RuntimeException e) {
            throw ContainerRefusal.integrityFailed();
        }
    }

    /** Integrity parameters Bouncy Castle cannot read make the file damaged, which fails its integrity check. */
    private static <T> T integrityParameters(ASN1Encodable encoded, Function<Object, T> reader) {
        T parameters;
        try {
            parameters = reader.apply(encoded);
        } catch (RuntimeException e) {
            throw ContainerRefusal.integrityFailed();
        }
        if (parameters == null) {
            throw ContainerRefusal.integrityFailed();
        }
        return parameters;
    }

    /** How a file's integrity was verified. */
    enum Integrity {

        /** The file has no MAC. */
        NONE,

        /** The MAC verified with the passphrase, or with an empty password encoded as no bytes at all. */
        PASSPHRASE,

        /** The MAC verified with an empty password encoded as its terminator alone, as OpenSSL and the JDK do. */
        TERMINATED_EMPTY_PASSWORD;

        boolean verified() {
            return this != NONE;
        }

        /** Why a safe or a protected key does not open: once the MAC verified, it is under another passphrase. */
        ValidationException notOpened() {
            return verified() ? ContainerRefusal.twoPassphrases() : KeyFileRefusal.unreadableKey();
        }
    }
}
