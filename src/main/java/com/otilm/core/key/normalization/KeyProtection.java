package com.otilm.core.key.normalization;

import java.math.BigInteger;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.ScryptParams;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * The protection an uploaded key file may use, and the work a scheme may demand, checked before any key is derived:
 * PBES2 with a SHA-2 PRF or scrypt, PBES1, the PKCS#12 schemes, and the common OpenSSL traditional PEM ciphers.
 */
final class KeyProtection {

    static final int MAXIMUM_ITERATIONS = 10_000_000;

    /** The memory scrypt may take, 128·r·N bytes: OpenSSL's own default limit, which the files it writes stay under. */
    static final int MAXIMUM_SCRYPT_MEMORY = 32 * 1024 * 1024;

    static final int MAXIMUM_SCRYPT_PARALLELIZATION = 1;

    private static final String ITERATION_LIMIT = "key derivation iteration";

    private static final String SCRYPT_MEMORY_LIMIT = "scrypt memory";

    private static final String SCRYPT_MEMORY_MAXIMUM = (MAXIMUM_SCRYPT_MEMORY >> 20) + " MiB";

    private static final String SCRYPT_PARALLELIZATION_LIMIT = "scrypt parallelization";

    private static final BigInteger SCRYPT_BLOCK_BYTES = BigInteger.valueOf(128);

    /** The SHA-2 PRFs Bouncy Castle's PKCS#8 decryption reads; it reads neither SHA-512/224 nor SHA-512/256. */
    private static final Set<ASN1ObjectIdentifier> PBKDF2_PRFS = Set
            .of(PKCSObjectIdentifiers.id_hmacWithSHA224, PKCSObjectIdentifiers.id_hmacWithSHA256,
                    PKCSObjectIdentifiers.id_hmacWithSHA384, PKCSObjectIdentifiers.id_hmacWithSHA512);

    private static final Set<ASN1ObjectIdentifier> PBES2_CIPHERS = Set
            .of(NISTObjectIdentifiers.id_aes128_CBC, NISTObjectIdentifiers.id_aes192_CBC,
                    NISTObjectIdentifiers.id_aes256_CBC, PKCSObjectIdentifiers.des_EDE3_CBC);

    private static final Set<ASN1ObjectIdentifier> PBES1_SCHEMES = Set
            .of(PKCSObjectIdentifiers.pbeWithMD2AndDES_CBC, PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC,
                    PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC, PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC,
                    PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC);

    private static final Set<ASN1ObjectIdentifier> PKCS12_SCHEMES = Set
            .of(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4, PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC4,
                    PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
                    PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC,
                    PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC, PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC);

    private static final Set<String> TRADITIONAL_CIPHERS = Set
            .of("AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "DES-EDE3-CBC", "DES-CBC");

    /** What a cipher name from the file may look like to be repeated in a refusal. */
    private static final Pattern CIPHER_NAME = Pattern.compile("[A-Za-z0-9-]{1,32}");

    private KeyProtection() {
    }

    /**
     * Refuses a PKCS#8 protection outside the accepted set, naming the part that is not accepted, and one that demands
     * more work than its ceiling allows.
     *
     * @param protection the envelope's encryption algorithm
     */
    static void requireAccepted(AlgorithmIdentifier protection) {
        ASN1ObjectIdentifier scheme = protection.getAlgorithm();
        if (PKCSObjectIdentifiers.id_PBES2.equals(scheme)) {
            requireAcceptedPbes2(parameters(protection.getParameters(), PBES2Parameters::getInstance));
        } else if (PBES1_SCHEMES.contains(scheme)) {
            requireIterationsWithin(
                    parameters(protection.getParameters(), PBEParameter::getInstance).getIterationCount());
        } else if (PKCS12_SCHEMES.contains(scheme)) {
            requireIterationsWithin(
                    parameters(protection.getParameters(), PKCS12PBEParams::getInstance).getIterations());
        } else {
            throw KeyFileRefusal.unsupportedProtection(scheme.getId());
        }
    }

    /**
     * Whether the scheme is PBES1, whose key derivation takes the passphrase's bytes as the file's writer encoded them.
     *
     * @param scheme the envelope's encryption algorithm
     * @return whether it is one of the PBES1 schemes
     */
    static boolean isPbes1(ASN1ObjectIdentifier scheme) {
        return PBES1_SCHEMES.contains(scheme);
    }

    /**
     * Refuses an OpenSSL traditional PEM cipher outside the accepted set, naming it when the name is plain enough to
     * repeat. The scheme demands no work to bound.
     *
     * @param cipher the cipher the {@code DEK-Info} header names
     */
    static void requireAcceptedCipher(String cipher) {
        if (!TRADITIONAL_CIPHERS.contains(cipher)) {
            throw KeyFileRefusal
                    .unsupportedProtection(CIPHER_NAME.matcher(cipher).matches() ? cipher : "an unrecognized cipher");
        }
    }

    private static void requireAcceptedPbes2(PBES2Parameters parameters) {
        KeyDerivationFunc derivation = parameters.getKeyDerivationFunc();
        ASN1ObjectIdentifier function = derivation.getAlgorithm();
        if (PKCSObjectIdentifiers.id_PBKDF2.equals(function)) {
            PBKDF2Params pbkdf2 = parameters(derivation.getParameters(), PBKDF2Params::getInstance);
            ASN1ObjectIdentifier prf = pbkdf2.getPrf().getAlgorithm();
            if (!PBKDF2_PRFS.contains(prf)) {
                throw KeyFileRefusal.unsupportedProtection(prf.getId());
            }
            requireIterationsWithin(pbkdf2.getIterationCount());
        } else if (MiscObjectIdentifiers.id_scrypt.equals(function)) {
            requireScryptCostWithin(parameters(derivation.getParameters(), ScryptParams::getInstance));
        } else {
            throw KeyFileRefusal.unsupportedProtection(function.getId());
        }
        ASN1ObjectIdentifier cipher = parameters.getEncryptionScheme().getAlgorithm();
        if (!PBES2_CIPHERS.contains(cipher)) {
            throw KeyFileRefusal.unsupportedProtection(cipher.getId());
        }
    }

    private static void requireIterationsWithin(BigInteger iterations) {
        if (exceeds(iterations, MAXIMUM_ITERATIONS)) {
            throw KeyFileRefusal.limitExceeded(ITERATION_LIMIT, MAXIMUM_ITERATIONS);
        }
    }

    private static void requireScryptCostWithin(ScryptParams scrypt) {
        BigInteger memory = SCRYPT_BLOCK_BYTES.multiply(scrypt.getBlockSize()).multiply(scrypt.getCostParameter());
        if (exceeds(memory, MAXIMUM_SCRYPT_MEMORY)) {
            throw KeyFileRefusal.limitExceeded(SCRYPT_MEMORY_LIMIT, SCRYPT_MEMORY_MAXIMUM);
        }
        if (exceeds(scrypt.getParallelizationParameter(), MAXIMUM_SCRYPT_PARALLELIZATION)) {
            throw KeyFileRefusal.limitExceeded(SCRYPT_PARALLELIZATION_LIMIT, MAXIMUM_SCRYPT_PARALLELIZATION);
        }
    }

    private static boolean exceeds(BigInteger value, int maximum) {
        return value.compareTo(BigInteger.valueOf(maximum)) > 0;
    }

    /**
     * Parameters Bouncy Castle cannot read make the file damaged; it signals that with a range of unchecked exceptions,
     * each meaning the same here.
     */
    private static <T> T parameters(ASN1Encodable encoded, Function<Object, T> reader) {
        T parameters;
        try {
            parameters = reader.apply(encoded);
        } catch (RuntimeException e) {
            throw KeyFileRefusal.unreadableKey();
        }
        if (parameters == null) {
            throw KeyFileRefusal.unreadableKey();
        }
        return parameters;
    }
}
