package com.otilm.core.key.normalization;

import java.math.BigInteger;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
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
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.util.DigestFactory;

/**
 * The protection an uploaded key file may use, and the work a scheme demands, checked before any key is derived: PBES2
 * with a SHA-2 PRF or scrypt, PBES1, the PKCS#12 schemes, the common OpenSSL traditional PEM ciphers, and the JDK's own
 * JKS and JCEKS protections. The work of PBES2, PBES1, the PKCS#12 schemes and JCEKS is charged to the file's
 * derivation budget; a traditional PEM cipher and JKS derive their key at a fixed cost, which is not charged.
 */
public final class KeyProtection {

    /** The memory scrypt may take, 128·r·N bytes: OpenSSL's own default limit, which the files it writes stay under. */
    static final int MAXIMUM_SCRYPT_MEMORY = 32 * 1024 * 1024;

    static final int MAXIMUM_SCRYPT_PARALLELIZATION = 1;

    private static final String SCRYPT_MEMORY_LIMIT = "scrypt memory";

    private static final String SCRYPT_MEMORY_MAXIMUM = (MAXIMUM_SCRYPT_MEMORY >> 20) + " MiB";

    private static final String SCRYPT_PARALLELIZATION_LIMIT = "scrypt parallelization";

    private static final BigInteger SCRYPT_BLOCK_BYTES = BigInteger.valueOf(128);

    /** The most blocks of 128 bytes the memory ceiling holds, which bounds the block size and the cost alike. */
    private static final int MAXIMUM_SCRYPT_BLOCKS = MAXIMUM_SCRYPT_MEMORY / SCRYPT_BLOCK_BYTES.intValue();

    /**
     * The SHA-2 PRFs Bouncy Castle's PKCS#8 decryption reads, each with the digest it is an HMAC over; it reads neither
     * SHA-512/224 nor SHA-512/256.
     */
    static final Map<ASN1ObjectIdentifier, Supplier<Digest>> PBKDF2_PRFS = Map
            .of(PKCSObjectIdentifiers.id_hmacWithSHA224, DigestFactory::createSHA224,
                    PKCSObjectIdentifiers.id_hmacWithSHA256, DigestFactory::createSHA256,
                    PKCSObjectIdentifiers.id_hmacWithSHA384, DigestFactory::createSHA384,
                    PKCSObjectIdentifiers.id_hmacWithSHA512, DigestFactory::createSHA512);

    /** The ciphers of PBES2. */
    static final Map<ASN1ObjectIdentifier, Pbes2Cipher> PBES2_CIPHERS = Map
            .of(NISTObjectIdentifiers.id_aes128_CBC, new Pbes2Cipher("AES", 16), NISTObjectIdentifiers.id_aes192_CBC,
                    new Pbes2Cipher("AES", 24), NISTObjectIdentifiers.id_aes256_CBC, new Pbes2Cipher("AES", 32),
                    PKCSObjectIdentifiers.des_EDE3_CBC, new Pbes2Cipher("DESede", 24));

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
     * Refuses a protection outside the accepted set, naming the part that is not accepted, and one over the scrypt
     * ceilings; then charges its key derivation to the budget, which refuses it once the file's share is spent.
     *
     * @param protection the encryption algorithm of a protected key or of a PKCS#12 safe
     * @param budget the budget of the file the protection is part of
     */
    public static void requireAccepted(AlgorithmIdentifier protection, DerivationBudget budget) {
        budget.charge(acceptedIterations(protection));
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
     * Whether the scheme is one of the PKCS#12 schemes, whose key derivation takes the passphrase as a BMPString.
     *
     * @param scheme the envelope's encryption algorithm
     * @return whether it is one of the PKCS#12 schemes
     */
    static boolean isPkcs12(ASN1ObjectIdentifier scheme) {
        return PKCS12_SCHEMES.contains(scheme);
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

    /** The iterations the protection's key derivation takes, once every part of the protection is accepted. */
    private static BigInteger acceptedIterations(AlgorithmIdentifier protection) {
        ASN1ObjectIdentifier scheme = protection.getAlgorithm();
        if (PKCSObjectIdentifiers.id_PBES2.equals(scheme)) {
            return acceptedPbes2Iterations(parameters(protection.getParameters(), PBES2Parameters::getInstance));
        }
        if (PBES1_SCHEMES.contains(scheme)) {
            return parameters(protection.getParameters(), PBEParameter::getInstance).getIterationCount();
        }
        if (PKCS12_SCHEMES.contains(scheme)) {
            return parameters(protection.getParameters(), PKCS12PBEParams::getInstance).getIterations();
        }
        if (JavaKeyStoreProtection.JKS.equals(scheme)) {
            return BigInteger.ZERO;
        }
        if (JavaKeyStoreProtection.JCEKS.equals(scheme)) {
            return parameters(protection.getParameters(), PBEParameter::getInstance).getIterationCount();
        }
        throw KeyFileRefusal.unsupportedProtection(scheme.getId());
    }

    private static BigInteger acceptedPbes2Iterations(PBES2Parameters parameters) {
        KeyDerivationFunc derivation = parameters.getKeyDerivationFunc();
        ASN1ObjectIdentifier function = derivation.getAlgorithm();
        BigInteger iterations;
        if (PKCSObjectIdentifiers.id_PBKDF2.equals(function)) {
            iterations = acceptedPbkdf2Iterations(parameters(derivation.getParameters(), PBKDF2Params::getInstance));
        } else if (MiscObjectIdentifiers.id_scrypt.equals(function)) {
            iterations = acceptedScryptIterations(parameters(derivation.getParameters(), ScryptParams::getInstance));
        } else {
            throw KeyFileRefusal.unsupportedProtection(function.getId());
        }
        ASN1ObjectIdentifier cipher = parameters.getEncryptionScheme().getAlgorithm();
        if (!PBES2_CIPHERS.containsKey(cipher)) {
            throw KeyFileRefusal.unsupportedProtection(cipher.getId());
        }
        return iterations;
    }

    private static BigInteger acceptedPbkdf2Iterations(PBKDF2Params pbkdf2) {
        ASN1ObjectIdentifier prf = pbkdf2.getPrf().getAlgorithm();
        if (!PBKDF2_PRFS.containsKey(prf)) {
            throw KeyFileRefusal.unsupportedProtection(prf.getId());
        }
        return pbkdf2.getIterationCount();
    }

    /**
     * scrypt within its memory and parallelization ceilings, its work counted as r·N·p iterations. The file states the
     * parameters as integers of any size and sign, so each is held between 1 and its ceiling before any is multiplied;
     * one below 1 makes the protection damaged.
     */
    private static BigInteger acceptedScryptIterations(ScryptParams scrypt) {
        BigInteger blockSize = scrypt.getBlockSize();
        BigInteger cost = scrypt.getCostParameter();
        BigInteger parallelization = scrypt.getParallelizationParameter();
        if (belowOne(blockSize) || belowOne(cost) || belowOne(parallelization)) {
            throw KeyFileRefusal.unreadableKey();
        }
        if (exceeds(blockSize, MAXIMUM_SCRYPT_BLOCKS) || exceeds(cost, MAXIMUM_SCRYPT_BLOCKS)) {
            throw KeyFileRefusal.limitExceeded(SCRYPT_MEMORY_LIMIT, SCRYPT_MEMORY_MAXIMUM);
        }
        if (exceeds(parallelization, MAXIMUM_SCRYPT_PARALLELIZATION)) {
            throw KeyFileRefusal.limitExceeded(SCRYPT_PARALLELIZATION_LIMIT, MAXIMUM_SCRYPT_PARALLELIZATION);
        }
        BigInteger blocks = blockSize.multiply(cost);
        if (exceeds(SCRYPT_BLOCK_BYTES.multiply(blocks), MAXIMUM_SCRYPT_MEMORY)) {
            throw KeyFileRefusal.limitExceeded(SCRYPT_MEMORY_LIMIT, SCRYPT_MEMORY_MAXIMUM);
        }
        return blocks.multiply(parallelization);
    }

    private static boolean belowOne(BigInteger value) {
        return value.signum() < 1;
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

    /**
     * A cipher of PBES2: a block cipher in CBC mode with PKCS#5 padding.
     *
     * @param algorithm the cipher's JCA name
     * @param keyBytes the length of its key
     */
    record Pbes2Cipher(String algorithm, int keyBytes) {
    }
}
