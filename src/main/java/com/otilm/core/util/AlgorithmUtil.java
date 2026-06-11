package com.otilm.core.util;

import com.otilm.api.exception.ValidationException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class AlgorithmUtil {

    private static final Logger logger = LoggerFactory.getLogger(AlgorithmUtil.class);

    public static String getSignatureAlgorithmName(String digestAlgorithmOID, String privateKeyAlgorithm) throws NoSuchAlgorithmException {
        // Map digest algorithm OID to digest algorithm name
        String digestAlgorithm = getDigestAlgorithm(digestAlgorithmOID);
        // Determine signature algorithm name based on private key algorithm and digest algorithm
        String signatureAlgorithm;
        if (privateKeyAlgorithm.equals("RSA")) {
            signatureAlgorithm = digestAlgorithm + "withRSA";
        } else if (privateKeyAlgorithm.equals("EC") || privateKeyAlgorithm.equals("ECDSA")) {
            signatureAlgorithm = digestAlgorithm + "withECDSA";
        } else {
            throw new NoSuchAlgorithmException("Unsupported private key algorithm: " + privateKeyAlgorithm);
        }

        return signatureAlgorithm;
    }

    public static String getDigestAlgorithm(String digestAlgorithmOID) throws NoSuchAlgorithmException {
        // Try to identify the digest algorithm from the bouncy castle provider
        try {
            MessageDigest md = MessageDigest.getInstance(
                    digestAlgorithmOID, BouncyCastleProvider.PROVIDER_NAME);
            String digestAlgorithmName = md.getAlgorithm();
            if(!List.of("SHA-1", "SHA-256", "SHA-384", "SHA-512", "MD5").contains(digestAlgorithmName)) {
                throw new ValidationException("Unsupported digest algorithm");
            }
            return digestAlgorithmName;
        } catch (Exception e) {
            logger.warn("Unable to find algorithm from the Bouncycastle provider");
        }
        // If the algorithm is not found then fallback to the below IOD identification since
        // they are not available in the bouncycastle provider
        if (digestAlgorithmOID.equals("1.2.840.113549.1.1.5")) { // SHA1 OID
            return "SHA-1";
        } else if (digestAlgorithmOID.equals("2.16.840.1.101.3.4.2.1")) { // SHA256 OID
            return "SHA-256";
        } else if (digestAlgorithmOID.equals("2.16.840.1.101.3.4.2.2")) { // SHA384 OID
            return "SHA-384";
        } else if (digestAlgorithmOID.equals("2.16.840.1.101.3.4.2.3")) { // SHA512 OID
            return "SHA-512";
        } else if(digestAlgorithmOID.equals("1.2.840.10045.4.3.2")) {
            return "SHA256";
        } else if(digestAlgorithmOID.equals("1.2.840.10045.4.3.3")) {
            return "SHA384";
        } else if (digestAlgorithmOID.equals("1.2.840.10045.4.3.4")) {
            return "SHA512";
        } else {
            throw new NoSuchAlgorithmException("Unsupported digest algorithm OID: " + digestAlgorithmOID);
        }
    }

}
