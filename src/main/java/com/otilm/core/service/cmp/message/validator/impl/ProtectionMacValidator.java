package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.validator.Validator;
import com.otilm.core.service.cmp.registration.CmpRegistrationResolver;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Validator of Password-Based MAC protection of {@link PKIMessage}.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3.1">Shared secret Information</a>
 */
public class ProtectionMacValidator implements Validator<PKIMessage, Void> {

    // Guardrails on the client-supplied PBMParameter, enforced before the MAC is computed and — in
    // registration mode — before the challenge gate takes its row lock. The iteration count drives a digest
    // loop, so an unbounded value would burn CPU while holding the lock. These are protocol-hardening bounds,
    // not operator settings.
    static final int MAX_PBM_ITERATION_COUNT = 100_000;
    static final int MAX_PBM_SALT_LENGTH = 1024;

    private static final Set<String> ALLOWED_OWF_OIDS = Set
            .of(OIWObjectIdentifiers.idSHA1.getId(), NISTObjectIdentifiers.id_sha256.getId(),
                    NISTObjectIdentifiers.id_sha384.getId(), NISTObjectIdentifiers.id_sha512.getId());
    private static final Set<String> ALLOWED_MAC_OIDS = Set
            .of(
                    // Both the IPSEC/ISAKMP (IANA) and PKCS#5 forms of HMAC-SHA1; RFC 4210 clients and the platform's
                    // own shared-secret response strategy use the PKCS form.
                    IANAObjectIdentifiers.hmacSHA1.getId(), PKCSObjectIdentifiers.id_hmacWithSHA1.getId(),
                    PKCSObjectIdentifiers.id_hmacWithSHA256.getId(), PKCSObjectIdentifiers.id_hmacWithSHA384.getId(),
                    PKCSObjectIdentifiers.id_hmacWithSHA512.getId());

    /**
     * see flow at rfc4210, section 5.1.3.1 id-PasswordBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 13}
     * PBMParameter ::= SEQUENCE { salt OCTET STRING, owf AlgorithmIdentifier, iterationCount INTEGER, mac
     * AlgorithmIdentifier }
     *
     * @param message subject (its protection and header) for validation
     * @return null if validation is ok
     * @throws CmpProcessingException if validation has failed
     */
    @Override
    public Void validate(PKIMessage message, ConfigurationContext configuration) throws CmpBaseException {
        ASN1OctetString tid = message.getHeader().getTransactionID();
        // Before anything that iterates the PBM parameters — the gate's row lock included — bound them.
        validatePbmParameters(message, tid);
        // The registration gate runs on the incoming request only. A response (validateOut) is MAC-validated
        // through the normal path below, keyed by the matched registration's challenge via getSharedSecret().
        if (configuration.isRegistrationMode()) {
            if (isRegistrationMacBody(message)) {
                // The gate (via the context) does the senderKID resolution, MAC check through this predicate,
                // failed-attempt counting and lockout, and throws the single generic rejection on any failure.
                configuration.verifyRegistrationMacProtection(message, password -> {
                    try {
                        return matchesMac(message, password);
                    } catch (Exception e) {
                        return false;
                    }
                });
                return null;
            }
            // Registration mode stores no shared secret. The only other legitimate MAC is a response, keyed
            // below by the matched registration's challenge (getSharedSecret returns it once a request has
            // matched). An empty key means nothing matched — e.g. a MAC-protected revocation, which
            // registration mode does not authenticate — so it must never be allowed to verify a forged MAC.
            if (configuration.getSharedSecret().length == 0) {
                throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                        CmpRegistrationResolver.REGISTRATION_REJECTION);
            }
        }
        try {
            if (!matchesMac(message, configuration.getSharedSecret())) {
                throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                        "mac validation: check of PasswordBasedMac protection failed");
            }
        } catch (CmpBaseException e) {
            throw e;
        } catch (Exception e) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck, e.getLocalizedMessage());
        }
        return null;// validation is ok
    }

    /**
     * Bodies whose MAC registration mode authenticates against a pre-registration challenge: the enrolment and rekey
     * requests (ir/cr/kur) and the async follow-ups of a registration exchange (pollReq/certConf). Every other MAC body
     * (e.g. a revocation) has no registration challenge to key it and is rejected below.
     */
    private static boolean isRegistrationMacBody(PKIMessage message) {
        int bodyType = message.getBody().getType();
        return bodyType == PKIBody.TYPE_INIT_REQ || bodyType == PKIBody.TYPE_CERT_REQ
                || bodyType == PKIBody.TYPE_KEY_UPDATE_REQ || bodyType == PKIBody.TYPE_POLL_REQ
                || bodyType == PKIBody.TYPE_CERT_CONFIRM;
    }

    /**
     * Rejects a message whose Password-Based MAC parameters fall outside the accepted bounds: a non-positive or
     * over-maximum iteration count, an oversized salt, or a one-way-function / MAC algorithm outside the allowlist.
     * Enforced before the MAC computation (and the registration gate's row lock), so a hostile iteration count cannot
     * drive the digest loop while holding resources.
     */
    static void validatePbmParameters(PKIMessage message, ASN1OctetString tid) throws CmpProcessingException {
        PBMParameter pbmParameter;
        try {
            pbmParameter = PBMParameter.getInstance(message.getHeader().getProtectionAlg().getParameters());
        } catch (RuntimeException e) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                    "PBM protection parameters are malformed");
        }
        if (pbmParameter == null) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                    "PBM protection parameters are missing");
        }
        BigInteger iterationCount = pbmParameter.getIterationCount().getValue();
        if (iterationCount.signum() <= 0 || iterationCount.compareTo(BigInteger.valueOf(MAX_PBM_ITERATION_COUNT)) > 0) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                    "PBM iteration count is outside the permitted range");
        }
        if (pbmParameter.getSalt().getOctets().length > MAX_PBM_SALT_LENGTH) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                    "PBM salt exceeds the permitted size");
        }
        if (!ALLOWED_OWF_OIDS.contains(pbmParameter.getOwf().getAlgorithm().getId())) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badAlg,
                    "PBM one-way function algorithm is not permitted");
        }
        if (!ALLOWED_MAC_OIDS.contains(pbmParameter.getMac().getAlgorithm().getId())) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badAlg, "PBM MAC algorithm is not permitted");
        }
    }

    /**
     * Whether the message's Password-Based MAC verifies under {@code passwordAsBytes}, computed per RFC 4210 §5.1.3.1
     * from the message's own PBMParameter (salt, owf, iteration count, mac algorithm). The pure computation, reusable
     * both with the profile shared secret and with a registration challenge.
     */
    static boolean matchesMac(PKIMessage message, byte[] passwordAsBytes)
            throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException {
        PKIHeader header = message.getHeader();
        PBMParameter pbmParameter = PBMParameter.getInstance(header.getProtectionAlg().getParameters());
        byte[] salt = pbmParameter.getSalt().getOctets();
        AlgorithmIdentifier owf = pbmParameter.getOwf();
        // The salted secret is the input to the first iteration; the output of the final iteration
        // (called "BASEKEY", size "H") forms the symmetric key.
        byte[] basekey = new byte[passwordAsBytes.length + salt.length];
        System.arraycopy(passwordAsBytes, 0, basekey, 0, passwordAsBytes.length);
        System.arraycopy(salt, 0, basekey, passwordAsBytes.length, salt.length);
        MessageDigest dig = MessageDigest.getInstance(owf.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        for (int i = 0; i < pbmParameter.getIterationCount().getValue().intValue(); i++) {
            basekey = dig.digest(basekey);
            dig.reset();
        }
        String macId = pbmParameter.getMac().getAlgorithm().getId();
        Mac mac = Mac.getInstance(macId, BouncyCastleProvider.PROVIDER_NAME);
        mac.init(new SecretKeySpec(basekey, macId));
        mac.update(new ProtectedPart(header, message.getBody()).getEncoded(ASN1Encoding.DER));
        // -- check counted bytes (mac) vs. bytes from protection field
        return Arrays.equals(mac.doFinal(), message.getProtection().getBytes());
    }
}
