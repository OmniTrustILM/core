package com.czertainly.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.message.validator.Validator;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Validator of Password-Based MAC protection of {@link PKIMessage}.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3.1">Shared secret Information</a>
 */
public class ProtectionMacValidator implements Validator<PKIMessage, Void> {

    /**
     * see flow at rfc4210, section 5.1.3.1
     * id-PasswordBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 13}
     * PBMParameter ::= SEQUENCE {
     * salt                OCTET STRING,
     * owf                 AlgorithmIdentifier,
     * iterationCount      INTEGER,
     * mac                 AlgorithmIdentifier
     * }
     *
     * @param message subject (its protection and header) for validation
     * @return null if validation is ok
     * @throws CmpProcessingException if validation has failed
     */
    @Override
    public Void validate(PKIMessage message, ConfigurationContext configuration) throws CmpBaseException {
        PKIHeader header = message.getHeader();
        ASN1OctetString tid = header.getTransactionID();
        try {
            byte[] passwordAsBytes = configuration.getSharedSecret();
            PBMParameter pbmParameter = PBMParameter.getInstance(
                    header.getProtectionAlg().getParameters());      // -- PBMParameter
            byte[] salt = pbmParameter.getSalt().getOctets();        // --    salt (octetstring)
            AlgorithmIdentifier owf = pbmParameter.getOwf();         // --    owf  (algIdentifier)
            // The output of the final iteration (called
            //   "BASEKEY" for ease of reference, with a size of "H") is what is used
            //   to form the symmetric key.
            byte[] basekey = new byte[passwordAsBytes.length + salt.length];
            // The OWF is then applied iterationCount times, where
            //   the salted secret is the input to the first iteration and
            System.arraycopy(passwordAsBytes, 0, basekey, 0, passwordAsBytes.length);
            System.arraycopy(salt, 0, basekey, passwordAsBytes.length, salt.length);
            // for each
            //   successive iteration, the input is set to be the output of the
            //   previous iteration.  The output of the final iteration (called
            //   "BASEKEY" for ease of reference, with a size of "H")
            MessageDigest dig = MessageDigest.getInstance(owf.getAlgorithm().getId(),
                    BouncyCastleProvider.PROVIDER_NAME);
            for (int i = 0; i < pbmParameter.getIterationCount().getValue().intValue(); i++) {
                basekey = dig.digest(basekey);
                dig.reset();
            }
            // create mac instance
            String macId = pbmParameter.getMac().getAlgorithm().getId();
            Mac mac = Mac.getInstance(macId, BouncyCastleProvider.PROVIDER_NAME);
            mac.init(new SecretKeySpec(basekey, macId));
            mac.update(new ProtectedPart(header,
                    message.getBody()).getEncoded(ASN1Encoding.DER));
            // -- check counted bytes (mac) vs. bytes from protection field
            if (!Arrays.equals(mac.doFinal(), message.getProtection().getBytes())) {
                throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                        "mac validation: check of PasswordBasedMac protection failed");
            }
        } catch (CmpBaseException e) {
            throw e;
        } catch (Exception e) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                    e.getLocalizedMessage());
        }
        return null;// validation is ok
    }
}
