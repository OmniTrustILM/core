package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpConfigurationException;
import com.otilm.api.model.core.cmp.ProtectionMethod;
import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.interfaces.core.cmp.error.ImplFailureInfo;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.PkiMessageDumper;
import com.otilm.core.service.cmp.message.protection.ProtectionStrategy;
import com.otilm.core.service.cmp.message.protection.impl.PasswordBasedMacProtectionStrategy;
import com.otilm.core.service.cmp.message.protection.impl.SingatureBaseProtectionStrategy;
import com.otilm.core.service.cmp.message.validator.BiValidator;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * <pre>[1]
 *       PKIMessage ::= SEQUENCE {
 *          header           PKIHeader,
 *          body             PKIBody,
 *          protection   [0] PKIProtection OPTIONAL,
 *          extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
 *                           OPTIONAL
 *      }
 * </pre>
 * <p>[2] The protectionAlg field specifies the algorithm used to protect the
 * message.  If no protection bits are supplied (note that PKIProtection
 * is OPTIONAL) then this field MUST be omitted; if protection bits are
 * supplied, then this field MUST be supplied.</p>
 *
 * <p>When protection is applied, the following structure is used:
 * <pre>
 *         PKIProtection ::= BIT STRING
 *    </pre>
 * The input to the calculation of PKIProtection is the DER encoding of
 * the following data structure:
 * <pre>
 *         ProtectedPart ::= SEQUENCE {
 *             header    PKIHeader,
 *             body      PKIBody
 *    }</pre>
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1">Overall PKI Message</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.1">PKI message header</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3">PKI message protection</a>
 */
@Component
@Transactional
public class ProtectionValidator implements BiValidator<Void, Void> {

    private static final Logger LOG = LoggerFactory.getLogger(ProtectionValidator.class.getName());

    @Override
    public Void validateIn(PKIMessage request, ConfigurationContext configuration) throws CmpBaseException {
        ASN1BitString protection = request.getProtection();
        ASN1OctetString tid = request.getHeader().getTransactionID();

        /*
         * The protectionAlg field specifies the algorithm used to protect the
         * message.  If no protection bits are supplied (note that PKIProtection
         * is OPTIONAL) then this field MUST be omitted; if protection bits are
         * supplied, then this field MUST be supplied.
         */
        if (protection == null && request.getHeader().getProtectionAlg() == null) {
            return null;
        }

        if (protection == null) {
            throw new CmpProcessingException(tid, PKIFailureInfo.notAuthorized,
                    ImplFailureInfo.CMPVALPRO530);
        }

        final AlgorithmIdentifier protectionAlg = request.getHeader().getProtectionAlg();
        if (protectionAlg == null) {
            throw new CmpProcessingException(tid, PKIFailureInfo.notAuthorized,
                    ImplFailureInfo.CMPVALPRO532);
        }

        checkProtectionMatrix(configuration, request);
        if (CMPObjectIdentifiers.passwordBasedMac.equals(protectionAlg.getAlgorithm())) {
            new ProtectionMacValidator().validate(request, configuration);
        } else if (PKCSObjectIdentifiers.id_PBMAC1.equals(protectionAlg.getAlgorithm())) {
            new ProtectionPBMac1Validator().validate(request, configuration);
        } else {
            new ProtectionSignatureValidator().validate(request, configuration);
        }
        return null;
    }

    @Override
    public Void validateOut(PKIMessage response, ConfigurationContext configuration) throws CmpBaseException {
        ASN1BitString protection = response.getProtection();
        ASN1OctetString tid = response.getHeader().getTransactionID();

        /*
         * The protectionAlg field specifies the algorithm used to protect the
         * message.  If no protection bits are supplied (note that PKIProtection
         * is OPTIONAL) then this field MUST be omitted; if protection bits are
         * supplied, then this field MUST be supplied.
         */
        if (protection == null && response.getHeader().getProtectionAlg() == null) {
            return null;
        }

        if (protection == null) {
            return switch (response.getBody().getType()) {
                case PKIBody.TYPE_ERROR, PKIBody.TYPE_CONFIRM, PKIBody.TYPE_REVOCATION_REP -> {
                    LOG.warn("TID={} | ignore protection for type={}", tid, PkiMessageDumper.msgTypeAsString(response.getBody()));
                    yield null;
                }
                default -> throw new CmpProcessingException(tid, PKIFailureInfo.notAuthorized,
                        ImplFailureInfo.CMPVALPRO531);
            };
        }

        final AlgorithmIdentifier protectionAlg = response.getHeader().getProtectionAlg();
        if (protectionAlg == null) {
            throw new CmpProcessingException(tid, PKIFailureInfo.notAuthorized,
                    ImplFailureInfo.CMPVALPRO533);
        }

        ProtectionStrategy czrtProtectionStrategy = configuration.getProtectionStrategy();
        String protectionAlgId = czrtProtectionStrategy.getProtectionAlg().getAlgorithm().getId();
        if (CMPObjectIdentifiers.passwordBasedMac.getId().equals(protectionAlgId)) {
            new ProtectionMacValidator().validate(response, configuration);
        } else if (PKCSObjectIdentifiers.id_PBMAC1.getId().equals(protectionAlgId)) {
            new ProtectionPBMac1Validator().validate(response, configuration);
        } else {
            new ProtectionSignatureValidator().validate(response, configuration);
        }

        return null;
    }

    /**
     * <p>
     * Check if protection is set up correctly: client and server can handle
     * protection only if the below given scheme is used. The scheme is based on:
     * </p>
     * <ol>
     *     <li>if server uses SHARED_SECRET, client must use SHARED_SECRET also</li>
     *     <li>if client uses SIGNATURE, server must use SIGNATURE also</li>
     *     <li>if client uses SHARED_SECRET, server can use SHARED_SECRET or SIGNATURE</li>
     * </ol>
     *
     * @throws CmpBaseException if protection matrix is not allowed
     */
    private void checkProtectionMatrix(ConfigurationContext configuration, PKIMessage request) throws CmpBaseException {
        ProtectionMethod clientProtection = configuration.getProtectionMethod();
        ProtectionStrategy serverProtection = configuration.getProtectionStrategy();

        // -- (1) server use SHARED_SECRET, client must use SHARED_SECRET also
        if (serverProtection instanceof PasswordBasedMacProtectionStrategy) {// is SHARED_SECRET
            if (ProtectionMethod.SIGNATURE.equals(clientProtection)) {
                throw new CmpConfigurationException(request.getHeader().getTransactionID(), PKIFailureInfo.systemFailure,
                        "wrong client configuration: server uses SHARED_SECRET and client uses SIGNATURE");
            }
            // ok state
        }
        // -- (2) client uses SIGNATURE, server must use SIGNATURE also
        else if (ProtectionMethod.SIGNATURE.equals(clientProtection)) {
            if (!(serverProtection instanceof SingatureBaseProtectionStrategy)) {
                throw new CmpConfigurationException(request.getHeader().getTransactionID(), PKIFailureInfo.systemFailure,
                        "wrong server configuration: client uses SIGNATURE and server uses different type of protection");
            }
            // ok state
        }
        // -- (3) client uses SHARED_SECRET, server can use SHARED_SECRET or SIGNATURE
        // ok state
    }

}
