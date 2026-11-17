package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpConfigurationException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.interfaces.core.cmp.error.ImplFailureInfo;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.cmp.ProtectionMethod;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.PkiMessageDumper;
import com.otilm.core.service.cmp.message.protection.ProtectionStrategy;
import com.otilm.core.service.cmp.message.protection.impl.PasswordBasedMacProtectionStrategy;
import com.otilm.core.service.cmp.message.protection.impl.SingatureBaseProtectionStrategy;
import com.otilm.core.service.cmp.message.validator.BiValidator;
import com.otilm.core.util.CertificateUtil;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * <pre>
 * [1]
 *       PKIMessage ::= SEQUENCE {
 *          header           PKIHeader,
 *          body             PKIBody,
 *          protection   [0] PKIProtection OPTIONAL,
 *          extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
 *                           OPTIONAL
 *      }
 * </pre>
 * <p>
 * [2] The protectionAlg field specifies the algorithm used to protect the message. If no protection bits are supplied
 * (note that PKIProtection is OPTIONAL) then this field MUST be omitted; if protection bits are supplied, then this
 * field MUST be supplied.
 * </p>
 *
 * <p>
 * When protection is applied, the following structure is used:
 *
 * <pre>
 *         PKIProtection ::= BIT STRING
 * </pre>
 *
 * The input to the calculation of PKIProtection is the DER encoding of the following data structure:
 *
 * <pre>
 *         ProtectedPart ::= SEQUENCE {
 *             header    PKIHeader,
 *             body      PKIBody
 *    }
 * </pre>
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1">Overall PKI Message</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.1">PKI message header</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3">PKI message protection</a>
 */
@Component
// noRollbackFor keeps Spring's default (no rollback on checked exceptions): CMP surfaces
// CmpBaseException as a protocol error response, and a rollback here would clear the request's
// EntityManager, detaching the profiles the configuration context holds.
@Transactional(noRollbackFor = CmpBaseException.class)
public class ProtectionValidator implements BiValidator<Void, Void> {

    private static final Logger LOG = LoggerFactory.getLogger(ProtectionValidator.class.getName());

    private static final String UNTRUSTED_PROTECTION_CERTIFICATE = "the CMP protection certificate is not trusted";

    // EnumSet tolerates a null argument to contains(), unlike Set.of.
    private static final Set<CertificateValidationStatus> TRUSTED_VALIDATION_STATUSES = EnumSet
            .of(CertificateValidationStatus.VALID, CertificateValidationStatus.EXPIRING);

    private CertificateRepository certificateRepository;

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Override
    public Void validateIn(PKIMessage request, ConfigurationContext configuration) throws CmpBaseException {
        ASN1BitString protection = request.getProtection();
        ASN1OctetString tid = request.getHeader().getTransactionID();

        // The message protection is the only authentication of a CMP client, so RFC 9483 §3.5 refuses a request
        // without it, whatever protection the profile expects.
        if (protection == null) {
            throw new CmpProcessingException(tid, PKIFailureInfo.notAuthorized, ImplFailureInfo.CMPVALPRO530);
        }

        /*
         * The protectionAlg field specifies the algorithm used to protect the message. If no protection bits are
         * supplied (note that PKIProtection is OPTIONAL) then this field MUST be omitted; if protection bits are
         * supplied, then this field MUST be supplied.
         */
        final AlgorithmIdentifier protectionAlg = request.getHeader().getProtectionAlg();
        if (protectionAlg == null) {
            throw new CmpProcessingException(tid, PKIFailureInfo.notAuthorized, ImplFailureInfo.CMPVALPRO532);
        }

        assertMessageProtectionMatchesProfile(tid, protectionAlg, configuration.getProtectionMethod());
        checkProtectionMatrix(configuration, request);
        if (CMPObjectIdentifiers.passwordBasedMac.equals(protectionAlg.getAlgorithm())) {
            new ProtectionMacValidator().validate(request, configuration);
        } else if (PKCSObjectIdentifiers.id_PBMAC1.equals(protectionAlg.getAlgorithm())) {
            new ProtectionPBMac1Validator().validate(request, configuration);
        } else {
            new ProtectionSignatureValidator(true).validate(request, configuration);
            configuration.setProtectionCertificate(trustedProtectionCertificate(request, configuration));
        }
        return null;
    }

    /**
     * Resolves the CMP protection certificate of a verified signature, the first of the request's extraCerts, to the
     * inventory. Core trusts it as RFC 9483 §4.1.2 trusts an end entity enrolled by the same PKI: a certificate of the
     * profile's RA profile that is issued, not archived, validated as valid or expiring, and within its validity
     * period. Every refusal answers alike, so a client cannot probe the inventory; the log names the reason.
     */
    private Certificate trustedProtectionCertificate(PKIMessage request, ConfigurationContext configuration)
            throws CmpProcessingException {
        Certificate certificate = findInventoryCertificate(request.getExtraCerts()[0]);
        String refusal = protectionCertificateRefusal(certificate, configuration.getRaProfile());
        if (refusal != null) {
            ASN1OctetString tid = request.getHeader().getTransactionID();
            LOG
                    .warn("TID={}, PN={} | signature-protected request refused: {}", tid,
                            configuration.getCmpProfile().getName(), refusal);
            throw new CmpProcessingException(tid, PKIFailureInfo.signerNotTrusted, UNTRUSTED_PROTECTION_CERTIFICATE);
        }
        return certificate;
    }

    private Certificate findInventoryCertificate(CMPCertificate protectionCertificate) {
        try {
            String fingerprint = CertificateUtil.getThumbprint(protectionCertificate.getEncoded());
            return certificateRepository.findByFingerprint(fingerprint).orElse(null);
        } catch (IOException | NoSuchAlgorithmException e) {
            LOG.debug("The CMP protection certificate cannot be fingerprinted", e);
            return null;
        }
    }

    /** Why Core does not trust {@code certificate} as a CMP protection certificate, or {@code null} when it does. */
    private static String protectionCertificateRefusal(Certificate certificate, RaProfile raProfile) {
        if (certificate == null) {
            return "the protection certificate is not in the inventory";
        }
        String subject = "protection certificate " + certificate.getUuid();
        if (certificate.getRaProfileUuid() == null || !certificate.getRaProfileUuid().equals(raProfile.getUuid())) {
            return subject + " belongs to another RA profile";
        }
        if (certificate.isArchived() || certificate.getState() != CertificateState.ISSUED) {
            return subject + " is archived or not issued, state " + certificate.getState();
        }
        if (!TRUSTED_VALIDATION_STATUSES.contains(certificate.getValidationStatus())) {
            return subject + " has validation status " + certificate.getValidationStatus();
        }
        Instant now = Instant.now();
        if (now.isBefore(certificate.getNotBefore().toInstant())
                || now.isAfter(certificate.getNotAfter().toInstant())) {
            return subject + " is outside its validity period";
        }
        return null;
    }

    @Override
    public Void validateOut(PKIMessage response, ConfigurationContext configuration) throws CmpBaseException {
        ASN1BitString protection = response.getProtection();
        ASN1OctetString tid = response.getHeader().getTransactionID();

        /*
         * The protectionAlg field specifies the algorithm used to protect the message. If no protection bits are
         * supplied (note that PKIProtection is OPTIONAL) then this field MUST be omitted; if protection bits are
         * supplied, then this field MUST be supplied.
         */
        if (protection == null && response.getHeader().getProtectionAlg() == null) {
            return null;
        }

        if (protection == null) {
            return switch (response.getBody().getType()) {
                case PKIBody.TYPE_ERROR, PKIBody.TYPE_CONFIRM, PKIBody.TYPE_REVOCATION_REP -> {
                    LOG
                            .warn("TID={} | ignore protection for type={}", tid,
                                    PkiMessageDumper.msgTypeAsString(response.getBody()));
                    yield null;
                }
                default ->
                    throw new CmpProcessingException(tid, PKIFailureInfo.notAuthorized, ImplFailureInfo.CMPVALPRO531);
            };
        }

        final AlgorithmIdentifier protectionAlg = response.getHeader().getProtectionAlg();
        if (protectionAlg == null) {
            throw new CmpProcessingException(tid, PKIFailureInfo.notAuthorized, ImplFailureInfo.CMPVALPRO533);
        }

        ProtectionStrategy czrtProtectionStrategy = configuration.getProtectionStrategy();
        String protectionAlgId = czrtProtectionStrategy.getProtectionAlg().getAlgorithm().getId();
        if (CMPObjectIdentifiers.passwordBasedMac.getId().equals(protectionAlgId)) {
            new ProtectionMacValidator().validate(response, configuration);
        } else if (PKCSObjectIdentifiers.id_PBMAC1.getId().equals(protectionAlgId)) {
            new ProtectionPBMac1Validator().validate(response, configuration);
        } else {
            new ProtectionSignatureValidator(false).validate(response, configuration);
        }

        return null;
    }

    /**
     * Rejects a request whose actual protection type contradicts the profile's configured
     * {@code Requested Protection Method}. A sharedSecret profile must receive PBM-protected messages
     * ({@code passwordBasedMac} / {@code id_PBMAC1}); a signature profile must receive signature-protected messages. On
     * mismatch a {@link PKIFailureInfo#badMessageCheck} rejection is raised (RFC 4210 §5.2.7) so the client gets a
     * parseable CMP error instead of the platform dereferencing PBM-specific fields on a non-PBM message.
     *
     * <p>
     * When the profile does not constrain the request method ({@code expectedRequestMethod == null}) no check is
     * applied.
     * </p>
     *
     * @throws CmpProcessingException if the message protection type is not accepted by the profile
     */
    static void assertMessageProtectionMatchesProfile(ASN1OctetString tid, AlgorithmIdentifier protectionAlg,
            ProtectionMethod expectedRequestMethod) throws CmpProcessingException {
        if (expectedRequestMethod == null) {
            return;
        }
        boolean messageIsPbm = CMPObjectIdentifiers.passwordBasedMac.equals(protectionAlg.getAlgorithm())
                || PKCSObjectIdentifiers.id_PBMAC1.equals(protectionAlg.getAlgorithm());
        if (ProtectionMethod.SHARED_SECRET.equals(expectedRequestMethod) && !messageIsPbm) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                    "this CMP profile only accepts PBM (shared secret) protected messages");
        }
        if (ProtectionMethod.SIGNATURE.equals(expectedRequestMethod) && messageIsPbm) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                    "this CMP profile only accepts signature-protected messages");
        }
    }

    /**
     * <p>
     * Check if protection is set up correctly: client and server can handle protection only if the below given scheme
     * is used. The scheme is based on:
     * </p>
     * <ol>
     * <li>if server uses SHARED_SECRET, client must use SHARED_SECRET also</li>
     * <li>if client uses SIGNATURE, server must use SIGNATURE also</li>
     * <li>if client uses SHARED_SECRET, server can use SHARED_SECRET or SIGNATURE</li>
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
                throw new CmpConfigurationException(request.getHeader().getTransactionID(),
                        PKIFailureInfo.systemFailure,
                        "wrong client configuration: server uses SHARED_SECRET and client uses SIGNATURE");
            }
            // ok state
        }
        // -- (2) client uses SIGNATURE, server must use SIGNATURE also
        else if (ProtectionMethod.SIGNATURE.equals(clientProtection)) {
            if (!(serverProtection instanceof SingatureBaseProtectionStrategy)) {
                throw new CmpConfigurationException(request.getHeader().getTransactionID(),
                        PKIFailureInfo.systemFailure,
                        "wrong server configuration: client uses SIGNATURE and server uses different type of protection");
            }
            // ok state
        }
        // -- (3) client uses SHARED_SECRET, server can use SHARED_SECRET or SIGNATURE
        // ok state
    }

}
