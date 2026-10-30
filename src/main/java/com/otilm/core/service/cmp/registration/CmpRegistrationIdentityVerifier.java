package com.otilm.core.service.cmp.registration;

import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.model.request.CrmfCertificateRequest;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.registration.RegistrationIdentityMatcher;
import com.otilm.core.util.CertificateUtil;
import java.io.IOException;
import java.util.List;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Verifies that a registration-mode CRMF request presents exactly the identity of the pre-registration its challenge
 * authorizes — the same subject and the same subject alternative names. The challenge authenticates one certificate
 * identity; without this check a CRMF could carry a different SAN set and have it issued under a challenge that never
 * authorized it. Used by both the ir/cr completion and the kur rekey path so the two enforce the identity check
 * identically.
 */
@Component
public class CmpRegistrationIdentityVerifier {

    private CertificateEventHistoryInternalService certificateEventHistoryService;

    @Autowired
    public void setCertificateEventHistoryService(
            CertificateEventHistoryInternalService certificateEventHistoryService) {
        this.certificateEventHistoryService = certificateEventHistoryService;
    }

    /**
     * Requires the CRMF's subject and SANs to equal those of {@code matched}. On any mismatch the failure is recorded
     * against {@code matched} under {@code event} (server-side only) and the single generic registration rejection is
     * thrown; the wire never distinguishes the reason.
     */
    public void verify(CertReqMessages crmf, Certificate matched, CertificateEvent event, ASN1OctetString tid)
            throws CmpBaseException {
        try {
            CrmfCertificateRequest parsed = new CrmfCertificateRequest(crmf.getEncoded());
            RegistrationIdentityMatcher.MatchResult result = RegistrationIdentityMatcher
                    .match(parsed.getSubject(), CertificateUtil.getSAN(parsed),
                            List
                                    .of(new RegistrationIdentityMatcher.Candidate(matched.getUuid(),
                                            matched.getSubjectDn(), matched.getSubjectAlternativeNames())));
            if (result.outcome() != RegistrationIdentityMatcher.Outcome.MATCHED) {
                // A single candidate can only yield SAN_MISMATCH (subject matched, SANs differ) or NO_MATCH
                // (subject differs); AMBIGUOUS cannot occur. Attribute the failure to the resolved certificate.
                String reason = result.outcome() == RegistrationIdentityMatcher.Outcome.SAN_MISMATCH
                        ? "CMP enrolment subject alternative names do not match the registered ones"
                        : "CMP enrolment subject does not match the registered identity";
                certificateEventHistoryService
                        .addEventHistory(matched.getUuid(), event, CertificateEventStatus.FAILED, reason, "");
                throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                        CmpRegistrationResolver.REGISTRATION_REJECTION);
            }
        } catch (CertificateRequestException | IOException e) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                    CmpRegistrationResolver.REGISTRATION_REJECTION);
        }
    }
}
