package com.otilm.core.certificate.type;

import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.core.dao.entity.RaProfile;
import java.util.EnumSet;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * The certificate types the authority of an RA profile can issue. Every authority issues X.509 only until its connector
 * can report its types.
 */
@Component
public class AuthorityCertificateTypes {

    public Set<CertificateType> supportedBy(RaProfile raProfile) {
        return EnumSet.of(CertificateType.X509);
    }

    /** Refuses a type the authority of the RA profile does not issue; a missing type is X.509. */
    public void requireSupport(CertificateType type, RaProfile raProfile) {
        CertificateType effectiveType = type != null ? type : CertificateType.X509;
        if (!supportedBy(raProfile).contains(effectiveType)) {
            throw UnsupportedCertificateTypeException
                    .notIssuedByAuthority(effectiveType.getCode(), raProfile.getName());
        }
    }
}
