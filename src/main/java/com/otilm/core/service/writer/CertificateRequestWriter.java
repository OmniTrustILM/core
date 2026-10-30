package com.otilm.core.service.writer;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * A certificate request belongs to the certificate it was submitted for, so it is deleted when that certificate is
 * deleted or stops referring to it.
 */
@Service
public class CertificateRequestWriter {

    private final CertificateRequestRepository certificateRequestRepository;
    private final ComplianceProfileAssociationWriter complianceProfileAssociationWriter;
    private final AttributeEngine attributeEngine;

    public CertificateRequestWriter(CertificateRequestRepository certificateRequestRepository,
            ComplianceProfileAssociationWriter complianceProfileAssociationWriter, AttributeEngine attributeEngine) {
        this.certificateRequestRepository = certificateRequestRepository;
        this.complianceProfileAssociationWriter = complianceProfileAssociationWriter;
        this.attributeEngine = attributeEngine;
    }

    /**
     * Deletes those of the given requests no certificate refers to, with their attribute values and compliance profile
     * associations. A request a certificate still refers to is kept: an earlier release pointed every certificate
     * submitted with an identical CSR at one request, and while it runs beside this one in a rolling update it still
     * may.
     */
    @Transactional
    public int deleteUnreferenced(Collection<UUID> certificateRequestUuids) {
        if (certificateRequestUuids.isEmpty()) {
            return 0;
        }
        List<UUID> unreferencedRequestUuids = certificateRequestRepository
                .findUuidsWithoutCertificate(certificateRequestUuids);
        if (unreferencedRequestUuids.isEmpty()) {
            return 0;
        }
        complianceProfileAssociationWriter.deleteAllForObjects(Resource.CERTIFICATE_REQUEST, unreferencedRequestUuids);
        attributeEngine.bulkDeleteObjectAttributeContent(Resource.CERTIFICATE_REQUEST, unreferencedRequestUuids);
        return certificateRequestRepository.deleteByUuidIn(unreferencedRequestUuids);
    }
}
