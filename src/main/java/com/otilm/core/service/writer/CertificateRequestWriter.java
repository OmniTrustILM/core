package com.otilm.core.service.writer;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
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
    private final ClusterOperationSynchronizer synchronizer;

    public CertificateRequestWriter(CertificateRequestRepository certificateRequestRepository,
            ComplianceProfileAssociationWriter complianceProfileAssociationWriter, AttributeEngine attributeEngine,
            ClusterOperationSynchronizer synchronizer) {
        this.certificateRequestRepository = certificateRequestRepository;
        this.complianceProfileAssociationWriter = complianceProfileAssociationWriter;
        this.attributeEngine = attributeEngine;
        this.synchronizer = synchronizer;
    }

    /**
     * Deletes the given requests no certificate refers to, with their attribute values and compliance profile
     * associations. A referenced request is kept: the previous release may share one during a rolling update. The lock
     * makes concurrent deleters of one request's certificates look in turn, so the last one deletes it.
     */
    @Transactional
    public int deleteUnreferenced(Collection<UUID> certificateRequestUuids) {
        if (certificateRequestUuids.isEmpty()) {
            return 0;
        }
        synchronizer
                .lockAll(certificateRequestUuids
                        .stream()
                        .map(requestUuid -> "certificate-request:" + requestUuid)
                        .toList());
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
