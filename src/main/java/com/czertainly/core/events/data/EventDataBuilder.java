package com.czertainly.core.events.data;

import com.czertainly.api.model.client.approvalprofile.ApprovalStepDto;
import com.czertainly.api.model.common.events.data.*;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.compliance.v2.ComplianceCheckResultDto;
import com.czertainly.api.model.core.notification.RecipientType;
import com.czertainly.core.dao.entity.Approval;
import com.czertainly.core.dao.entity.ApprovalProfile;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.DiscoveryHistory;
import com.czertainly.core.model.auth.ResourceAction;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZoneId;
import java.util.UUID;

@Transactional
public class EventDataBuilder {

    private EventDataBuilder() {
    }

    public static ApprovalEventData getApprovalEventData(Approval approval, ApprovalProfile approvalProfile, String creatorUsername) {
        ApprovalEventData eventData = new ApprovalEventData();
        eventData.setApprovalUuid(approval.getUuid());
        eventData.setApprovalProfileUuid(approvalProfile.getUuid());
        eventData.setApprovalProfileName(approvalProfile.getName());
        eventData.setVersion(approval.getApprovalProfileVersion().getVersion());
        eventData.setStatus(approval.getStatus());
        eventData.setExpiryAt(approval.getExpiryAt());
        eventData.setClosedAt(approval.getClosedAt());
        eventData.setResource(approval.getResource());
        eventData.setResourceAction(approval.getAction().getCode());
        eventData.setObjectUuid(approval.getObjectUuid());
        eventData.setCreatorUuid(approval.getCreatorUuid());
        eventData.setCreatorUsername(creatorUsername);

        return eventData;
    }

    public static ApprovalEventData getApprovalRequestedEventData(Approval approval, ApprovalProfile approvalProfile, ApprovalStepDto approvalStepDto, String creatorUsername) {
        ApprovalEventData eventData = getApprovalEventData(approval, approvalProfile, creatorUsername);

        if (approvalStepDto.getUserUuid() != null) {
            eventData.setRecipientType(RecipientType.USER);
            eventData.setRecipientUuid(approvalStepDto.getUserUuid());
        } else if (approvalStepDto.getRoleUuid() != null) {
            eventData.setRecipientType(RecipientType.ROLE);
            eventData.setRecipientUuid(approvalStepDto.getRoleUuid());
        } else if (approvalStepDto.getGroupUuid() != null) {
            eventData.setRecipientType(RecipientType.GROUP);
            eventData.setRecipientUuid(approvalStepDto.getGroupUuid());
        }

        return eventData;
    }

    public static CertificateStatusChangedEventData getCertificateStatusChangedEventData(Certificate certificate, CertificateValidationStatus[] statusArrayData) {
        CertificateStatusChangedEventData eventData = new CertificateStatusChangedEventData();
        eventData.setOldStatus(statusArrayData[0].getLabel());
        eventData.setNewStatus(statusArrayData[1].getLabel());
        setCertificateEventData(eventData, certificate);
        eventData.setNotBefore(certificate.getNotBefore().toInstant().atZone(ZoneId.systemDefault()));
        eventData.setExpiresAt(certificate.getNotAfter().toInstant().atZone(ZoneId.systemDefault()));

        setCertificateAuthorityData(eventData, certificate);

        return eventData;
    }

    public static CertificateActionPerformedEventData getCertificateActionPerformedEventData(Certificate certificate, ResourceAction action) {
        CertificateActionPerformedEventData eventData = new CertificateActionPerformedEventData();
        eventData.setAction(action.getCode());
        eventData.setState(certificate.getState());
        setCertificateEventData(eventData, certificate);
        setCertificateAuthorityData(eventData, certificate);
        return eventData;
    }

    public static CertificateDiscoveredEventData getCertificateDiscoveredEventData(Certificate certificate, DiscoveryHistory discovery, UUID userUuid) {
        CertificateDiscoveredEventData eventData = new CertificateDiscoveredEventData();
        setCertificateEventData(eventData, certificate);
        eventData.setNotBefore(certificate.getNotBefore().toInstant().atZone(ZoneId.systemDefault()));
        eventData.setExpiresAt(certificate.getNotAfter().toInstant().atZone(ZoneId.systemDefault()));

        eventData.setDiscoveryUuid(discovery.getUuid());
        eventData.setDiscoveryName(discovery.getName());
        eventData.setDiscoveryUserUuid(userUuid);
        eventData.setDiscoveryConnectorUuid(discovery.getConnectorUuid());
        eventData.setDiscoveryConnectorName(discovery.getConnectorName());

        return eventData;
    }

    public static DiscoveryFinishedEventData getDiscoveryFinishedEventData(DiscoveryHistory discovery) {
        DiscoveryFinishedEventData eventData = new DiscoveryFinishedEventData();
        eventData.setDiscoveryUuid(discovery.getUuid());
        eventData.setDiscoveryName(discovery.getName());
        eventData.setDiscoveryConnectorUuid(discovery.getConnectorUuid());
        eventData.setDiscoveryConnectorName(discovery.getConnectorName());
        eventData.setDiscoveryStatus(discovery.getStatus());
        eventData.setTotalCertificateDiscovered(discovery.getTotalCertificatesDiscovered() == null ? 0 : discovery.getTotalCertificatesDiscovered());
        eventData.setDiscoveryMessage(discovery.getMessage());

        return eventData;
    }

    public static CertificateExpiringEventData getCertificateExpiringEventData(Certificate certificate) {
        CertificateExpiringEventData eventData = new CertificateExpiringEventData();
        setCertificateEventData(eventData, certificate);
        setCertificateAuthorityData(eventData, certificate);
        eventData.setNotBefore(certificate.getNotBefore().toInstant().atZone(ZoneId.systemDefault()));
        eventData.setExpiresAt(certificate.getNotAfter().toInstant().atZone(ZoneId.systemDefault()));

        return eventData;
    }

    public static CertificateNotCompliantEventData getCertificateNotCompliantEventData(Certificate certificate, ComplianceCheckResultDto checkResultDto) {
        CertificateNotCompliantEventData eventData = new CertificateNotCompliantEventData();
        setCertificateEventData(eventData, certificate);
        eventData.setComplianceCheckResultDto(checkResultDto);
        return eventData;
    }

    private static void setCertificateEventData(CertificateEventData eventData, Certificate certificate) {
        eventData.setCertificateUuid(certificate.getUuid());
        eventData.setFingerprint(certificate.getFingerprint());
        eventData.setSerialNumber(certificate.getSerialNumber());
        eventData.setSubjectDn(certificate.getSubjectDn());
        eventData.setIssuerDn(certificate.getIssuerDn());
    }

    private static void setCertificateAuthorityData(CertificateEventAuthorityData eventData, Certificate certificate) {
        if (certificate.getRaProfile() != null) {
            eventData.setRaProfileUuid(certificate.getRaProfile().getUuid());
            eventData.setRaProfileName(certificate.getRaProfile().getName());
            if (certificate.getRaProfile().getAuthorityInstanceReferenceUuid() != null) {
                eventData.setAuthorityInstanceUuid(certificate.getRaProfile().getAuthorityInstanceReferenceUuid());
            }
        }
    }
}