package com.czertainly.core.mapper.certificate;

import com.czertainly.api.model.client.raprofile.SimplifiedRaProfileDto;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.Group;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.MetaDefinitions;

public class CertificateDetailDtoMapper {

    private CertificateDetailDtoMapper() {}

    public static CertificateDetailDto toDetailDto(Certificate certificate) {
        return buildDetailDto(certificate, false);
    }

    public static CertificateDetailDto toChainDto(Certificate certificate) {
        return buildDetailDto(certificate, true);
    }

    /**
     * @param chainContext when {@code true}, key associations are mapped with {@link com.czertainly.core.dao.entity.CryptographicKey#mapToChainDto()} (omits the {@code associations} count);
     *                     when {@code false}, the full {@link com.czertainly.core.dao.entity.CryptographicKey#mapToDto()} is used.
     */
    private static CertificateDetailDto buildDetailDto(Certificate certificate, boolean chainContext) {
        final CertificateDetailDto dto = new CertificateDetailDto();
        dto.setCommonName(CertificateUtil.formatCommonName(certificate.getCommonName()));
        dto.setIssuerCommonName(resolveIssuerCommonName(certificate));
        if (certificate.getCertificateContent() != null) {
            dto.setCertificateContent(certificate.getCertificateContent().getContent());
            dto.setIssuerDn(certificate.getIssuerDn());
            dto.setNotBefore(certificate.getNotBefore());
            dto.setNotAfter(certificate.getNotAfter());
            dto.setSubjectType(certificate.getSubjectType());
            dto.setExtendedKeyUsage(MetaDefinitions.deserializeArrayString(certificate.getExtendedKeyUsage()));
            dto.setKeyUsage(certificate.getKeyUsage().stream().toList());
            dto.setFingerprint(certificate.getFingerprint());
            dto.setSubjectAlternativeNames(CertificateUtil.deserializeSans(certificate.getSubjectAlternativeNames()));
            dto.setIssuerSerialNumber(certificate.getIssuerSerialNumber());
            dto.setSerialNumber(certificate.getSerialNumber());

            boolean hasAnyQc = certificate.getQcCompliance() != null || certificate.getQcSscd() != null
                    || certificate.getQcType() != null || certificate.getQcCcLegislation() != null;
            if (hasAnyQc) {
                CertificateQcStatementsDto qcDto = new CertificateQcStatementsDto();
                qcDto.setQcCompliance(certificate.getQcCompliance());
                qcDto.setQcSscd(certificate.getQcSscd());
                if (certificate.getQcType() != null) {
                    qcDto.setQcType(MetaDefinitions.deserializeArrayString(certificate.getQcType()).stream().map(QcType::valueOf).toList());
                }
                if (certificate.getQcCcLegislation() != null) {
                    qcDto.setQcCcLegislation(MetaDefinitions.deserializeArrayString(certificate.getQcCcLegislation()));
                }
                dto.setQcStatements(qcDto);
            }
        }
        dto.setSubjectDn(certificate.getSubjectDn());
        dto.setPublicKeyAlgorithm(certificate.getPublicKeyAlgorithm());
        dto.setAltPublicKeyAlgorithm(certificate.getAltPublicKeyAlgorithm());
        dto.setSignatureAlgorithm(certificate.getSignatureAlgorithm());
        if (certificate.getAltSignatureAlgorithm() != null) dto.setAltSignatureAlgorithm(certificate.getAltSignatureAlgorithm());
        dto.setKeySize(certificate.getKeySize());
        dto.setAltKeySize(certificate.getAltKeySize());
        dto.setUuid(certificate.getUuid().toString());
        dto.setState(certificate.getState());
        dto.setValidationStatus(certificate.getValidationStatus());
        dto.setCertificateType(certificate.getCertificateType());
        dto.setTrustedCa(certificate.getTrustedCa());
        dto.setHybridCertificate(certificate.isHybridCertificate());
        dto.setArchived(certificate.isArchived());
        if (!certificate.getPredecessorRelations().isEmpty()) {
            dto.setSourceCertificateUuid(certificate.getPredecessorRelations().stream().toList().getFirst().getPredecessorCertificate().getUuid());
        }
        if (certificate.getIssuerCertificateUuid() != null) dto.setIssuerCertificateUuid(certificate.getIssuerCertificateUuid().toString());
        if (certificate.getOwner() != null) {
            dto.setOwnerUuid(certificate.getOwner().getOwnerUuid().toString());
            dto.setOwner(certificate.getOwner().getOwnerUsername());
        }
        /*
         * Result for the compliance check of a certificate is stored in the database in the form of List of Rule IDs.
         * When the details of the certificate is requested, the Service will transform the result into the user understandable
         * format and send it. It is not moved into the mapToDto function, as the computation involves other repositories
         * like complianceRules etc., So only the overall status of the compliance will be set in the mapToDto function
         */
        dto.setComplianceStatus(certificate.getComplianceStatus());
        if (certificate.getRaProfile() != null) {
            dto.setRaProfile(toSimplifiedRaProfileDto(certificate));
        }

        if (certificate.getGroups() != null) {
            dto.setGroups(certificate.getGroups().stream().map(Group::mapToDto).toList());
        }

        dto.setPrivateKeyAvailability(false);

        if (certificate.getCertificateRequestEntity() != null) {
            final CertificateRequestDto certificateRequestDto = new CertificateRequestDto();
            certificateRequestDto.setUuid(certificate.getCertificateRequestEntity().getUuid());
            certificateRequestDto.setContent(certificate.getCertificateRequestEntity().getContent());
            certificateRequestDto.setCertificateType(certificate.getCertificateRequestEntity().getCertificateType());
            certificateRequestDto.setCommonName(CertificateUtil.formatCommonName(certificate.getCertificateRequestEntity().getCommonName()));
            certificateRequestDto.setSubjectDn(certificate.getCertificateRequestEntity().getSubjectDn());
            certificateRequestDto.setSignatureAlgorithm(certificate.getCertificateRequestEntity().getSignatureAlgorithm());
            certificateRequestDto.setAltSignatureAlgorithm(certificate.getCertificateRequestEntity().getAltSignatureAlgorithm());
            certificateRequestDto.setPublicKeyAlgorithm(certificate.getCertificateRequestEntity().getPublicKeyAlgorithm());
            certificateRequestDto.setCertificateRequestFormat(certificate.getCertificateRequestEntity().getCertificateRequestFormat());
            certificateRequestDto.setSubjectAlternativeNames(CertificateUtil.deserializeSans(certificate.getCertificateRequestEntity().getSubjectAlternativeNames()));
            certificateRequestDto.setKeyUuid(certificate.getCertificateRequestEntity().getKeyUuid() != null ? certificate.getCertificateRequestEntity().getKeyUuid().toString() : null);
            certificateRequestDto.setAltKeyUuid(certificate.getCertificateRequestEntity().getAltKeyUuid() != null ? certificate.getCertificateRequestEntity().getAltKeyUuid().toString() : null);
            certificateRequestDto.setComplianceStatus(certificate.getCertificateRequestEntity().getComplianceStatus());
            dto.setCertificateRequest(certificateRequestDto);
        }
        if (certificate.getKey() != null && !certificate.getKey().getItems().isEmpty()
                && !certificate.getKey().getItems().stream().filter(item -> item.getType().equals(KeyType.PRIVATE_KEY) && item.getState().equals(KeyState.ACTIVE)).toList().isEmpty()) {
            dto.setPrivateKeyAvailability(true);
        }

        if (certificate.getKey() != null) dto.setKey(chainContext ? certificate.getKey().mapToChainDto() : certificate.getKey().mapToDto());

        if (certificate.getAltKey() != null) dto.setAltKey(chainContext ? certificate.getAltKey().mapToChainDto() : certificate.getAltKey().mapToDto());

        if (certificate.getProtocolAssociation() != null) {
            CertificateProtocolDto protocolDto = new CertificateProtocolDto();
            protocolDto.setProtocol(certificate.getProtocolAssociation().getProtocol());
            protocolDto.setProtocolProfileUuid(certificate.getProtocolAssociation().getProtocolProfileUuid());
            protocolDto.setAdditionalProtocolUuid(certificate.getProtocolAssociation().getAdditionalProtocolUuid());
            dto.setProtocolInfo(protocolDto);
        }

        return dto;
    }

    public static CertificateSimpleDto toSimpleDto(Certificate certificate, CertificateRelationType relationType) {
        CertificateSimpleDto dto = new CertificateSimpleDto();
        dto.setUuid(certificate.getUuid());
        dto.setCertificateType(certificate.getCertificateType());
        dto.setState(certificate.getState());
        dto.setRelationType(relationType);
        dto.setCommonName(certificate.getCommonName());
        dto.setSubjectDn(certificate.getSubjectDn());
        dto.setIssuerCommonName(certificate.getIssuerCommonName());
        dto.setIssuerDn(certificate.getIssuerDn());
        dto.setSerialNumber(certificate.getSerialNumber());
        dto.setFingerprint(certificate.getFingerprint());
        dto.setPublicKeyAlgorithm(certificate.getPublicKeyAlgorithm());
        dto.setAltPublicKeyAlgorithm(certificate.getAltPublicKeyAlgorithm());
        dto.setSignatureAlgorithm(certificate.getSignatureAlgorithm());
        dto.setAltSignatureAlgorithm(certificate.getAltSignatureAlgorithm());
        dto.setNotBefore(certificate.getNotBefore());
        dto.setNotAfter(certificate.getNotAfter());
        return dto;
    }

    public static CertificateDto toListDto(Certificate certificate) {
        CertificateDto dto = new CertificateDto();
        dto.setCommonName(CertificateUtil.formatCommonName(certificate.getCommonName()));
        dto.setSerialNumber(certificate.getSerialNumber());
        dto.setIssuerCommonName(certificate.getIssuerCommonName());
        dto.setIssuerDn(certificate.getIssuerDn());
        dto.setSubjectDn(certificate.getSubjectDn());
        dto.setNotBefore(certificate.getNotBefore());
        dto.setNotAfter(certificate.getNotAfter());
        dto.setPublicKeyAlgorithm(certificate.getPublicKeyAlgorithm());
        dto.setAltPublicKeyAlgorithm(certificate.getAltPublicKeyAlgorithm());
        dto.setSignatureAlgorithm(certificate.getSignatureAlgorithm());
        dto.setAltSignatureAlgorithm(certificate.getAltSignatureAlgorithm());
        dto.setKeySize(certificate.getKeySize());
        dto.setAltKeySize(certificate.getAltKeySize());
        dto.setUuid(certificate.getUuid().toString());
        dto.setState(certificate.getState());
        dto.setValidationStatus(certificate.getValidationStatus());
        dto.setFingerprint(certificate.getFingerprint());
        dto.setTrustedCa(certificate.getTrustedCa());
        dto.setHybridCertificate(certificate.isHybridCertificate());
        dto.setArchived(certificate.isArchived());
        if (certificate.getIssuerCertificateUuid() != null) dto.setIssuerCertificateUuid(certificate.getIssuerCertificateUuid().toString());
        if (certificate.getOwner() != null) {
            dto.setOwnerUuid(certificate.getOwner().getOwnerUuid().toString());
            dto.setOwner(certificate.getOwner().getOwnerUsername());
        }
        dto.setCertificateType(certificate.getCertificateType());
        dto.setIssuerSerialNumber(certificate.getIssuerSerialNumber());
        /*
         * Result for the compliance check of a certificate is stored in the database in the form of List of Rule IDs.
         * When the details of the certificate is requested, the Service will transform the result into the user understandable
         * format and send it. It is not moved into the mapToDto function, as the computation involves other repositories
         * like complianceRules etc., So only the overall status of the compliance will be set in the mapToDto function
         */
        dto.setComplianceStatus(certificate.getComplianceStatus());

        if (certificate.getRaProfile() != null) {
            dto.setRaProfile(toSimplifiedRaProfileDto(certificate));
        }

        if (certificate.getGroups() != null) {
            dto.setGroups(certificate.getGroups().stream().map(Group::mapToDto).toList());
        }

        dto.setPrivateKeyAvailability(false);
        if (certificate.getKey() != null && !certificate.getKey().getItems().isEmpty()
                && !certificate.getKey().getItems().stream().filter(item -> item.getType().equals(KeyType.PRIVATE_KEY) && item.getState().equals(KeyState.ACTIVE)).toList().isEmpty()) {
            dto.setPrivateKeyAvailability(true);
        }

        return dto;
    }

    private static String resolveIssuerCommonName(Certificate certificate) {
        if (certificate.getIssuerCommonName() != null) {
            return certificate.getIssuerCommonName();
        } else if (certificate.getIssuerCertificateUuid() != null) {
            return CertificateUtil.EMPTY_COMMON_NAME_PLACEHOLDER;
        }
        return null;
    }

    private static SimplifiedRaProfileDto toSimplifiedRaProfileDto(Certificate certificate) {
        SimplifiedRaProfileDto raDto = new SimplifiedRaProfileDto();
        raDto.setName(certificate.getRaProfile().getName());
        raDto.setUuid(certificate.getRaProfile().getUuid().toString());
        raDto.setEnabled(certificate.getRaProfile().getEnabled());
        if (certificate.getRaProfile().getAuthorityInstanceReference() != null) {
            raDto.setAuthorityInstanceUuid(certificate.getRaProfile().getAuthorityInstanceReference().getUuid().toString());
        }
        return raDto;
    }
}
