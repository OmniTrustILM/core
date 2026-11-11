package com.otilm.core.mapper.certificate;

import com.otilm.api.model.client.raprofile.SimplifiedRaProfileDto;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.certificate.CertificateProtocolDto;
import com.otilm.api.model.core.certificate.CertificateQcStatementsDto;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateRequestDto;
import com.otilm.api.model.core.certificate.CertificateSimpleDto;
import com.otilm.api.model.core.certificate.QcType;
import com.otilm.api.model.core.cryptography.key.KeyDto;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.entity.X509CertificateRequestEntity;
import com.otilm.core.mapper.crypto.CryptographicKeyDtoMapper;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyListModel;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.MetaDefinitions;

public class CertificateDetailDtoMapper {

    private CertificateDetailDtoMapper() {
    }

    public static CertificateDetailDto toDetailDto(Certificate certificate) {
        return buildDetailDto(certificate, false);
    }

    public static CertificateDetailDto toChainDto(Certificate certificate) {
        return buildDetailDto(certificate, true);
    }

    private static KeyDto mapKey(CryptographicKey key, boolean chainContext) {
        if (chainContext) {
            // Chain responses omit counts, so certificate links need not be queried.
            var summary = ImmutableCryptographicKeyListModel.from(key, 0);
            return CryptographicKeyDtoMapper.mapToChainDto(summary);
        }
        var fullModel = ImmutableCryptographicKeyFullModel.from(key);
        return CryptographicKeyDtoMapper.mapToDto(fullModel);
    }

    /**
     * @param chainContext whether to omit key association counts and avoid loading their certificate collections
     */
    private static CertificateDetailDto buildDetailDto(Certificate certificate, boolean chainContext) {
        final CertificateDetailDto dto = new CertificateDetailDto();
        String commonName = CertificateUtil.formatCommonName(certificate.getCommonName());
        dto.setCommonName(commonName);
        dto.setDisplayName(commonName);
        dto.setIssuerCommonName(resolveIssuerCommonName(certificate));
        if (certificate.getCertificateContent() != null) {
            dto.setCertificateContent(certificate.getCertificateContent().getContent());
            dto.setNotBefore(certificate.getNotBefore());
            dto.setNotAfter(certificate.getNotAfter());
            dto.setSubjectType(certificate.getSubjectType());
            dto.setFingerprint(certificate.getFingerprint());
            dto.setSerialNumber(certificate.getSerialNumber());
        }
        dto.setPublicKeyAlgorithm(certificate.getPublicKeyAlgorithm());
        dto.setSignatureAlgorithm(certificate.getSignatureAlgorithm());
        dto.setKeySize(certificate.getKeySize());
        dto.setUuid(certificate.getUuid().toString());
        dto.setState(certificate.getState());
        dto.setValidationStatus(certificate.getValidationStatus());
        dto.setCertificateType(certificate.getCertificateType());
        dto.setArchived(certificate.isArchived());
        if (X509CertificateEntity.fromOrNull(certificate) instanceof X509CertificateEntity x509Certificate) {
            applyX509Details(dto, x509Certificate);
        }
        if (!certificate.getPredecessorRelations().isEmpty()) {
            dto
                    .setSourceCertificateUuid(certificate
                            .getPredecessorRelations()
                            .stream()
                            .toList()
                            .getFirst()
                            .getPredecessorCertificate()
                            .getUuid());
        }
        if (certificate.getIssuerCertificateUuid() != null) {
            dto.setIssuerCertificateUuid(certificate.getIssuerCertificateUuid().toString());
        }
        if (certificate.getOwner() != null) {
            dto.setOwnerUuid(certificate.getOwner().getOwnerUuid().toString());
            dto.setOwner(certificate.getOwner().getOwnerUsername());
        }
        /*
         * Result for the compliance check of a certificate is stored in the database in the form of List of Rule IDs.
         * When the details of the certificate is requested, the Service will transform the result into the user
         * understandable format and send it. It is not moved into the mapToDto function, as the computation involves
         * other repositories like complianceRules etc., So only the overall status of the compliance will be set in the
         * mapToDto function
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
            String requestCommonName = CertificateUtil
                    .formatCommonName(certificate.getCertificateRequestEntity().getCommonName());
            certificateRequestDto.setCommonName(requestCommonName);
            certificateRequestDto.setDisplayName(requestCommonName);
            certificateRequestDto
                    .setSignatureAlgorithm(certificate.getCertificateRequestEntity().getSignatureAlgorithm());
            certificateRequestDto
                    .setPublicKeyAlgorithm(certificate.getCertificateRequestEntity().getPublicKeyAlgorithm());
            certificateRequestDto
                    .setCertificateRequestFormat(
                            certificate.getCertificateRequestEntity().getCertificateRequestFormat());
            if (X509CertificateRequestEntity
                    .fromOrNull(certificate
                            .getCertificateRequestEntity()) instanceof X509CertificateRequestEntity x509Request) {
                certificateRequestDto.setSubjectDn(x509Request.getSubjectDn());
                certificateRequestDto.setAltSignatureAlgorithm(x509Request.getAltSignatureAlgorithm());
                certificateRequestDto
                        .setSubjectAlternativeNames(
                                CertificateUtil.deserializeSans(x509Request.getSubjectAlternativeNames()));
            }
            certificateRequestDto
                    .setKeyUuid(certificate.getCertificateRequestEntity().getKeyUuid() != null
                            ? certificate.getCertificateRequestEntity().getKeyUuid().toString()
                            : null);
            certificateRequestDto
                    .setAltKeyUuid(certificate.getCertificateRequestEntity().getAltKeyUuid() != null
                            ? certificate.getCertificateRequestEntity().getAltKeyUuid().toString()
                            : null);
            certificateRequestDto.setComplianceStatus(certificate.getCertificateRequestEntity().getComplianceStatus());
            dto.setCertificateRequest(certificateRequestDto);
        }
        if (certificate.getKey() != null && !certificate.getKey().getItems().isEmpty() && !certificate
                .getKey()
                .getItems()
                .stream()
                .filter(item -> item.getType().equals(KeyType.PRIVATE_KEY) && item.getState().equals(KeyState.ACTIVE))
                .toList()
                .isEmpty()) {
            dto.setPrivateKeyAvailability(true);
        }

        if (certificate.getKey() != null) {
            dto.setKey(mapKey(certificate.getKey(), chainContext));
        }

        if (certificate.getAltKey() != null) {
            dto.setAltKey(mapKey(certificate.getAltKey(), chainContext));
        }

        if (certificate.getProtocolAssociation() != null) {
            CertificateProtocolDto protocolDto = new CertificateProtocolDto();
            protocolDto.setProtocol(certificate.getProtocolAssociation().getProtocol());
            protocolDto.setProtocolProfileUuid(certificate.getProtocolAssociation().getProtocolProfileUuid());
            protocolDto.setAdditionalProtocolUuid(certificate.getProtocolAssociation().getAdditionalProtocolUuid());
            dto.setProtocolInfo(protocolDto);
        }

        return dto;
    }

    private static void applyX509Details(CertificateDetailDto dto, X509CertificateEntity certificate) {
        if (certificate.getSubjectAlternativeNames() != null) {
            dto.setSubjectAlternativeNames(CertificateUtil.deserializeSans(certificate.getSubjectAlternativeNames()));
        }
        if (certificate.getCertificateContent() != null) {
            dto.setIssuerDn(certificate.getIssuerDn());
            dto.setExtendedKeyUsage(MetaDefinitions.deserializeArrayString(certificate.getExtendedKeyUsage()));
            dto.setKeyUsage(certificate.getKeyUsage().stream().toList());
            dto.setIssuerSerialNumber(certificate.getIssuerSerialNumber());
            applyQcStatements(dto, certificate);
        }
        dto.setSubjectDn(certificate.getSubjectDn());
        dto.setAltPublicKeyAlgorithm(certificate.getAltPublicKeyAlgorithm());
        if (certificate.getAltSignatureAlgorithm() != null) {
            dto.setAltSignatureAlgorithm(certificate.getAltSignatureAlgorithm());
        }
        dto.setAltKeySize(certificate.getAltKeySize());
        dto.setTrustedCa(certificate.getTrustedCa());
        dto.setHybridCertificate(certificate.isHybridCertificate());
    }

    private static void applyQcStatements(CertificateDetailDto dto, X509CertificateEntity certificate) {
        boolean hasAnyQc = certificate.getQcCompliance() != null || certificate.getQcSscd() != null
                || certificate.getQcType() != null || certificate.getQcCcLegislation() != null;
        if (!hasAnyQc) {
            return;
        }
        CertificateQcStatementsDto qcDto = new CertificateQcStatementsDto();
        qcDto.setQcCompliance(certificate.getQcCompliance());
        qcDto.setQcSscd(certificate.getQcSscd());
        if (certificate.getQcType() != null) {
            qcDto
                    .setQcType(MetaDefinitions
                            .deserializeArrayString(certificate.getQcType())
                            .stream()
                            .map(QcType::valueOf)
                            .toList());
        }
        if (certificate.getQcCcLegislation() != null) {
            qcDto.setQcCcLegislation(MetaDefinitions.deserializeArrayString(certificate.getQcCcLegislation()));
        }
        dto.setQcStatements(qcDto);
    }

    public static CertificateSimpleDto toSimpleDto(Certificate certificate, CertificateRelationType relationType) {
        CertificateSimpleDto dto = new CertificateSimpleDto();
        dto.setUuid(certificate.getUuid());
        dto.setCertificateType(certificate.getCertificateType());
        dto.setState(certificate.getState());
        dto.setRelationType(relationType);
        dto.setCommonName(certificate.getCommonName());
        dto.setDisplayName(CertificateUtil.formatCommonName(certificate.getCommonName()));
        dto.setIssuerCommonName(certificate.getIssuerCommonName());
        dto.setSerialNumber(certificate.getSerialNumber());
        dto.setFingerprint(certificate.getFingerprint());
        dto.setPublicKeyAlgorithm(certificate.getPublicKeyAlgorithm());
        dto.setSignatureAlgorithm(certificate.getSignatureAlgorithm());
        dto.setNotBefore(certificate.getNotBefore());
        dto.setNotAfter(certificate.getNotAfter());
        if (X509CertificateEntity.fromOrNull(certificate) instanceof X509CertificateEntity x509Certificate) {
            dto.setSubjectDn(x509Certificate.getSubjectDn());
            dto.setIssuerDn(x509Certificate.getIssuerDn());
            dto.setAltPublicKeyAlgorithm(x509Certificate.getAltPublicKeyAlgorithm());
            dto.setAltSignatureAlgorithm(x509Certificate.getAltSignatureAlgorithm());
        }
        return dto;
    }

    public static CertificateDto toListDto(Certificate certificate) {
        CertificateDto dto = new CertificateDto();
        String commonName = CertificateUtil.formatCommonName(certificate.getCommonName());
        dto.setCommonName(commonName);
        dto.setDisplayName(commonName);
        dto.setSerialNumber(certificate.getSerialNumber());
        dto.setIssuerCommonName(certificate.getIssuerCommonName());
        dto.setNotBefore(certificate.getNotBefore());
        dto.setNotAfter(certificate.getNotAfter());
        dto.setPublicKeyAlgorithm(certificate.getPublicKeyAlgorithm());
        dto.setSignatureAlgorithm(certificate.getSignatureAlgorithm());
        dto.setKeySize(certificate.getKeySize());
        dto.setUuid(certificate.getUuid().toString());
        dto.setState(certificate.getState());
        dto.setValidationStatus(certificate.getValidationStatus());
        dto.setFingerprint(certificate.getFingerprint());
        dto.setArchived(certificate.isArchived());
        if (X509CertificateEntity.fromOrNull(certificate) instanceof X509CertificateEntity x509Certificate) {
            dto.setIssuerDn(x509Certificate.getIssuerDn());
            dto.setSubjectDn(x509Certificate.getSubjectDn());
            dto.setAltPublicKeyAlgorithm(x509Certificate.getAltPublicKeyAlgorithm());
            dto.setAltSignatureAlgorithm(x509Certificate.getAltSignatureAlgorithm());
            dto.setAltKeySize(x509Certificate.getAltKeySize());
            dto.setTrustedCa(x509Certificate.getTrustedCa());
            dto.setHybridCertificate(x509Certificate.isHybridCertificate());
            dto.setIssuerSerialNumber(x509Certificate.getIssuerSerialNumber());
        }
        if (certificate.getIssuerCertificateUuid() != null) {
            dto.setIssuerCertificateUuid(certificate.getIssuerCertificateUuid().toString());
        }
        if (certificate.getOwner() != null) {
            dto.setOwnerUuid(certificate.getOwner().getOwnerUuid().toString());
            dto.setOwner(certificate.getOwner().getOwnerUsername());
        }
        dto.setCertificateType(certificate.getCertificateType());
        /*
         * Result for the compliance check of a certificate is stored in the database in the form of List of Rule IDs.
         * When the details of the certificate is requested, the Service will transform the result into the user
         * understandable format and send it. It is not moved into the mapToDto function, as the computation involves
         * other repositories like complianceRules etc., So only the overall status of the compliance will be set in the
         * mapToDto function
         */
        dto.setComplianceStatus(certificate.getComplianceStatus());

        if (certificate.getRaProfile() != null) {
            dto.setRaProfile(toSimplifiedRaProfileDto(certificate));
        }

        if (certificate.getGroups() != null) {
            dto.setGroups(certificate.getGroups().stream().map(Group::mapToDto).toList());
        }

        dto.setPrivateKeyAvailability(false);
        if (certificate.getKey() != null && !certificate.getKey().getItems().isEmpty() && !certificate
                .getKey()
                .getItems()
                .stream()
                .filter(item -> item.getType().equals(KeyType.PRIVATE_KEY) && item.getState().equals(KeyState.ACTIVE))
                .toList()
                .isEmpty()) {
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
            raDto
                    .setAuthorityInstanceUuid(
                            certificate.getRaProfile().getAuthorityInstanceReference().getUuid().toString());
        }
        return raDto;
    }
}
