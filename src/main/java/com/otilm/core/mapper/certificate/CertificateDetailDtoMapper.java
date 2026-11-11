package com.otilm.core.mapper.certificate;

import com.otilm.api.model.client.raprofile.SimplifiedRaProfileDto;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.certificate.CertificateDetail;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.certificate.CertificateProtocolDto;
import com.otilm.api.model.core.certificate.CertificateQcStatementsDto;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateRequestDetail;
import com.otilm.api.model.core.certificate.CertificateSimpleDto;
import com.otilm.api.model.core.certificate.QcType;
import com.otilm.api.model.core.certificate.X509CertificateDetail;
import com.otilm.api.model.core.certificate.X509CertificateRequestDetail;
import com.otilm.api.model.core.cryptography.key.KeyDto;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.certificate.type.UnsupportedCertificateTypeException;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRequestEntity;
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

    public static CertificateDetail toDetailDto(Certificate certificate) {
        return buildDetailDto(certificate, false);
    }

    public static CertificateDetail toChainDto(Certificate certificate) {
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
    @SuppressWarnings("deprecation")
    private static CertificateDetail buildDetailDto(Certificate certificate, boolean chainContext) {
        final CertificateDetail dto = newDetail(certificate);
        String commonName = CertificateUtil.formatCommonName(certificate.getCommonName());
        dto.setCommonName(commonName);
        dto.setDisplayName(commonName);
        dto.setIssuerCommonName(resolveIssuerCommonName(certificate));
        if (certificate.getCertificateContent() != null) {
            dto.setCertificateContent(certificate.getCertificateContent().getContent());
            dto.setNotBefore(certificate.getNotBefore());
            dto.setNotAfter(certificate.getNotAfter());
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
        if (dto instanceof X509CertificateDetail x509Dto) {
            applyX509Details(x509Dto, X509CertificateEntity.from(certificate));
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
            dto.setCertificateRequest(mapCertificateRequest(certificate));
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

        if (certificate.getAltKey() != null && dto instanceof X509CertificateDetail x509Dto) {
            x509Dto.setAltKey(mapKey(certificate.getAltKey(), chainContext));
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

    private static CertificateRequestDetail mapCertificateRequest(Certificate certificate) {
        CertificateRequestEntity request = certificate.getCertificateRequestEntity();
        final CertificateRequestDetail dto = newRequestDetail(request);
        dto.setUuid(request.getUuid());
        dto.setContent(request.getContent());
        dto.setCertificateType(request.getCertificateType());
        String requestCommonName = CertificateUtil.formatCommonName(request.getCommonName());
        dto.setCommonName(requestCommonName);
        dto.setDisplayName(requestCommonName);
        dto.setSignatureAlgorithm(request.getSignatureAlgorithm());
        dto.setPublicKeyAlgorithm(request.getPublicKeyAlgorithm());
        dto.setCertificateRequestFormat(request.getCertificateRequestFormat());
        dto.setKeyUuid(request.getKeyUuid() != null ? request.getKeyUuid().toString() : null);
        dto.setComplianceStatus(request.getComplianceStatus());
        if (dto instanceof X509CertificateRequestDetail x509Dto) {
            applyX509RequestDetails(x509Dto, X509CertificateRequestEntity.fromOrNull(request));
        }
        return dto;
    }

    private static void applyX509RequestDetails(X509CertificateRequestDetail dto,
            X509CertificateRequestEntity request) {
        dto.setSubjectDn(request.getSubjectDn());
        dto.setSubjectAlternativeNames(CertificateUtil.deserializeSans(request.getSubjectAlternativeNames()));
        dto.setAltSignatureAlgorithm(request.getAltSignatureAlgorithm());
        dto.setAltPublicKeyAlgorithm(request.getAltPublicKeyAlgorithm());
        dto.setAltKeyUuid(request.getAltKeyUuid() != null ? request.getAltKeyUuid().toString() : null);
    }

    private static CertificateDetail newDetail(Certificate certificate) {
        if (X509CertificateEntity.fromOrNull(certificate) != null) {
            return new X509CertificateDetail();
        }
        throw UnsupportedCertificateTypeException.unknownType(certificate.getCertificateType().getCode());
    }

    private static CertificateRequestDetail newRequestDetail(CertificateRequestEntity request) {
        if (X509CertificateRequestEntity.fromOrNull(request) != null) {
            return new X509CertificateRequestDetail();
        }
        throw UnsupportedCertificateTypeException.unknownType(request.getCertificateType().getCode());
    }

    private static void applyX509Details(X509CertificateDetail dto, X509CertificateEntity certificate) {
        if (certificate.getSubjectAlternativeNames() != null) {
            dto.setSubjectAlternativeNames(CertificateUtil.deserializeSans(certificate.getSubjectAlternativeNames()));
        }
        if (certificate.getCertificateContent() != null) {
            dto.setIssuerDn(certificate.getIssuerDn());
            dto.setIssuerSerialNumber(certificate.getIssuerSerialNumber());
            dto.setSubjectType(certificate.getSubjectType());
            dto.setExtendedKeyUsage(MetaDefinitions.deserializeArrayString(certificate.getExtendedKeyUsage()));
            dto.setKeyUsage(certificate.getKeyUsage().stream().toList());
            dto.setQcStatements(toQcStatements(certificate));
        }
        dto.setSubjectDn(certificate.getSubjectDn());
        dto.setHybridCertificate(certificate.isHybridCertificate());
        dto.setAltPublicKeyAlgorithm(certificate.getAltPublicKeyAlgorithm());
        dto.setAltSignatureAlgorithm(certificate.getAltSignatureAlgorithm());
        dto.setAltKeySize(certificate.getAltKeySize());
        dto.setTrustedCa(certificate.getTrustedCa());
    }

    private static CertificateQcStatementsDto toQcStatements(X509CertificateEntity certificate) {
        boolean hasAnyQc = certificate.getQcCompliance() != null || certificate.getQcSscd() != null
                || certificate.getQcType() != null || certificate.getQcCcLegislation() != null;
        if (!hasAnyQc) {
            return null;
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
        return qcDto;
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
