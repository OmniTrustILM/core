package com.otilm.core.mapper.certificate;

import com.otilm.api.model.core.certificate.CertificateQcStatementsDto;
import com.otilm.api.model.core.certificate.QcType;
import com.otilm.api.model.core.certificate.X509CertificateRequestTypeDetailsDto;
import com.otilm.api.model.core.certificate.X509CertificateTypeDetailsDto;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.entity.X509CertificateRequestEntity;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.MetaDefinitions;

/** Maps what only X.509 certificates and requests have to the type-specific section of the API. */
public final class X509TypeDetailsMapper {

    private X509TypeDetailsMapper() {
    }

    /**
     * Content that comes from the issued certificate is left empty for a certificate that has no content yet, such as a
     * registration that is waiting for its request.
     */
    public static X509CertificateTypeDetailsDto toDetails(X509CertificateEntity certificate) {
        X509CertificateTypeDetailsDto details = new X509CertificateTypeDetailsDto();
        if (certificate.getSubjectAlternativeNames() != null) {
            details
                    .setSubjectAlternativeNames(
                            CertificateUtil.deserializeSans(certificate.getSubjectAlternativeNames()));
        }
        if (certificate.getCertificateContent() != null) {
            details.setIssuerDn(certificate.getIssuerDn());
            details.setIssuerSerialNumber(certificate.getIssuerSerialNumber());
            details.setExtendedKeyUsage(MetaDefinitions.deserializeArrayString(certificate.getExtendedKeyUsage()));
            details.setKeyUsage(certificate.getKeyUsage().stream().toList());
            details.setQcStatements(toQcStatements(certificate));
        }
        details.setSubjectType(certificate.getSubjectType());
        details.setCommonName(CertificateUtil.formatCommonName(certificate.getCommonName()));
        details.setSubjectDn(certificate.getSubjectDn());
        details.setHybridCertificate(certificate.isHybridCertificate());
        details.setAltPublicKeyAlgorithm(certificate.getAltPublicKeyAlgorithm());
        details.setAltSignatureAlgorithm(certificate.getAltSignatureAlgorithm());
        details.setAltKeySize(certificate.getAltKeySize());
        return details;
    }

    public static X509CertificateRequestTypeDetailsDto toRequestDetails(X509CertificateRequestEntity request) {
        X509CertificateRequestTypeDetailsDto details = new X509CertificateRequestTypeDetailsDto();
        details.setCommonName(CertificateUtil.formatCommonName(request.getCommonName()));
        details.setSubjectDn(request.getSubjectDn());
        details.setSubjectAlternativeNames(CertificateUtil.deserializeSans(request.getSubjectAlternativeNames()));
        details.setAltSignatureAlgorithm(request.getAltSignatureAlgorithm());
        details.setAltPublicKeyAlgorithm(request.getAltPublicKeyAlgorithm());
        details.setAltKeyUuid(request.getAltKeyUuid() != null ? request.getAltKeyUuid().toString() : null);
        return details;
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
}
