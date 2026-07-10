package com.otilm.core.util.builders;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateSubjectType;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.RaProfile;

import java.util.Date;
import java.util.UUID;

/**
 * Builds an in-memory {@link Certificate} entity; tests override only the fields whose values drive the
 * assertion under test. Persistence goes through {@code CertificateRepository}, not this builder — the
 * builder never touches the database.
 * <p>
 * Defaults match a bare {@code new Certificate()}: every field is left unset. Unlike most builders this one
 * carries no "valid defaults", because these service tests deliberately exercise the whole certificate
 * lifecycle — issued, pending, not-yet-issued, revoked — and rely on absent identity (null {@code commonName}
 * renders as the empty-name placeholder) and absent {@code state}. A field is written only when its
 * {@code withXxx} is called, so building with no overrides is behaviourally identical to {@code new Certificate()}.
 */
public class CertificateBuilder {

    private UUID uuid;
    private String commonName;
    private String serialNumber;
    private String fingerprint;
    private String publicKeyFingerprint;
    private String subjectDn;
    private String subjectDnNormalized;
    private String issuerDn;
    private String issuerDnNormalized;
    private String issuerSerialNumber;
    private UUID issuerCertificateUuid;
    private CertificateState state;
    private CertificateValidationStatus validationStatus;
    private CertificateSubjectType subjectType;
    private Date notBefore;
    private Boolean archived;
    private CertificateContent certificateContent;
    private Long certificateContentId;
    private RaProfile raProfile;
    private CryptographicKey key;
    private UUID keyUuid;
    private CryptographicKey altKey;
    private UUID altKeyUuid;
    private CertificateRequestEntity certificateRequest;
    private UUID certificateRequestUuid;

    public static CertificateBuilder aCertificate() {
        return new CertificateBuilder();
    }

    public CertificateBuilder withUuid(UUID uuid) {
        this.uuid = uuid;
        return this;
    }

    public CertificateBuilder withCommonName(String commonName) {
        this.commonName = commonName;
        return this;
    }

    public CertificateBuilder withSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    public CertificateBuilder withFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
        return this;
    }

    public CertificateBuilder withPublicKeyFingerprint(String publicKeyFingerprint) {
        this.publicKeyFingerprint = publicKeyFingerprint;
        return this;
    }

    public CertificateBuilder withSubjectDn(String subjectDn) {
        this.subjectDn = subjectDn;
        return this;
    }

    public CertificateBuilder withSubjectDnNormalized(String subjectDnNormalized) {
        this.subjectDnNormalized = subjectDnNormalized;
        return this;
    }

    public CertificateBuilder withIssuerDn(String issuerDn) {
        this.issuerDn = issuerDn;
        return this;
    }

    public CertificateBuilder withIssuerDnNormalized(String issuerDnNormalized) {
        this.issuerDnNormalized = issuerDnNormalized;
        return this;
    }

    public CertificateBuilder withIssuerSerialNumber(String issuerSerialNumber) {
        this.issuerSerialNumber = issuerSerialNumber;
        return this;
    }

    public CertificateBuilder withIssuerCertificateUuid(UUID issuerCertificateUuid) {
        this.issuerCertificateUuid = issuerCertificateUuid;
        return this;
    }

    public CertificateBuilder withState(CertificateState state) {
        this.state = state;
        return this;
    }

    public CertificateBuilder withValidationStatus(CertificateValidationStatus validationStatus) {
        this.validationStatus = validationStatus;
        return this;
    }

    public CertificateBuilder withSubjectType(CertificateSubjectType subjectType) {
        this.subjectType = subjectType;
        return this;
    }

    public CertificateBuilder withNotBefore(Date notBefore) {
        this.notBefore = notBefore;
        return this;
    }

    public CertificateBuilder withArchived(boolean archived) {
        this.archived = archived;
        return this;
    }

    public CertificateBuilder withCertificateContent(CertificateContent certificateContent) {
        this.certificateContent = certificateContent;
        return this;
    }

    public CertificateBuilder withCertificateContentId(Long certificateContentId) {
        this.certificateContentId = certificateContentId;
        return this;
    }

    public CertificateBuilder withRaProfile(RaProfile raProfile) {
        this.raProfile = raProfile;
        return this;
    }

    public CertificateBuilder withKey(CryptographicKey key) {
        this.key = key;
        return this;
    }

    public CertificateBuilder withKeyUuid(UUID keyUuid) {
        this.keyUuid = keyUuid;
        return this;
    }

    public CertificateBuilder withAltKey(CryptographicKey altKey) {
        this.altKey = altKey;
        return this;
    }

    public CertificateBuilder withAltKeyUuid(UUID altKeyUuid) {
        this.altKeyUuid = altKeyUuid;
        return this;
    }

    public CertificateBuilder withCertificateRequest(CertificateRequestEntity certificateRequest) {
        this.certificateRequest = certificateRequest;
        return this;
    }

    public CertificateBuilder withCertificateRequestUuid(UUID certificateRequestUuid) {
        this.certificateRequestUuid = certificateRequestUuid;
        return this;
    }

    public Certificate build() {
        Certificate certificate = new Certificate();
        if (uuid != null) certificate.setUuid(uuid);
        if (commonName != null) certificate.setCommonName(commonName);
        if (serialNumber != null) certificate.setSerialNumber(serialNumber);
        if (fingerprint != null) certificate.setFingerprint(fingerprint);
        if (publicKeyFingerprint != null) certificate.setPublicKeyFingerprint(publicKeyFingerprint);
        if (subjectDn != null) certificate.setSubjectDn(subjectDn);
        if (subjectDnNormalized != null) certificate.setSubjectDnNormalized(subjectDnNormalized);
        if (issuerDn != null) certificate.setIssuerDn(issuerDn);
        if (issuerDnNormalized != null) certificate.setIssuerDnNormalized(issuerDnNormalized);
        if (issuerSerialNumber != null) certificate.setIssuerSerialNumber(issuerSerialNumber);
        if (issuerCertificateUuid != null) certificate.setIssuerCertificateUuid(issuerCertificateUuid);
        if (state != null) certificate.setState(state);
        if (validationStatus != null) certificate.setValidationStatus(validationStatus);
        if (subjectType != null) certificate.setSubjectType(subjectType);
        if (notBefore != null) certificate.setNotBefore(notBefore);
        if (archived != null) certificate.setArchived(archived);
        if (certificateContent != null) certificate.setCertificateContent(certificateContent);
        if (certificateContentId != null) certificate.setCertificateContentId(certificateContentId);
        if (raProfile != null) certificate.setRaProfile(raProfile);
        if (key != null) certificate.setKey(key);
        if (keyUuid != null) certificate.setKeyUuid(keyUuid);
        if (altKey != null) certificate.setAltKey(altKey);
        if (altKeyUuid != null) certificate.setAltKeyUuid(altKeyUuid);
        if (certificateRequest != null) certificate.setCertificateRequest(certificateRequest);
        if (certificateRequestUuid != null) certificate.setCertificateRequestUuid(certificateRequestUuid);
        return certificate;
    }
}
