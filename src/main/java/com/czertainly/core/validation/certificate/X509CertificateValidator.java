package com.czertainly.core.validation.certificate;

import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.settings.CertificateValidationSettingsDto;
import com.czertainly.api.model.core.settings.PlatformSettingsDto;
import com.czertainly.api.model.core.settings.SettingsSection;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CrlEntry;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.service.CrlService;
import com.czertainly.core.service.writer.CertificateValidationWriter;
import com.czertainly.core.settings.SettingsCache;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.OcspUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service("X.509")
public class X509CertificateValidator implements ICertificateValidator {
    private static final Logger logger = LoggerFactory.getLogger(X509CertificateValidator.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private CertificateRepository certificateRepository;


    private CrlService crlService;

    private CertificateValidationWriter validationWriter;

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setCrlService(CrlService crlService) {
        this.crlService = crlService;
    }

    @Autowired
    public void setValidationWriter(CertificateValidationWriter validationWriter) {
        this.validationWriter = validationWriter;
    }


    @Override
    public CertificateValidationStatus validateCertificate(Certificate certificate, boolean isCompleteChain) throws CertificateException {
        logger.debug("Initiating the certificate validation: {}", certificate.toStringShort());

        ArrayList<Certificate> certificateChain = new ArrayList<>();
        Certificate lastCertificate = certificate;
        do {
            certificateChain.add(lastCertificate);
            lastCertificate = lastCertificate.getIssuerCertificateUuid() == null ? null : certificateRepository.findByUuid(lastCertificate.getIssuerCertificateUuid()).orElse(null);
        } while (lastCertificate != null);

        X509Certificate x509Certificate;
        X509Certificate x509IssuerCertificate = null;
        CertificateValidationStatus previousCertStatus = CertificateValidationStatus.NOT_CHECKED;
        Map<CertificateValidationCheck, CertificateValidationCheckDto> validationOutput;
        for (int i = certificateChain.size() - 1; i >= 0; i--) {
            // initialization by preparing X509Certificate object
            x509Certificate = CertificateUtil.getX509Certificate(certificateChain.get(i).getCertificateContent().getContent());

            boolean isEndCertificate = i == 0;
            validationOutput = validatePathCertificate(x509Certificate, x509IssuerCertificate, certificateChain.get(i).getTrustedCa(), previousCertStatus, isCompleteChain, isEndCertificate, certificateChain.get(i).getSubjectType(),
                    certificate.getRaProfile());
            CertificateValidationStatus resultStatus = calculateResultStatus(validationOutput);
            finalizeValidation(certificateChain.get(i), resultStatus, validationOutput);

            previousCertStatus = resultStatus;
            x509IssuerCertificate = x509Certificate;
        }

        logger.debug("Certificate validation of {} finalized with result: {}", certificate.toStringShort(), previousCertStatus);
        return previousCertStatus;
    }

    private Map<CertificateValidationCheck, CertificateValidationCheckDto> validatePathCertificate(X509Certificate certificate, X509Certificate issuerCertificate, Boolean trustedCa, CertificateValidationStatus issuerCertificateStatus, boolean isCompleteChain, boolean isEndCertificate, CertificateSubjectType subjectType, RaProfile raProfile) {
        Map<CertificateValidationCheck, CertificateValidationCheckDto> validationOutput = initializeValidationOutput();

        // check certificate signature
        // section (a)(1) in https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.3
        validationOutput.put(CertificateValidationCheck.SIGNATURE_VERIFICATION, checkCertificateSignature(certificate, issuerCertificate, isCompleteChain));

        // check certificate validity
        // section (a)(2) in https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.3
        validationOutput.put(CertificateValidationCheck.CERTIFICATE_VALIDITY, checkCertificateValidity(certificate, raProfile));

        // check if certificate is not revoked - OCSP & CRL
        // section (a)(3) in https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.3
        validationOutput.put(CertificateValidationCheck.OCSP_VERIFICATION, checkOcspRevocationStatus(certificate, issuerCertificate));
        validationOutput.put(CertificateValidationCheck.CRL_VERIFICATION, checkCrlRevocationStatus(certificate, issuerCertificate, isCompleteChain));

        // check certificate issuer DN and if certificate chain is valid
        // section (a)(4) in https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.3
        validationOutput.put(CertificateValidationCheck.CERTIFICATE_CHAIN, checkCertificateChain(certificate, issuerCertificate, trustedCa, issuerCertificateStatus, isCompleteChain, subjectType));

        // (k) and (l) section in https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.4
        validationOutput.put(CertificateValidationCheck.BASIC_CONSTRAINTS, checkBasicConstraints(certificate, issuerCertificate, isEndCertificate, subjectType));

        // (n) section in https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.4
        validationOutput.put(CertificateValidationCheck.KEY_USAGE, checkKeyUsage(certificate, subjectType));

        return validationOutput;
    }

    private CertificateValidationCheckDto checkCertificateChain(X509Certificate certificate, X509Certificate issuerCertificate, Boolean isTrustedCa, CertificateValidationStatus issuerCertificateStatus, boolean isCompleteChain, CertificateSubjectType subjectType) {
        if (issuerCertificate == null) {
            // should be trust anchor (Root CA certificate or self-signed certificate)
            if (isCompleteChain) {
                String certificateType = subjectType.getLabel();

                if (Boolean.TRUE.equals(isTrustedCa)) {
                    return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_CHAIN, CertificateValidationStatus.VALID, "Certificate chain is complete. Certificate is trusted " + certificateType + " certificate.");
                } else {
                    return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_CHAIN, CertificateValidationStatus.INVALID, "Certificate chain is complete. Certificate is " + certificateType + " certificate but not marked as trusted.");
                }
            } else {
                return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_CHAIN, CertificateValidationStatus.INVALID, "Incomplete certificate chain. Issuer certificate is not available in the inventory or in the AIA extension.");
            }
        } else {
            String issuerStatusMessage = "";
            if (issuerCertificateStatus.equals(CertificateValidationStatus.INVALID) || issuerCertificateStatus.equals(CertificateValidationStatus.REVOKED)) {
                issuerStatusMessage = String.format(" Issuer certificate is %s.", issuerCertificateStatus.getLabel());
            }

            String issuerNameEqualityMessage = "";
            if (!issuerCertificate.getSubjectX500Principal().getName().equals(certificate.getIssuerX500Principal().getName())) {
                issuerNameEqualityMessage = " Issuer DN does not equal to issuer certificate subject DN.";
            }

            if (isCompleteChain) {
                String trustedCaMessage = "";
                if (isTrustedCa != null) {
                    trustedCaMessage = Boolean.TRUE.equals(isTrustedCa) ? " Certificate is trusted intermediate CA." : " Certificate is intermediate CA certificate but not marked as trusted.";
                }

                CertificateValidationStatus chainValidationStatus = issuerNameEqualityMessage.isEmpty() && issuerStatusMessage.isEmpty() && (trustedCaMessage.isEmpty() || Boolean.TRUE.equals(isTrustedCa)) ? CertificateValidationStatus.VALID : CertificateValidationStatus.INVALID;
                return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_CHAIN, chainValidationStatus, "Certificate chain is complete.%s%s%s".formatted(trustedCaMessage, issuerNameEqualityMessage, issuerStatusMessage));
            } else {
                return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_CHAIN, CertificateValidationStatus.INVALID, "Incomplete certificate chain. Missing certificate in validation path.%s%s".formatted(issuerNameEqualityMessage, issuerStatusMessage));
            }
        }
    }

    private CertificateValidationCheckDto checkCertificateSignature(X509Certificate certificate, X509Certificate issuerCertificate, boolean isCompleteChain) {
        if (issuerCertificate == null) { // self-signed root CA
            if (!isCompleteChain) {
                return new CertificateValidationCheckDto(CertificateValidationCheck.SIGNATURE_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, "Issuer certificate is not available.");
            }
            return getCertificateSignatureVerification(certificate, certificate, true);
        } else {
            return getCertificateSignatureVerification(certificate, issuerCertificate, false);
        }
    }

    private CertificateValidationCheckDto getCertificateSignatureVerification(X509Certificate certificate, X509Certificate issuerCertificate, boolean selfSigned) {
        String altSignatureValidationMessage = "";
        boolean altSignatureVerified = true;
        String altMessageStart = selfSigned ? "Self-signed alternative" : "Alternative";
        if (certificate.getExtensionValue(Extension.altSignatureValue.getId()) != null) {
            altSignatureVerified = verifyAltSignature(certificate, issuerCertificate);
            altSignatureValidationMessage = altSignatureVerified ? altMessageStart + " signature verification successful." : altMessageStart + " signature verification failed.";
        }

        boolean signatureVerified = verifySignature(certificate, issuerCertificate);
        String messageStart = selfSigned ? "Self-signed signature" : "Signature";
        String signatureValidationMessage = signatureVerified ? messageStart + " verification successful. " : messageStart + " verification failed. ";

        if (altSignatureVerified && signatureVerified) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.SIGNATURE_VERIFICATION, CertificateValidationStatus.VALID, signatureValidationMessage + altSignatureValidationMessage);
        } else {
            return new CertificateValidationCheckDto(CertificateValidationCheck.SIGNATURE_VERIFICATION, CertificateValidationStatus.FAILED, signatureValidationMessage + altSignatureValidationMessage);
        }
    }

    private CertificateValidationCheckDto checkCertificateValidity(X509Certificate certificate, RaProfile raProfile) {
        Date currentUtcDate = Date.from(Instant.now());
        Date notAfterDate = certificate.getNotAfter();
        Date notBeforeDate = certificate.getNotBefore();
        if (notBeforeDate.after(currentUtcDate)) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_VALIDITY, CertificateValidationStatus.INACTIVE, "Certificate is inactive (not valid yet).");
        } else if (currentUtcDate.after(notAfterDate)) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_VALIDITY, CertificateValidationStatus.EXPIRED, "Certificate is expired.");
        } else if (isExpiring(notAfterDate, raProfile)) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_VALIDITY, CertificateValidationStatus.EXPIRING, "Certificate will expire in " + convertMillisecondsToTimeString(notAfterDate.getTime() - currentUtcDate.getTime()));
        } else {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_VALIDITY, CertificateValidationStatus.VALID, "Certificate is valid.");
        }
    }

    private boolean isExpiring(Date notAfterDate, RaProfile raProfile) {
        int expiringThreshold;
        if (raProfile == null || raProfile.getValidationEnabled() == null) {
            PlatformSettingsDto platformSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
            CertificateValidationSettingsDto validationSettings = platformSettings.getCertificates().getValidation();
            expiringThreshold = validationSettings.getExpiringThreshold();
        } else {
            expiringThreshold = raProfile.getExpiringThreshold();
        }
        return (notAfterDate.getTime() - Date.from(Instant.now()).getTime()) < TimeUnit.DAYS.toMillis(expiringThreshold);
    }

    private CertificateValidationCheckDto checkOcspRevocationStatus(X509Certificate certificate, X509Certificate issuerCertificate) {
        if (issuerCertificate == null) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.OCSP_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, "Issuer certificate is not available.");
        }

        List<String> ocspUrls;
        try {
            ocspUrls = OcspUtil.getOcspUrlFromCertificate(certificate);
        } catch (IOException e) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.OCSP_VERIFICATION, CertificateValidationStatus.FAILED, "Failed to retrieve OCSP URL from certificate: " + e.getMessage());
        }

        if (ocspUrls.isEmpty()) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.OCSP_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, "Certificate does not contain AIA extension or OCSP URL is not present");
        }

        StringBuilder ocspMessage = new StringBuilder();
        CertificateValidationStatus ocspOutputStatus = CertificateValidationStatus.NOT_CHECKED;
        for (String ocspUrl : ocspUrls) {
            try {
                CertificateValidationStatus ocspStatus = OcspUtil.checkOcsp(certificate, issuerCertificate, ocspUrl);
                if (ocspStatus.equals(CertificateValidationStatus.VALID)) {
                    if (ocspOutputStatus.equals(CertificateValidationStatus.NOT_CHECKED)) {
                        ocspOutputStatus = ocspStatus;
                    }
                    ocspMessage.append("OCSP verification successful from URL ");
                    ocspMessage.append(ocspUrl);
                    ocspMessage.append(". ");
                } else if (ocspStatus.equals(CertificateValidationStatus.REVOKED)) {
                    ocspOutputStatus = ocspStatus;
                    ocspMessage.append("Certificate was revoked according to information from OCSP URL ");
                    ocspMessage.append(ocspUrl);
                    ocspMessage.append(". ");
                    break;
                } else {
                    ocspOutputStatus = ocspStatus;
                    ocspMessage.append("OCSP Check result is unknown from URL ");
                    ocspMessage.append(ocspUrl);
                    ocspMessage.append(". ");
                }
            } catch (Exception e) {
                logger.debug("Not able to check OCSP: {}", e.getMessage());
                ocspOutputStatus = CertificateValidationStatus.FAILED;
                ocspMessage.append("Error while checking OCSP URL ");
                ocspMessage.append(ocspUrl);
                ocspMessage.append(". Error: ");
                ocspMessage.append(e.getMessage());
                ocspMessage.append(". ");
            }
        }

        return new CertificateValidationCheckDto(CertificateValidationCheck.OCSP_VERIFICATION, ocspOutputStatus, ocspMessage.toString());
    }

    private CertificateValidationCheckDto checkCrlRevocationStatus(X509Certificate certificate, X509Certificate issuerCertificate, boolean isCompleteChain) {
        if (issuerCertificate == null) {
            if (!isCompleteChain)
                return new CertificateValidationCheckDto(CertificateValidationCheck.CRL_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, "Issuer certificate is not available.");
            issuerCertificate = certificate;
        }

        if (certificate.getExtensionValue(Extension.cRLDistributionPoints.getId()) == null) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CRL_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, "The cRLDistributionPoints extension is not set.");
        }
        UUID crlUuid;
        try {
            crlUuid = crlService.getCurrentCrl(certificate, issuerCertificate);
        } catch (IOException e) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CRL_VERIFICATION, CertificateValidationStatus.FAILED, "Failed to retrieve CRL: " + e.getMessage());
        } catch (ValidationException e) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CRL_VERIFICATION, CertificateValidationStatus.FAILED, "Failed to process CRL: " + e.getMessage());
        }

        if (crlUuid == null) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.CRL_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, "No available working CRL URL found in cRLDistributionPoints extension.");
        }

        StringBuilder crlMessage = new StringBuilder();
        CertificateValidationStatus crlOutputStatus;

        CrlEntry crlEntry = crlService.findCrlEntryForCertificate(certificate.getSerialNumber().toString(16), crlUuid);

        if (crlEntry == null) {
            crlOutputStatus = CertificateValidationStatus.VALID;
            crlMessage.append("CRL verification successful from URL");
            crlMessage.append(". ");
        } else {
            crlOutputStatus = CertificateValidationStatus.REVOKED;
            crlMessage.append("Certificate was revoked according to information from CRL URL");
            crlMessage.append(". Revocation reason: ");
            crlMessage.append(crlEntry.getRevocationReason().getLabel());
            crlMessage.append(". ");
        }
        return new CertificateValidationCheckDto(CertificateValidationCheck.CRL_VERIFICATION, crlOutputStatus, crlMessage.toString());
    }


    private CertificateValidationCheckDto checkBasicConstraints(X509Certificate certificate, X509Certificate issuerCertificate, boolean isEndCertificate, CertificateSubjectType subjectType) {
        int pathLenConstraint = certificate.getBasicConstraints();
        boolean isCa = subjectType.isCa();

        if (!isCa) {
            if (certificate.getVersion() == 3 && !isEndCertificate) {
                return new CertificateValidationCheckDto(CertificateValidationCheck.BASIC_CONSTRAINTS, CertificateValidationStatus.INVALID, "Certificate is not end certificate in chain and is not marked as CA");
            } else if (certificate.getVersion() != 3) {
                return new CertificateValidationCheckDto(CertificateValidationCheck.BASIC_CONSTRAINTS, CertificateValidationStatus.FAILED, "Certificate is not last in chain and cannot verify if it is a CA certificate");
            }
        } else if (issuerCertificate != null && pathLenConstraint > issuerCertificate.getBasicConstraints()) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.BASIC_CONSTRAINTS, CertificateValidationStatus.INVALID, "Certificate path length is greater than path length in issuer certificate");
        }

        return new CertificateValidationCheckDto(CertificateValidationCheck.BASIC_CONSTRAINTS, CertificateValidationStatus.VALID, "Certificate basic constraints verification successful.");
    }

    private CertificateValidationCheckDto checkKeyUsage(X509Certificate certificate, CertificateSubjectType subjectType) {

        if (!subjectType.isCa()) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.KEY_USAGE, CertificateValidationStatus.NOT_CHECKED, "Certificate is not CA.");
        }

        if (CertificateUtil.isKeyUsagePresent(certificate.getKeyUsage(), CertificateKeyUsage.KEY_CERT_SIGN)) {
            return new CertificateValidationCheckDto(CertificateValidationCheck.KEY_USAGE, CertificateValidationStatus.VALID, "Certificate keyCertSign bit is set and can be used to verify signatures on other certificates.");
        } else {
            return new CertificateValidationCheckDto(CertificateValidationCheck.KEY_USAGE, CertificateValidationStatus.INVALID, "Certificate keyCertSign bit is not set and cannot be used to verify signatures on other certificates.");
        }
    }

    private CertificateValidationStatus calculateResultStatus(Map<CertificateValidationCheck, CertificateValidationCheckDto> validationOutput) {
        CertificateValidationCheckDto certificateValidationDto = validationOutput.get(CertificateValidationCheck.CERTIFICATE_CHAIN);
        if (!certificateValidationDto.getStatus().equals(CertificateValidationStatus.VALID)) {
            return CertificateValidationStatus.INVALID;
        }
        certificateValidationDto = validationOutput.get(CertificateValidationCheck.SIGNATURE_VERIFICATION);
        if (!certificateValidationDto.getStatus().equals(CertificateValidationStatus.VALID)) {
            return CertificateValidationStatus.INVALID;
        }

        CertificateValidationCheckDto validityCertificateValidationDto = validationOutput.get(CertificateValidationCheck.CERTIFICATE_VALIDITY);
        if (validityCertificateValidationDto.getStatus().equals(CertificateValidationStatus.INACTIVE)) {
            return CertificateValidationStatus.INACTIVE;
        }
        if (validityCertificateValidationDto.getStatus().equals(CertificateValidationStatus.EXPIRED)) {
            return CertificateValidationStatus.EXPIRED;
        }

        if (validationOutput.get(CertificateValidationCheck.OCSP_VERIFICATION).getStatus().equals(CertificateValidationStatus.REVOKED)
                || validationOutput.get(CertificateValidationCheck.CRL_VERIFICATION).getStatus().equals(CertificateValidationStatus.REVOKED)) {
            return CertificateValidationStatus.REVOKED;
        }

        if (validityCertificateValidationDto.getStatus().equals(CertificateValidationStatus.EXPIRING)) {
            return CertificateValidationStatus.EXPIRING;
        }

        return CertificateValidationStatus.VALID;
    }

    private void finalizeValidation(Certificate certificate, CertificateValidationStatus resultStatus, Map<CertificateValidationCheck, CertificateValidationCheckDto> validationOutput) throws CertificateException {
        OffsetDateTime now = OffsetDateTime.now();
        String resultJson;
        try {
            resultJson = OBJECT_MAPPER.writeValueAsString(validationOutput);
        } catch (Exception e) {
            throw new CertificateException("Error in serialization of validation output for " + certificate);
        }

        validationWriter.applyValidationResult(certificate.getUuid(), resultStatus, now, resultJson);
        // Keep the in-memory entity coherent with what was just persisted.
        certificate.setValidationStatus(resultStatus);
        certificate.setStatusValidationTimestamp(now);
        certificate.setCertificateValidationResult(resultJson);

        boolean ocspOrCrlSaysRevoked =
                validationOutput.get(CertificateValidationCheck.OCSP_VERIFICATION).getStatus().equals(CertificateValidationStatus.REVOKED)
                || validationOutput.get(CertificateValidationCheck.CRL_VERIFICATION).getStatus().equals(CertificateValidationStatus.REVOKED);
        if (certificate.getState() == CertificateState.ISSUED && ocspOrCrlSaysRevoked) {
            int rows = validationWriter.markRevokedIfStillIssued(certificate.getUuid());
            if (rows == 1) {
                // Transition happened successfully.
                certificate.setState(CertificateState.REVOKED);
            } else {
                // Transition did not happen - most likely some concurrent update has already set the state.
                // Read back the state outside the writer's tx and classify the outcome.
                CertificateState observed = certificateRepository.findStateByUuid(certificate.getUuid()).orElse(null);
                switch (classifyZeroRowOutcome(observed)) {
                    case INTENT_ALREADY_SATISFIED ->
                            logger.info("OCSP/CRL-driven revoke for {} skipped; state already {}", certificate.getUuid(), observed);
                    case STATE_DIVERGENCE ->
                            logger.warn("OCSP/CRL wanted to mark {} REVOKED but row is now in {} — manual reconciliation may be needed",
                                    certificate.getUuid(), observed);
                }
            }
        }
    }

    /**
     * Read-back classification: given the observed state after a 0-row return from {@code transitionIssuedToRevoked},
     * decide whether OCSP/CRL's revoke intent has already been fulfilled by a concurrent path (a peer revoke transaction
     * reached the row first) or whether the state has diverged from the external truth and requires manual reconciliation.
     */
    static ZeroRowOutcome classifyZeroRowOutcome(CertificateState observed) {
        if (observed == CertificateState.REVOKED || observed == CertificateState.PENDING_REVOKE) {
            return ZeroRowOutcome.INTENT_ALREADY_SATISFIED;
        }
        return ZeroRowOutcome.STATE_DIVERGENCE;
    }

    enum ZeroRowOutcome { INTENT_ALREADY_SATISFIED, STATE_DIVERGENCE }

    private boolean verifySignature(X509Certificate subjectCertificate, X509Certificate issuerCertificate) {
        try {
            subjectCertificate.verify(issuerCertificate.getPublicKey());
            return true;
        } catch (Exception e) {
            logger.debug("Unable to verify certificate for signature", e);
            return false;
        }
    }

    private boolean verifyAltSignature(X509Certificate subjectCertificate, X509Certificate issuerCertificate) {
        try {
            X509CertificateHolder holder = new JcaX509CertificateHolder(subjectCertificate);
            return holder.isAlternativeSignatureValid(new JcaContentVerifierProviderBuilder().build(CertificateUtil.getAltPublicKey(issuerCertificate.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId()))));
        } catch (Exception e) {
            logger.debug("Unable to verify certificate for alternative signature", e);
            return false;
        }
    }

    private String convertMillisecondsToTimeString(long milliseconds) {
        final long dy = TimeUnit.MILLISECONDS.toDays(milliseconds);
        final long hr = TimeUnit.MILLISECONDS.toHours(milliseconds)
                - TimeUnit.DAYS.toHours(TimeUnit.MILLISECONDS.toDays(milliseconds));
        final long min = TimeUnit.MILLISECONDS.toMinutes(milliseconds)
                - TimeUnit.HOURS.toMinutes(TimeUnit.MILLISECONDS.toHours(milliseconds));
        final long sec = TimeUnit.MILLISECONDS.toSeconds(milliseconds)
                - TimeUnit.MINUTES.toSeconds(TimeUnit.MILLISECONDS.toMinutes(milliseconds));

        return "%d days %d hours %d minutes %d seconds".formatted(dy, hr, min, sec);
    }

    private Map<CertificateValidationCheck, CertificateValidationCheckDto> initializeValidationOutput() {
        Map<CertificateValidationCheck, CertificateValidationCheckDto> validationOutput = new LinkedHashMap<>();
        validationOutput.put(CertificateValidationCheck.CERTIFICATE_CHAIN, new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_CHAIN, CertificateValidationStatus.NOT_CHECKED, null));
        validationOutput.put(CertificateValidationCheck.SIGNATURE_VERIFICATION, new CertificateValidationCheckDto(CertificateValidationCheck.SIGNATURE_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, null));
        validationOutput.put(CertificateValidationCheck.CERTIFICATE_VALIDITY, new CertificateValidationCheckDto(CertificateValidationCheck.CERTIFICATE_VALIDITY, CertificateValidationStatus.NOT_CHECKED, null));
        validationOutput.put(CertificateValidationCheck.OCSP_VERIFICATION, new CertificateValidationCheckDto(CertificateValidationCheck.OCSP_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, null));
        validationOutput.put(CertificateValidationCheck.CRL_VERIFICATION, new CertificateValidationCheckDto(CertificateValidationCheck.CRL_VERIFICATION, CertificateValidationStatus.NOT_CHECKED, null));
        validationOutput.put(CertificateValidationCheck.BASIC_CONSTRAINTS, new CertificateValidationCheckDto(CertificateValidationCheck.BASIC_CONSTRAINTS, CertificateValidationStatus.NOT_CHECKED, null));
        validationOutput.put(CertificateValidationCheck.KEY_USAGE, new CertificateValidationCheckDto(CertificateValidationCheck.KEY_USAGE, CertificateValidationStatus.NOT_CHECKED, null));
        return validationOutput;
    }

}
