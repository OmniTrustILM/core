package com.czertainly.core.service.impl;

import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.core.authority.CertificateRevocationReason;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.CrlEntryRepository;
import com.czertainly.core.dao.repository.CrlRepository;
import com.czertainly.core.service.CrlService;
import com.czertainly.core.service.writer.CrlEntryData;
import com.czertainly.core.service.writer.CrlWriter;
import com.czertainly.core.util.CrlUtil;
import com.czertainly.core.util.CzertainlyX500NameStyle;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.cert.*;
import java.util.*;

@Service
public class CrlServiceImpl implements CrlService {

    private static final Logger logger = LoggerFactory.getLogger(CrlServiceImpl.class);

    private CertificateRepository certificateRepository;

    private CrlRepository crlRepository;

    private CrlEntryRepository crlEntryRepository;

    private CrlWriter crlWriter;

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setCrlRepository(CrlRepository crlRepository) {
        this.crlRepository = crlRepository;
    }

    @Autowired
    public void setCrlEntryRepository(CrlEntryRepository crlEntryRepository) {
        this.crlEntryRepository = crlEntryRepository;
    }

    @Autowired
    public void setCrlWriter(CrlWriter crlWriter) {
        this.crlWriter = crlWriter;
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public UUID getCurrentCrl(X509Certificate certificate, X509Certificate issuerCertificate) throws IOException {
        byte[] issuerDnPrincipalEncoded = certificate.getIssuerX500Principal().getEncoded();
        String issuerDn = X500Name.getInstance(new CzertainlyX500NameStyle(true), issuerDnPrincipalEncoded).toString();
        String issuerSerialNumber = issuerCertificate.getSerialNumber().toString(16);
        Crl crl = crlRepository.findByIssuerDnAndSerialNumber(issuerDn, issuerSerialNumber).orElse(null);
        Certificate caCertificate = certificateRepository.findBySubjectDnNormalizedAndSerialNumber(issuerDn, issuerSerialNumber).orElse(null);
        byte[] crlDistributionPoints = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());

        UUID caCertificateUuid = caCertificate != null ? caCertificate.getUuid() : null;
        // If CRL is not present or current UTC time is past its next_update timestamp, download the CRL and save the CRL and its entries in database
        if (crl == null || crl.getNextUpdate().before(new Date())) {
            Crl newCrl = createCrlAndCrlEntries(crlDistributionPoints, issuerDn, issuerSerialNumber, caCertificateUuid, crl);
            // If CRL received is not null, then the downloaded CRL is updated CRL, delete old CRL and use updated one
            if (newCrl != null) {
                crl = newCrl;
            }
        }

        // Check if certificate has freshestCrl extension set
        if (certificate.getExtensionValue(Extension.freshestCRL.getId()) != null && (crl != null && (crl.getNextUpdateDelta() == null || !crl.getNextUpdateDelta().before(new Date())))) {
            // If no delta CRL is set or delta CRL is not up-to-date, download delta CRL
            updateCrlAndCrlEntriesFromDeltaCrl(certificate, crl, issuerDn, issuerSerialNumber, caCertificateUuid);
        }
        return crl == null ? null : crl.getUuid();
    }

    @Override
    public CrlEntry findCrlEntryForCertificate(String serialNumber, UUID crlUuid) {
        CrlEntryId crlEntryId = new CrlEntryId(crlUuid, serialNumber);
        return crlEntryRepository.findById(crlEntryId).orElse(null);
    }

    @Override
    public void clearCrlsForCaCertificate(List<UUID> caCertificateUuids) {
        crlRepository.clearCaCertificateReferenceIn(caCertificateUuids);
    }

    private Crl createCrlAndCrlEntries(byte[] crlDistributionPointsEncoded, String issuerDn, String issuerSerialNumber, UUID caCertificateUuid, Crl oldCrl) throws IOException {
        List<String> crlUrls = CrlUtil.getCDPFromCertificate(crlDistributionPointsEncoded);

        boolean failedToRead = false;
        for (String crlUrl : crlUrls) {
            X509CRL x509CRL;
            try {
                x509CRL = CrlUtil.getX509Crl(crlUrl);
            } catch (Exception e) {
                // Failed to read content from URL, continue to next URL
                logger.error("Failed to read CRL content from URL: {}, {}", crlUrl, e.getMessage());
                failedToRead = true;
                continue;
            }

            String crlNumber = JcaX509ExtensionUtils.parseExtensionValue(x509CRL.getExtensionValue(Extension.cRLNumber.getId())).toString();

            boolean isNewCrl = oldCrl == null;
            if (!isNewCrl && Objects.equals(crlNumber, oldCrl.getCrlNumber())) {
                return null;
            }

            Crl crl;
            if (isNewCrl) {
                crl = new Crl();
                crl.setUuid(UUID.randomUUID());
                byte[] issuerDnPrincipalEncoded = x509CRL.getIssuerX500Principal().getEncoded();
                crl.setCrlIssuerDn(X500Name.getInstance(new CzertainlyX500NameStyle(true), issuerDnPrincipalEncoded).toString());
                crl.setSerialNumber(issuerSerialNumber);
                crl.setIssuerDn(issuerDn);
                crl.setCaCertificateUuid(caCertificateUuid);
            } else {
                crl = oldCrl;
            }
            crl.setNextUpdate(x509CRL.getNextUpdate());
            crl.setCrlNumber(crlNumber);

            List<CrlEntryData> entries = new ArrayList<>();
            Date lastRevocationDate = collectEntries(x509CRL, entries);

            return crlWriter.persistCrlAndEntries(crl, isNewCrl, entries, lastRevocationDate);
        }

        if (failedToRead) {
            throw new IOException("Failed to read CRL from %d available URL(s)".formatted(crlUrls.size()));
        }

        return null;
    }

    private Date collectEntries(X509CRL x509CRL, List<CrlEntryData> sink) {
        Set<? extends X509CRLEntry> crlCertificates = x509CRL.getRevokedCertificates();
        if (crlCertificates == null) return null;
        Date lastRevocationDate = new Date(0);
        for (X509CRLEntry x509CRLEntry : crlCertificates) {
            sink.add(toEntryData(x509CRLEntry));
            if (x509CRLEntry.getRevocationDate().after(lastRevocationDate)) {
                lastRevocationDate = x509CRLEntry.getRevocationDate();
            }
        }
        return lastRevocationDate;
    }

    private void updateCrlAndCrlEntriesFromDeltaCrl(X509Certificate certificate, Crl crl, String issuerDn, String issuerSerialNumber, UUID caCertificateUuid) throws IOException {
        List<String> deltaCrlUrls = CrlUtil.getCDPFromCertificate(certificate.getExtensionValue(Extension.freshestCRL.getId()));
        for (String deltaCrlUrl : deltaCrlUrls) {
            X509CRL deltaCrl;
            try {
                deltaCrl = CrlUtil.getX509Crl(deltaCrlUrl);
            } catch (Exception e) {
                // Failed to read content from URL, continue to next URL
                continue;
            }
            String deltaCrlIssuer = X500Name.getInstance(new CzertainlyX500NameStyle(true), deltaCrl.getIssuerX500Principal().getEncoded()).toString();
            // Compare CRL issuer with issuer stored in CRL entity, delta CRL is invalid if they are not the same
            if (!Objects.equals(deltaCrlIssuer, crl.getCrlIssuerDn()))
                throw new ValidationException("Delta CRL issuer not same as issuer stored in CRL entity");

            // Compare DeltaCRLIndicator with base CRL number, if they are not equal, try to get newer CRL
            String deltaCrlIndicator = JcaX509ExtensionUtils.parseExtensionValue(deltaCrl.getExtensionValue(Extension.deltaCRLIndicator.getId())).toString();
            if (!Objects.equals(deltaCrlIndicator, crl.getCrlNumber())) {
                Crl newCrl = createCrlAndCrlEntries(certificate.getExtensionValue(Extension.cRLDistributionPoints.getId()), issuerDn, issuerSerialNumber, caCertificateUuid, crl);
                // If received CRL is null, it means it is the old one again, and we are not able to set delta CRL properly
                if (newCrl == null)
                    throw new ValidationException("Unable to get CRL with base CRL number equal to DeltaCRLIndicator");
                // Otherwise delete the old CRL and continue with the new CRL
                crl = newCrl;
            }
            updateDeltaCrl(crl, deltaCrl);
            // Managed to process a delta CRL url and do not need to try other URLs
            return;
        }
    }


    private void updateDeltaCrl(Crl crl, X509CRL deltaCrl) throws IOException {
        ASN1Primitive encodedCrlNumber = JcaX509ExtensionUtils.parseExtensionValue(deltaCrl.getExtensionValue(Extension.cRLNumber.getId()));
        // If delta CRL number has been set, check if delta CRL number is greater than one in DB entity, if it is, process delta CRL entries
        if (crl.getCrlNumberDelta() != null && Integer.parseInt(encodedCrlNumber.toString()) <= Integer.parseInt(crl.getCrlNumberDelta())) {
            return;
        }

        Map<String, CrlEntry> existing = new HashMap<>();
        for (CrlEntry e : crlEntryRepository.findAllByCrlUuid(crl.getUuid())) {
            existing.put(e.getId().getSerialNumber(), e);
        }

        List<CrlEntryData> upserts = new ArrayList<>();
        List<String> removals = new ArrayList<>();
        Date lastRevocationDateNew = classifyDeltaEntries(deltaCrl, existing, crl.getLastRevocationDate(), upserts, removals);

        crlWriter.applyDeltaCrl(
                crl.getUuid(), upserts, removals,
                encodedCrlNumber.toString(), deltaCrl.getNextUpdate(), lastRevocationDateNew);
    }

    private Date classifyDeltaEntries(X509CRL deltaCrl,
                                      Map<String, CrlEntry> existing,
                                      Date lastRevocationDate,
                                      List<CrlEntryData> upserts,
                                      List<String> removals) {
        Set<? extends X509CRLEntry> deltaCrlEntries = deltaCrl.getRevokedCertificates();
        if (deltaCrlEntries == null) return lastRevocationDate;

        Date lastRevocationDateNew = lastRevocationDate;
        for (X509CRLEntry deltaCrlEntry : deltaCrlEntries) {
            Date entryRevocationDate = deltaCrlEntry.getRevocationDate();
            // Process only entries which revocation date is >= last_revocation_date, others are already in DB
            if (lastRevocationDate != null
                    && entryRevocationDate.before(lastRevocationDate)) {
                continue;
            }
            String serialNumber = deltaCrlEntry.getSerialNumber().toString(16);
            CrlEntry existingEntry = existing.get(serialNumber);
            if (existingEntry == null) {
                upserts.add(toEntryData(deltaCrlEntry));
            } else if (Objects.equals(deltaCrlEntry.getRevocationReason(), CRLReason.REMOVE_FROM_CRL)) {
                removals.add(serialNumber);
            } else {
                upserts.add(toEntryData(deltaCrlEntry));
            }
            if (lastRevocationDateNew == null || lastRevocationDateNew.before(entryRevocationDate)) {
                lastRevocationDateNew = entryRevocationDate;
            }
        }
        return lastRevocationDateNew;
    }

    private static CrlEntryData toEntryData(X509CRLEntry x509CRLEntry) {
        String serialNumber = x509CRLEntry.getSerialNumber().toString(16);
        String reason = x509CRLEntry.getRevocationReason() == null
                ? CertificateRevocationReason.UNSPECIFIED.name()
                : CertificateRevocationReason.fromCrlReason(x509CRLEntry.getRevocationReason()).name();
        return new CrlEntryData(serialNumber, x509CRLEntry.getRevocationDate(), reason);
    }
}
