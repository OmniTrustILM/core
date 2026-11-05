package com.otilm.core.service.impl;

import com.otilm.api.model.core.authority.CertificateRevocationReason;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Crl;
import com.otilm.core.dao.entity.CrlEntry;
import com.otilm.core.dao.entity.CrlEntryId;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CrlEntryRepository;
import com.otilm.core.dao.repository.CrlRepository;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.service.CrlService;
import com.otilm.core.service.writer.CrlEntryData;
import com.otilm.core.service.writer.CrlWriter;
import com.otilm.core.util.CrlUtil;
import com.otilm.core.util.PlatformX500NameStyle;
import jakarta.persistence.EntityManager;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CRLReason;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CrlServiceImpl implements CrlService {

    private static final Logger logger = LoggerFactory.getLogger(CrlServiceImpl.class);

    private static final Duration CLOCK_SKEW = Duration.ofMinutes(5);

    private CertificateRepository certificateRepository;
    private X509CertificateRepository x509CertificateRepository;

    private CrlRepository crlRepository;

    private CrlEntryRepository crlEntryRepository;

    private CrlWriter crlWriter;

    private EntityManager entityManager;

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setX509CertificateRepository(X509CertificateRepository x509CertificateRepository) {
        this.x509CertificateRepository = x509CertificateRepository;
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

    @Autowired
    public void setEntityManager(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public UUID getCurrentCrl(X509Certificate certificate, X509Certificate issuerCertificate) throws IOException {
        byte[] issuerDnPrincipalEncoded = certificate.getIssuerX500Principal().getEncoded();
        String issuerDn = X500Name.getInstance(new PlatformX500NameStyle(true), issuerDnPrincipalEncoded).toString();
        String issuerSerialNumber = issuerCertificate.getSerialNumber().toString(16);
        Crl crl = findStoredCrl(issuerDn, issuerSerialNumber);
        Certificate caCertificate = x509CertificateRepository
                .findBySubjectDnNormalizedAndSerialNumber(issuerDn, issuerSerialNumber)
                .orElse(null);
        byte[] crlDistributionPoints = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());

        UUID caCertificateUuid = caCertificate != null ? caCertificate.getUuid() : null;
        CertificateIssuer issuer = new CertificateIssuer(certificate.getIssuerX500Principal(),
                issuerCertificate.getPublicKey());
        // If CRL is not present or current UTC time is past its next_update timestamp, download the CRL and save the
        // CRL and its entries in database
        if (crl == null) {
            Crl newCrl = downloadAndPersistNewCrl(crlDistributionPoints, issuerDn, issuerSerialNumber,
                    caCertificateUuid, issuer);
            if (newCrl != null) {
                crl = newCrl;
            }
        } else if (crl.getNextUpdate().before(new Date())) {
            refreshExistingCrl(crl, crlDistributionPoints, issuerDn, issuerSerialNumber, caCertificateUuid, issuer,
                    BigInteger.ZERO);
        }

        if (crl != null && certificate.getExtensionValue(Extension.freshestCRL.getId()) != null && isDeltaCrlDue(crl)) {
            try {
                updateCrlAndCrlEntriesFromDeltaCrl(certificate, crl, issuerDn, issuerSerialNumber, caCertificateUuid,
                        issuer);
            } catch (IOException e) {
                throwUnlessStoredCrlLists(certificate, crl, e);
            }
        }
        return crl == null ? null : crl.getUuid();
    }

    /**
     * Reads the stored CRL from its row. The writers update the row with queries that leave a loaded copy as it was,
     * and a request (open-in-view) may hold such a copy, loaded by an earlier check or with the CRL's entries, so a
     * copy found in the persistence context is dropped and the row read again. The CRL returned is detached, so the
     * request never flushes the changes made to it.
     */
    private Crl findStoredCrl(String issuerDn, String issuerSerialNumber) {
        Optional<Crl> storedCrl = crlRepository.findByIssuerDnAndSerialNumber(issuerDn, issuerSerialNumber);
        if (storedCrl.filter(entityManager::contains).isPresent()) {
            entityManager.detach(storedCrl.get());
            storedCrl = crlRepository.findByIssuerDnAndSerialNumber(issuerDn, issuerSerialNumber);
            storedCrl.ifPresent(entityManager::detach);
        }
        return storedCrl.orElse(null);
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

    /**
     * Without a current delta CRL the revocation status of a certificate that the stored CRL does not list is unknown,
     * so the failure stands. A certificate that it lists stays revoked: a delta CRL takes a certificate off only when
     * its hold is released or it expired, which cannot be assumed without seeing it.
     */
    private void throwUnlessStoredCrlLists(X509Certificate certificate, Crl crl, IOException deltaCrlFailure)
            throws IOException {
        String serialNumber = certificate.getSerialNumber().toString(16);
        if (findCrlEntryForCertificate(serialNumber, crl.getUuid()) == null) {
            throw deltaCrlFailure;
        }
        logger
                .debug("Serial number {} stays revoked as the stored CRL lists it, though no delta CRL applies",
                        serialNumber, deltaCrlFailure);
    }

    /**
     * Downloads a CRL and persists it as a brand-new {@link Crl} entity.
     *
     * @return the freshly persisted entity, or {@code null} if no configured URL returned a usable CRL.
     */
    private Crl downloadAndPersistNewCrl(byte[] crlDistributionPointsEncoded, String issuerDn,
            String issuerSerialNumber, UUID caCertificateUuid, CertificateIssuer issuer) throws IOException {
        return downloadCrl(crlDistributionPointsEncoded, issuerDn, issuerSerialNumber, caCertificateUuid, null, issuer,
                BigInteger.ZERO);
    }

    /**
     * Refreshes an existing {@link Crl} in place from the configured distribution points. The caller's {@code existing}
     * reference is mutated when a newer CRL is found. A CRL numbered below {@code lowestCrlNumber} is refused, since a
     * delta CRL extending a base CRL with that number proves that a newer CRL exists.
     */
    private void refreshExistingCrl(Crl existing, byte[] crlDistributionPointsEncoded, String issuerDn,
            String issuerSerialNumber, UUID caCertificateUuid, CertificateIssuer issuer, BigInteger lowestCrlNumber)
            throws IOException {
        downloadCrl(crlDistributionPointsEncoded, issuerDn, issuerSerialNumber, caCertificateUuid, existing, issuer,
                lowestCrlNumber);
    }

    private Crl downloadCrl(byte[] crlDistributionPointsEncoded, String issuerDn, String issuerSerialNumber,
            UUID caCertificateUuid, Crl oldCrl, CertificateIssuer issuer, BigInteger lowestCrlNumber)
            throws IOException {
        List<String> crlUrls = CrlUtil.getCDPFromCertificate(crlDistributionPointsEncoded, "cRLDistributionPoints");

        String lastReasonToIgnore = null;
        for (String crlUrl : crlUrls) {
            X509CRL x509CRL;
            try {
                x509CRL = CrlUtil.getX509Crl(crlUrl);
            } catch (Exception e) {
                logger.error("Failed to read CRL content from URL: {}, {}", crlUrl, e.getMessage());
                x509CRL = null;
            }
            String reasonToIgnore = x509CRL == null
                    ? "it could not be read"
                    : findReasonToIgnore(x509CRL, false, issuer, oldCrl, lowestCrlNumber, crlUrl);
            if (reasonToIgnore != null) {
                lastReasonToIgnore = reasonToIgnore;
                continue;
            }

            String crlNumber = readCrlNumber(x509CRL).toString();

            boolean isNewCrl = oldCrl == null;
            if (!isNewCrl && Objects.equals(crlNumber, oldCrl.getCrlNumber())) {
                return null;
            }

            Crl crl;
            if (isNewCrl) {
                crl = new Crl();
                crl.setUuid(UUID.randomUUID());
                byte[] issuerDnPrincipalEncoded = x509CRL.getIssuerX500Principal().getEncoded();
                crl
                        .setCrlIssuerDn(X500Name
                                .getInstance(new PlatformX500NameStyle(true), issuerDnPrincipalEncoded)
                                .toString());
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

            UUID persistedUuid = crlWriter.persistCrlAndEntries(crl, isNewCrl, entries, lastRevocationDate);
            crl.setUuid(persistedUuid);
            crl.setLastRevocationDate(lastRevocationDate);
            // Storing a base CRL drops the delta CRL applied to the one it replaces.
            crl.setCrlNumberDelta(null);
            crl.setNextUpdateDelta(null);
            return crl;
        }

        if (lastReasonToIgnore != null) {
            throw new IOException(
                    "Failed to read a usable CRL from %d available URL(s); the last one was ignored because %s"
                            .formatted(crlUrls.size(), lastReasonToIgnore));
        }

        return null;
    }

    private Date collectEntries(X509CRL x509CRL, List<CrlEntryData> sink) {
        Set<? extends X509CRLEntry> crlCertificates = x509CRL.getRevokedCertificates();
        if (crlCertificates == null) {
            return null;
        }
        Date lastRevocationDate = new Date(0);
        for (X509CRLEntry x509CRLEntry : crlCertificates) {
            sink.add(toEntryData(x509CRLEntry));
            if (x509CRLEntry.getRevocationDate().after(lastRevocationDate)) {
                lastRevocationDate = x509CRLEntry.getRevocationDate();
            }
        }
        return lastRevocationDate;
    }

    /**
     * Applies the first delta CRL from the certificate's freshest CRL points that extends the stored base CRL, after
     * refreshing the base CRL when the delta CRL extends a newer one.
     *
     * @throws IOException when none can be applied: with delta CRLs in use, the revocation status is unknown without a
     * current one (RFC 5280 section 6.3.3)
     */
    private void updateCrlAndCrlEntriesFromDeltaCrl(X509Certificate certificate, Crl crl, String issuerDn,
            String issuerSerialNumber, UUID caCertificateUuid, CertificateIssuer issuer) throws IOException {
        List<String> deltaCrlUrls = CrlUtil
                .getCDPFromCertificate(certificate.getExtensionValue(Extension.freshestCRL.getId()), "freshestCRL");
        if (deltaCrlUrls.isEmpty()) {
            throw new IOException("The certificate names a delta CRL without a URL to read it from");
        }
        String lastReasonToIgnore = null;
        for (String deltaCrlUrl : deltaCrlUrls) {
            X509CRL deltaCrl = readDeltaCrl(deltaCrlUrl);
            String reasonToIgnore = deltaCrl == null
                    ? "it could not be read"
                    : findReasonToIgnore(deltaCrl, true, issuer, crl, BigInteger.ZERO, deltaCrlUrl);
            if (reasonToIgnore == null && extendsNewerBaseCrl(deltaCrl, crl)) {
                refreshExistingCrl(crl, certificate.getExtensionValue(Extension.cRLDistributionPoints.getId()),
                        issuerDn, issuerSerialNumber, caCertificateUuid, issuer, readBaseCrlNumber(deltaCrl));
            }
            if (reasonToIgnore == null) {
                reasonToIgnore = findBaseCrlMismatch(deltaCrl, crl, deltaCrlUrl);
            }
            if (reasonToIgnore == null) {
                updateDeltaCrl(crl, deltaCrl);
                return;
            }
            lastReasonToIgnore = reasonToIgnore;
        }
        throw new IOException(
                "Failed to read a usable delta CRL from %d available URL(s); the last one was ignored because %s"
                        .formatted(deltaCrlUrls.size(), lastReasonToIgnore));
    }

    private static X509CRL readDeltaCrl(String deltaCrlUrl) {
        try {
            return CrlUtil.getX509Crl(deltaCrlUrl);
        } catch (Exception e) {
            logger.debug("Failed to read the delta CRL from {}: {}", deltaCrlUrl, e.getMessage());
            return null;
        }
    }

    private void updateDeltaCrl(Crl crl, X509CRL deltaCrl) throws IOException {
        BigInteger deltaCrlNumber = readCrlNumber(deltaCrl);
        // The stored delta CRL is applied already, and findReasonToIgnore refused older ones.
        if (crl.getCrlNumberDelta() != null && deltaCrlNumber.compareTo(new BigInteger(crl.getCrlNumberDelta())) <= 0) {
            return;
        }

        List<CrlEntryData> upserts = new ArrayList<>();
        List<String> removals = new ArrayList<>();
        classifyDeltaEntries(deltaCrl, upserts, removals);
        Date lastRevocationDate = Stream
                .concat(Stream.ofNullable(crl.getLastRevocationDate()),
                        upserts.stream().map(CrlEntryData::revocationDate))
                .max(Comparator.naturalOrder())
                .orElse(null);

        crlWriter
                .applyDeltaCrl(crl.getUuid(), upserts, removals, deltaCrlNumber.toString(), deltaCrl.getNextUpdate(),
                        lastRevocationDate);
    }

    /**
     * A delta CRL lists every change since its base CRL, so each entry is applied, also one dated before a revocation
     * already stored, and removeFromCRL only ever removes an entry.
     */
    private static void classifyDeltaEntries(X509CRL deltaCrl, List<CrlEntryData> upserts, List<String> removals) {
        Set<? extends X509CRLEntry> deltaCrlEntries = deltaCrl.getRevokedCertificates();
        if (deltaCrlEntries == null) {
            return;
        }
        for (X509CRLEntry deltaCrlEntry : deltaCrlEntries) {
            if (CRLReason.REMOVE_FROM_CRL.equals(deltaCrlEntry.getRevocationReason())) {
                removals.add(deltaCrlEntry.getSerialNumber().toString(16));
            } else {
                upserts.add(toEntryData(deltaCrlEntry));
            }
        }
    }

    /**
     * Returns why a CRL downloaded as a base CRL, or as a delta CRL when {@code delta} is set, cannot be used for the
     * certificate's issuer, after logging it at WARN, or {@code null} when it can. A CRL that would replace or update
     * {@code storedCrl} must not be older than it, nor numbered below {@code lowestCrlNumber}.
     */
    private static String findReasonToIgnore(X509CRL crl, boolean delta, CertificateIssuer issuer, Crl storedCrl,
            BigInteger lowestCrlNumber, String crlUrl) throws IOException {
        String reason = null;
        if (!crl.getIssuerX500Principal().equals(issuer.name())) {
            reason = "it names another issuer (%s)".formatted(crl.getIssuerX500Principal().getName());
        } else if (!isSignedBy(crl, issuer.publicKey())) {
            reason = "its signature does not verify with the issuer's public key";
        } else if (isDeltaCrl(crl) != delta) {
            reason = delta ? "it is not a delta CRL" : "it is a delta CRL";
        } else if (!isCurrent(crl)) {
            reason = "it is not current (nextUpdate %s)".formatted(crl.getNextUpdate());
        } else if (crl.getExtensionValue(Extension.cRLNumber.getId()) == null) {
            reason = "it has no CRL number";
        } else if (isOlderThan(crl, storedCrl)) {
            reason = "its CRL number %s is lower than the stored CRL number %s"
                    .formatted(readCrlNumber(crl), newestStoredCrlNumber(storedCrl));
        } else if (readCrlNumber(crl).compareTo(lowestCrlNumber) < 0) {
            reason = "its CRL number %s is lower than the base CRL number %s that a delta CRL extends"
                    .formatted(readCrlNumber(crl), lowestCrlNumber);
        }
        if (reason != null) {
            logger.warn("Ignoring the CRL from {}: {}", crlUrl, reason);
        }
        return reason;
    }

    private static boolean isSignedBy(X509CRL crl, PublicKey publicKey) {
        try {
            crl.verify(publicKey);
            return true;
        } catch (GeneralSecurityException e) {
            logger.debug("CRL signature does not verify with the key: {}", e.getMessage());
            return false;
        }
    }

    /**
     * A delta CRL is downloaded when none is stored, when the stored one is past its next update, or when the stored
     * one is numbered below the stored base CRL, so it cannot extend it.
     */
    private static boolean isDeltaCrlDue(Crl crl) {
        return crl.getCrlNumberDelta() == null || crl.getNextUpdateDelta() == null
                || new BigInteger(crl.getCrlNumberDelta()).compareTo(new BigInteger(crl.getCrlNumber())) < 0
                || crl.getNextUpdateDelta().toInstant().isBefore(Instant.now());
    }

    private static boolean isDeltaCrl(X509CRL crl) {
        return crl.getExtensionValue(Extension.deltaCRLIndicator.getId()) != null;
    }

    private static boolean isCurrent(X509CRL crl) {
        // A CRL without nextUpdate is never current, as for the JDK's CRL checker, so an old one cannot be replayed.
        Date nextUpdate = crl.getNextUpdate();
        return nextUpdate != null && !nextUpdate.toInstant().plus(CLOCK_SKEW).isBefore(Instant.now());
    }

    private static boolean isOlderThan(X509CRL crl, Crl storedCrl) throws IOException {
        return storedCrl != null && readCrlNumber(crl).compareTo(newestStoredCrlNumber(storedCrl)) < 0;
    }

    /**
     * Returns the higher of the stored base and delta CRL numbers: base and delta CRLs share one numbering sequence
     * (RFC 5280 section 5.2.3), so a base CRL numbered below an applied delta CRL predates what that delta added.
     */
    private static BigInteger newestStoredCrlNumber(Crl storedCrl) {
        BigInteger baseCrlNumber = new BigInteger(storedCrl.getCrlNumber());
        String deltaCrlNumber = storedCrl.getCrlNumberDelta();
        return deltaCrlNumber == null ? baseCrlNumber : baseCrlNumber.max(new BigInteger(deltaCrlNumber));
    }

    /**
     * Returns why a delta CRL cannot update the stored base CRL, after logging it at WARN, or {@code null} when it
     * extends that base CRL.
     */
    private static String findBaseCrlMismatch(X509CRL deltaCrl, Crl crl, String deltaCrlUrl) throws IOException {
        BigInteger baseCrlNumber = readBaseCrlNumber(deltaCrl);
        if (baseCrlNumber.equals(new BigInteger(crl.getCrlNumber()))) {
            return null;
        }
        String reason = "it extends base CRL number %s instead of the stored base CRL number %s"
                .formatted(baseCrlNumber, crl.getCrlNumber());
        logger.warn("Ignoring the CRL from {}: {}", deltaCrlUrl, reason);
        return reason;
    }

    private static boolean extendsNewerBaseCrl(X509CRL deltaCrl, Crl crl) throws IOException {
        return readBaseCrlNumber(deltaCrl).compareTo(new BigInteger(crl.getCrlNumber())) > 0;
    }

    private static BigInteger readCrlNumber(X509CRL crl) throws IOException {
        return readNumber(crl, Extension.cRLNumber);
    }

    private static BigInteger readBaseCrlNumber(X509CRL deltaCrl) throws IOException {
        return readNumber(deltaCrl, Extension.deltaCRLIndicator);
    }

    private static BigInteger readNumber(X509CRL crl, ASN1ObjectIdentifier extension) throws IOException {
        byte[] extensionValue = crl.getExtensionValue(extension.getId());
        return ASN1Integer.getInstance(JcaX509ExtensionUtils.parseExtensionValue(extensionValue)).getValue();
    }

    private static CrlEntryData toEntryData(X509CRLEntry x509CRLEntry) {
        String serialNumber = x509CRLEntry.getSerialNumber().toString(16);
        String reason = x509CRLEntry.getRevocationReason() == null
                ? CertificateRevocationReason.UNSPECIFIED.name()
                : CertificateRevocationReason.fromCrlReason(x509CRLEntry.getRevocationReason()).name();
        return new CrlEntryData(serialNumber, x509CRLEntry.getRevocationDate(), reason);
    }

    /** The name a CRL must carry and the key its signature must verify with to count for a certificate. */
    private record CertificateIssuer(X500Principal name, PublicKey publicKey) {
    }
}
