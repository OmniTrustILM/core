package com.otilm.core.service.impl;

import com.otilm.api.model.core.authority.CertificateRevocationReason;
import com.otilm.core.aop.OutsideTransaction;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Crl;
import com.otilm.core.dao.entity.CrlEntry;
import com.otilm.core.dao.entity.CrlEntryId;
import com.otilm.core.dao.repository.CrlEntryRepository;
import com.otilm.core.dao.repository.CrlRepository;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.service.CrlService;
import com.otilm.core.service.writer.CrlEntryData;
import com.otilm.core.service.writer.CrlWriter;
import com.otilm.core.service.writer.CrlWriter.CrlWrite;
import com.otilm.core.util.CrlUtil;
import com.otilm.core.util.PlatformX500NameStyle;
import com.otilm.core.util.crl.CrlDownloadException;
import com.otilm.core.util.crl.CrlDownloadGuard;
import com.otilm.core.util.crl.CrlDownloader;
import com.otilm.core.util.crl.CrlRefusedException;
import com.otilm.core.util.crl.EncodedCrl;
import com.otilm.core.util.crl.RevokedCertificate;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CRLReason;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionException;

@Service
public class CrlServiceImpl implements CrlService {

    private static final Logger logger = LoggerFactory.getLogger(CrlServiceImpl.class);

    private static final Duration CLOCK_SKEW = Duration.ofMinutes(5);

    private X509CertificateRepository x509CertificateRepository;

    private CrlRepository crlRepository;

    private CrlEntryRepository crlEntryRepository;

    private CrlWriter crlWriter;

    private EntityManager entityManager;

    private CrlDownloader crlDownloader;

    private CrlDownloadGuard crlDownloadGuard;

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

    @Autowired
    public void setCrlDownloader(CrlDownloader crlDownloader) {
        this.crlDownloader = crlDownloader;
    }

    @Autowired
    public void setCrlDownloadGuard(CrlDownloadGuard crlDownloadGuard) {
        this.crlDownloadGuard = crlDownloadGuard;
    }

    /**
     * Returns the stored CRL while it is current. Otherwise one validation of the issuer at a time downloads it, and
     * those that waited find it stored.
     *
     * <p>
     * When the stored base CRL is current and only its delta CRL is due, a certificate the stored CRL lists stays
     * revoked even if the delta CRL cannot be read, as {@link #throwUnlessStoredCrlLists} decides; this holds also when
     * the wait for the issuer or for a download permit ends first. After a failure the stored CRL is read again, so a
     * CRL another validation stored meanwhile is used.
     */
    @Override
    @OutsideTransaction
    public UUID getCurrentCrl(X509Certificate certificate, X509Certificate issuerCertificate) throws IOException {
        byte[] issuerDnPrincipalEncoded = certificate.getIssuerX500Principal().getEncoded();
        String issuerDn = X500Name.getInstance(new PlatformX500NameStyle(true), issuerDnPrincipalEncoded).toString();
        String issuerSerialNumber = issuerCertificate.getSerialNumber().toString(16);
        Crl storedCrl = findStoredCrl(issuerDn, issuerSerialNumber);
        if (storedCrl != null && !isDue(storedCrl, certificate)) {
            return storedCrl.getUuid();
        }
        try {
            return crlDownloadGuard.underIssuerLock(issuerDn + "|" + issuerSerialNumber, () -> {
                Crl crlStoredMeanwhile = findStoredCrl(issuerDn, issuerSerialNumber);
                if (crlStoredMeanwhile != null && !isDue(crlStoredMeanwhile, certificate)) {
                    return crlStoredMeanwhile.getUuid();
                }
                return crlDownloadGuard
                        .withDownloadPermit(
                                () -> readCurrentCrl(certificate, issuerCertificate, issuerDn, issuerSerialNumber));
            });
        } catch (IOException e) {
            Crl crlStoredNow = findStoredCrl(issuerDn, issuerSerialNumber);
            if (crlStoredNow == null || isBaseCrlDue(crlStoredNow)) {
                throw e;
            }
            if (isDue(crlStoredNow, certificate)) {
                throwUnlessStoredCrlLists(certificate, crlStoredNow, e);
            }
            return crlStoredNow.getUuid();
        }
    }

    private static boolean isDue(Crl crl, X509Certificate certificate) {
        return isBaseCrlDue(crl)
                || (certificate.getExtensionValue(Extension.freshestCRL.getId()) != null && isDeltaCrlDue(crl));
    }

    /**
     * A stored base CRL is due once its next update has passed by more than the clock skew a downloaded CRL is allowed,
     * so a CA publishing a little late does not make every validation download the same CRL again.
     */
    private static boolean isBaseCrlDue(Crl crl) {
        return crl.getNextUpdate().toInstant().plus(CLOCK_SKEW).isBefore(Instant.now());
    }

    private UUID readCurrentCrl(X509Certificate certificate, X509Certificate issuerCertificate, String issuerDn,
            String issuerSerialNumber) throws IOException {
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
        } else if (isBaseCrlDue(crl)) {
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
        String downloadKey = downloadKey("base", issuerDn, issuerSerialNumber, crlDistributionPointsEncoded);
        crlDownloadGuard.rethrowRecentFailure(downloadKey);

        String lastReasonToIgnore = null;
        for (String crlUrl : crlUrls) {
            DownloadedCrl downloaded = downloadCrl(crlUrl, false);
            EncodedCrl downloadedCrl = downloaded.crl();
            String reasonToIgnore = downloadedCrl == null
                    ? downloaded.reasonUnread()
                    : findReasonToIgnore(downloadedCrl, false, issuer, oldCrl, lowestCrlNumber, crlUrl);
            if (reasonToIgnore != null) {
                lastReasonToIgnore = reasonToIgnore;
                continue;
            }

            X509CRL x509CRL = downloadedCrl.header();
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

            Iterable<CrlEntryData> entries = entryData(downloadedCrl, entry -> true);
            Date lastRevocationDate = downloadedCrl.lastRevocationDate();

            CrlWrite write;
            try {
                write = crlWriter.persistCrlAndEntries(crl, isNewCrl, entries, lastRevocationDate);
            } catch (DataAccessException | TransactionException | PersistenceException e) {
                logger.error("Failed to store the CRL from {}: {}", crlUrl, e.getMessage());
                IOException failure = new IOException("The CRL could not be stored");
                crlDownloadGuard.rememberFailure(downloadKey, failure);
                throw failure;
            }
            if (!write.written()) {
                return adoptStoredState(crl, issuerDn, issuerSerialNumber);
            }
            crl.setUuid(write.crlUuid());
            crl.setLastRevocationDate(lastRevocationDate);
            // Storing a base CRL drops the delta CRL applied to the one it replaces.
            crl.setCrlNumberDelta(null);
            crl.setNextUpdateDelta(null);
            return crl;
        }

        if (lastReasonToIgnore != null) {
            IOException failure = new IOException(
                    "Failed to read a usable CRL from %d available URL(s); the last one was ignored because %s"
                            .formatted(crlUrls.size(), lastReasonToIgnore));
            crlDownloadGuard.rememberFailure(downloadKey, failure);
            throw failure;
        }

        return null;
    }

    /**
     * Identifies a download by the issuer and the extension naming its URLs, so certificates of the issuer pointing at
     * other CRLs are not refused for a failure of this one.
     */
    private static String downloadKey(String kind, String issuerDn, String issuerSerialNumber,
            byte[] distributionPointsEncoded) {
        String distributionPoints = distributionPointsEncoded == null
                ? ""
                : Base64.getEncoder().encodeToString(distributionPointsEncoded);
        return String.join("|", kind, issuerDn, issuerSerialNumber, distributionPoints);
    }

    private DownloadedCrl downloadCrl(String crlUrl, boolean delta) {
        try {
            return new DownloadedCrl(EncodedCrl.parse(crlDownloader.download(crlUrl)), null);
        } catch (CrlDownloadException e) {
            logger.warn("Ignoring the CRL from {}: {}", crlUrl, e.reason());
            return new DownloadedCrl(null, e.reason());
        } catch (CrlRefusedException e) {
            logger.warn("Ignoring the CRL from {}: {}", crlUrl, e.reason());
            return new DownloadedCrl(null, e.reason());
        } catch (Exception e) {
            if (delta) {
                logger.debug("Failed to read the delta CRL from {}: {}", crlUrl, e.getMessage());
            } else {
                logger.error("Failed to read CRL content from URL: {}, {}", crlUrl, e.getMessage());
            }
            return new DownloadedCrl(null, "it could not be read");
        }
    }

    /**
     * Gives {@code crl} the state of the stored row, after a writer for another validation stored the same CRL or a
     * newer one first. Callers refreshing a stored CRL read the refreshed state from the {@link Crl} they passed.
     */
    private Crl adoptStoredState(Crl crl, String issuerDn, String issuerSerialNumber) {
        Crl stored = findStoredCrl(issuerDn, issuerSerialNumber);
        if (stored == null) {
            throw new IllegalStateException("CRL row of issuer " + issuerDn + " not found after it was stored");
        }
        crl.setUuid(stored.getUuid());
        crl.setCrlNumber(stored.getCrlNumber());
        crl.setNextUpdate(stored.getNextUpdate());
        crl.setLastRevocationDate(stored.getLastRevocationDate());
        crl.setCrlNumberDelta(stored.getCrlNumberDelta());
        crl.setNextUpdateDelta(stored.getNextUpdateDelta());
        return crl;
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
        byte[] freshestCrlEncoded = certificate.getExtensionValue(Extension.freshestCRL.getId());
        List<String> deltaCrlUrls = CrlUtil.getCDPFromCertificate(freshestCrlEncoded, "freshestCRL");
        if (deltaCrlUrls.isEmpty()) {
            throw new IOException("The certificate names a delta CRL without a URL to read it from");
        }
        String downloadKey = downloadKey("delta", issuerDn, issuerSerialNumber, freshestCrlEncoded);
        crlDownloadGuard.rethrowRecentFailure(downloadKey);
        String lastReasonToIgnore = null;
        for (String deltaCrlUrl : deltaCrlUrls) {
            DownloadedCrl downloaded = downloadCrl(deltaCrlUrl, true);
            EncodedCrl deltaCrl = downloaded.crl();
            String reasonToIgnore = deltaCrl == null
                    ? downloaded.reasonUnread()
                    : findReasonToIgnore(deltaCrl, true, issuer, crl, BigInteger.ZERO, deltaCrlUrl);
            if (reasonToIgnore == null && extendsNewerBaseCrl(deltaCrl.header(), crl)) {
                refreshExistingCrl(crl, certificate.getExtensionValue(Extension.cRLDistributionPoints.getId()),
                        issuerDn, issuerSerialNumber, caCertificateUuid, issuer, readBaseCrlNumber(deltaCrl.header()));
            }
            if (reasonToIgnore == null) {
                reasonToIgnore = findBaseCrlMismatch(deltaCrl.header(), crl, deltaCrlUrl);
            }
            if (reasonToIgnore == null) {
                updateDeltaCrl(crl, deltaCrl, downloadKey);
                return;
            }
            lastReasonToIgnore = reasonToIgnore;
        }
        IOException failure = new IOException(
                "Failed to read a usable delta CRL from %d available URL(s); the last one was ignored because %s"
                        .formatted(deltaCrlUrls.size(), lastReasonToIgnore));
        crlDownloadGuard.rememberFailure(downloadKey, failure);
        throw failure;
    }

    private void updateDeltaCrl(Crl crl, EncodedCrl deltaCrl, String downloadKey) throws IOException {
        BigInteger deltaCrlNumber = readCrlNumber(deltaCrl.header());
        // The stored delta CRL is applied already, and findReasonToIgnore refused older ones.
        if (crl.getCrlNumberDelta() != null && deltaCrlNumber.compareTo(new BigInteger(crl.getCrlNumberDelta())) <= 0) {
            return;
        }

        // A delta CRL lists every change since its base CRL, so each entry is applied, also one dated before a
        // revocation already stored, and removeFromCRL only ever removes an entry.
        Iterable<String> removals = () -> stream(deltaCrl)
                .filter(CrlServiceImpl::removesFromCrl)
                .map(entry -> entry.serialNumber().toString(16))
                .iterator();
        Iterable<CrlEntryData> upserts = entryData(deltaCrl, entry -> !removesFromCrl(entry));
        Date lastRevocationDate = Stream
                .concat(Stream.ofNullable(crl.getLastRevocationDate()),
                        StreamSupport.stream(upserts.spliterator(), false).map(CrlEntryData::revocationDate))
                .max(Comparator.naturalOrder())
                .orElse(null);

        boolean applied;
        try {
            applied = crlWriter
                    .applyDeltaCrl(crl.getUuid(), crl.getCrlNumber(), removals, upserts, deltaCrlNumber.toString(),
                            deltaCrl.header().getNextUpdate(), lastRevocationDate);
        } catch (DataAccessException | TransactionException | PersistenceException e) {
            logger.error("Failed to store the delta CRL of issuer {}: {}", crl.getIssuerDn(), e.getMessage());
            IOException failure = new IOException("The delta CRL could not be stored");
            crlDownloadGuard.rememberFailure(downloadKey, failure);
            throw failure;
        }
        if (!applied) {
            requireDeltaCrlStoredMeanwhile(crl, deltaCrlNumber);
        }
    }

    /**
     * A writer for another validation, possibly on another Core instance, changed the stored CRL first. Its entries
     * answer the check only if they are at least as new as this delta CRL: a complete or delta CRL numbered at or above
     * it, since both share one numbering sequence. An older base CRL without it would miss the revocations this delta
     * CRL lists.
     */
    private void requireDeltaCrlStoredMeanwhile(Crl crl, BigInteger deltaCrlNumber) throws IOException {
        Crl stored = findStoredCrl(crl.getIssuerDn(), crl.getSerialNumber());
        boolean storedCrlIsAsNew = stored != null && newestStoredCrlNumber(stored).compareTo(deltaCrlNumber) >= 0;
        if (!storedCrlIsAsNew) {
            throw new IOException("The stored CRL changed while its delta CRL was applied");
        }
    }

    private static boolean removesFromCrl(RevokedCertificate entry) {
        return CRLReason.REMOVE_FROM_CRL.equals(entry.reason());
    }

    /** The CRL's entries matching the filter, decoded as the writer takes them. */
    private static Iterable<CrlEntryData> entryData(EncodedCrl crl, Predicate<RevokedCertificate> filter) {
        return () -> stream(crl).filter(filter).map(CrlServiceImpl::toEntryData).iterator();
    }

    private static Stream<RevokedCertificate> stream(EncodedCrl crl) {
        return StreamSupport.stream(crl.entries().spliterator(), false);
    }

    /**
     * Returns why a CRL downloaded as a base CRL, or as a delta CRL when {@code delta} is set, cannot be used for the
     * certificate's issuer, after logging it at WARN, or {@code null} when it can. A CRL that would replace or update
     * {@code storedCrl} must not be older than it, nor numbered below {@code lowestCrlNumber}.
     */
    private static String findReasonToIgnore(EncodedCrl encodedCrl, boolean delta, CertificateIssuer issuer,
            Crl storedCrl, BigInteger lowestCrlNumber, String crlUrl) throws IOException {
        X509CRL crl = encodedCrl.header();
        String reason = null;
        if (!crl.getIssuerX500Principal().equals(issuer.name())) {
            reason = "it names another issuer (%s)".formatted(crl.getIssuerX500Principal().getName());
        } else if (!encodedCrl.isSignedBy(issuer.publicKey())) {
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

    /**
     * A delta CRL is downloaded when none is stored, when the stored one is past its next update by more than the clock
     * skew a stored base CRL is allowed too, or when the stored one is numbered below the stored base CRL, so it cannot
     * extend it.
     */
    private static boolean isDeltaCrlDue(Crl crl) {
        return crl.getCrlNumberDelta() == null || crl.getNextUpdateDelta() == null
                || new BigInteger(crl.getCrlNumberDelta()).compareTo(new BigInteger(crl.getCrlNumber())) < 0
                || crl.getNextUpdateDelta().toInstant().plus(CLOCK_SKEW).isBefore(Instant.now());
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

    private static CrlEntryData toEntryData(RevokedCertificate entry) {
        String serialNumber = entry.serialNumber().toString(16);
        String reason = entry.reason() == null
                ? CertificateRevocationReason.UNSPECIFIED.name()
                : CertificateRevocationReason.fromCrlReason(entry.reason()).name();
        return new CrlEntryData(serialNumber, entry.revocationDate(), reason);
    }

    /** The name a CRL must carry and the key its signature must verify with to count for a certificate. */
    private record CertificateIssuer(X500Principal name, PublicKey publicKey) {
    }

    /** A downloaded CRL, or why none could be read, worded to follow "it was ignored because". */
    private record DownloadedCrl(EncodedCrl crl, String reasonUnread) {
    }
}
