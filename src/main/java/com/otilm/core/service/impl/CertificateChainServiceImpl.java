package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.service.CertificateChainService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.writer.CertificateChainWriter;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.LdapUtils;
import com.otilm.core.util.OcspUtil;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

/**
 * <p>
 * <b>Transactional contract:</b> the bean carries no class-level {@code @Transactional}. Methods inherit the caller's
 * ambient transaction (REQUIRED) or run without one (NOT_SUPPORTED) depending on where they are invoked from.
 */
@Service
public class CertificateChainServiceImpl implements CertificateChainService {

    private static final Logger logger = LoggerFactory.getLogger(CertificateChainServiceImpl.class);

    private static final int MAX_AIA_RESPONSE_BYTES = 1024 * 1024;
    private static final int MAX_AIA_URLS_PER_CERTIFICATE = 5;
    private static final int MAX_AIA_DOWNLOADS = 20;

    @Value("${certificate.chain.max-depth:20}")
    private int certificateChainMaxDepth;

    private final CertificateRepository certificateRepository;
    private final X509CertificateRepository x509CertificateRepository;
    private final CertificateChainWriter chainWriter;
    private final CertificateInternalService certificateService;

    @Autowired
    public CertificateChainServiceImpl(CertificateRepository certificateRepository,
            X509CertificateRepository x509CertificateRepository, CertificateChainWriter chainWriter,
            @Lazy CertificateInternalService certificateService) {
        this.certificateRepository = certificateRepository;
        this.x509CertificateRepository = x509CertificateRepository;
        this.chainWriter = chainWriter;
        this.certificateService = certificateService;
    }

    @Override
    public void updateCertificateChain(Certificate certificate) throws CertificateException {
        if (certificate.getCertificateContent() == null) {
            return;
        }
        X509Certificate subCert;
        try {
            subCert = CertificateUtil.parseCertificate(certificate.getCertificateContent().getContent());
        } catch (Exception e) {
            return;
        }
        updateCertificateChain(certificate, subCert);
    }

    @Override
    public void updateCertificateChain(Certificate certificate, X509Certificate subCert) throws CertificateException {
        Traversal traversal = new Traversal(certificateChainMaxDepth);
        while (traversal.remainingDepth > 0 && traversal.visited.add(subCert)
                && !isSelfSigned(subCert, certificate.getUuid())) {
            Issuer issuer = findInventoryIssuer(certificate, subCert, traversal.visited);
            if (issuer == null) {
                issuer = importAiaIssuer(certificate, subCert, traversal);
            }
            if (issuer == null) {
                return;
            }
            Certificate nextInChain = issuer.entity();
            X509CertificateEntity.from(certificate).setIssuerSerialNumber(nextInChain.getSerialNumber());
            certificate.setIssuerCertificateUuid(nextInChain.getUuid());
            chainWriter
                    .applyIssuerReference(certificate.getUuid(), nextInChain.getSerialNumber(), nextInChain.getUuid());
            --traversal.remainingDepth;
            if (nextInChain.getIssuerCertificateUuid() != null) {
                return;
            }
            certificate = nextInChain;
            subCert = issuer.x509();
        }
    }

    private Issuer findInventoryIssuer(Certificate certificate, X509Certificate subCert, Set<X509Certificate> visited) {
        for (Certificate issuer : x509CertificateRepository
                .findBySubjectDnNormalized(X509CertificateEntity.from(certificate).getIssuerDnNormalized())) {
            X509Certificate issCert = parseOrNull(issuer.getCertificateContent().getContent());
            if (issCert != null && !visited.contains(issCert) && verifySignature(subCert, issCert)) {
                return new Issuer(issuer, issCert);
            }
        }
        return null;
    }

    @Override
    public List<Certificate> getCertificateChainInternal(Certificate certificate, boolean withEndCertificate) {
        List<Certificate> certificateChain = new ArrayList<>();
        if (certificate.getCertificateContent() == null) {
            return certificateChain;
        }
        if (withEndCertificate) {
            certificateChain.add(certificate);
        }
        constructCertificateChainFromInventory(certificate, certificateChain);
        return certificateChain;
    }

    @Override
    public boolean completeCertificateChain(Certificate lastCertificate, List<Certificate> certificateChain) {
        try {
            X509Certificate x509 = CertificateUtil
                    .parseCertificate(lastCertificate.getCertificateContent().getContent());
            if (isSelfSigned(x509, lastCertificate.getUuid())) {
                return true;
            } else {
                updateCertificateChain(lastCertificate, x509);
                if (lastCertificate.getIssuerCertificateUuid() != null) {
                    lastCertificate = constructCertificateChainFromInventory(lastCertificate, certificateChain);
                    return isSelfSigned(lastCertificate);
                }
            }
        } catch (CertificateException e) {
            // If it cannot be verified whether certificate is self-signed or updateCertificateChain fails,
            // we end certificate chain building and return partial result
        }
        return false;
    }

    @Override
    public Certificate constructCertificateChainFromInventory(Certificate certificate,
            List<Certificate> certificateChain) {
        List<String> chainUuidStrings = certificateRepository
                .findCertificateChainUuids(certificate.getUuid(), certificateChainMaxDepth);
        if (chainUuidStrings.size() <= 1) {
            return certificate;
        }

        List<UUID> ancestorUuids = chainUuidStrings
                .subList(1, chainUuidStrings.size())
                .stream()
                .map(UUID::fromString)
                .toList();

        Map<UUID, Certificate> byUuid = certificateRepository
                .findChainWithAssociationsByUuidIn(ancestorUuids)
                .stream()
                .collect(Collectors.toMap(Certificate::getUuid, c -> c));

        Certificate lastCertificate = certificate;
        for (UUID ancestorUuid : ancestorUuids) {
            Certificate issuerCertificate = byUuid.get(ancestorUuid);
            if (issuerCertificate != null) {
                certificateChain.add(issuerCertificate);
                lastCertificate = issuerCertificate;
            } else {
                // Dangling FK — clear the references and return an incomplete chain.
                lastCertificate.setIssuerCertificateUuid(null);
                X509CertificateEntity.from(lastCertificate).setIssuerSerialNumber(null);
                chainWriter.clearIssuerReference(lastCertificate.getUuid());
                break;
            }
        }
        return lastCertificate;
    }

    private boolean isSelfSigned(Certificate certificate) throws CertificateException {
        return isSelfSigned(getX509(certificate.getCertificateContent().getContent()), certificate.getUuid());
    }

    private boolean isSelfSigned(X509Certificate x509Certificate, UUID certificateUuid) throws CertificateException {
        try {
            x509Certificate.verify(x509Certificate.getPublicKey());
            return true;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            logger.debug("Unable to verify if the certificate {} is self-signed: {}", certificateUuid, e.getMessage());
            throw new CertificateException(e);
        } catch (SignatureException | InvalidKeyException e) {
            return false;
        }
    }

    private X509Certificate parseOrNull(String content) {
        try {
            return CertificateUtil.parseCertificate(content);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean verifySignature(X509Certificate subjectCertificate, X509Certificate issuerCertificate) {
        try {
            subjectCertificate.verify(issuerCertificate.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private X509Certificate getX509(String certificate) throws CertificateException {
        return CertificateUtil
                .getX509Certificate(certificate
                        .replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("\r", "")
                        .replace("\n", "")
                        .replace("-----END CERTIFICATE-----", ""));
    }

    private Issuer importAiaIssuer(Certificate certificate, X509Certificate certX509, Traversal traversal) {
        X509Certificate issuer;
        String pem;
        try {
            issuer = findIssuer(certX509, traversal.candidates, traversal.visited);
            if (issuer == null) {
                issuer = downloadIssuer(certX509, traversal);
            }
            if (issuer == null) {
                return null;
            }
            pem = toPem(issuer);
        } catch (Exception e) {
            logger
                    .debug("Unable to get the chain of certificate {} from Authority Information Access",
                            certificate.getUuid(), e);
            return null;
        }
        try {
            Certificate entity = certificateService.createCertificateAtomic(pem, false);
            assert entity != null;
            return new Issuer(entity, issuer);
        } catch (NoSuchAlgorithmException | CertificateException | NotFoundException e) {
            return null;
        }
    }

    private X509Certificate downloadIssuer(X509Certificate certificate, Traversal traversal) throws IOException {
        int attemptedLocations = 0;
        for (String chainUrl : OcspUtil.getCaIssuerUrlsFromAia(certificate)) {
            if (attemptedLocations >= MAX_AIA_URLS_PER_CERTIFICATE || traversal.remainingDownloads == 0) {
                break;
            }
            if (!traversal.attemptedUrls.add(chainUrl)) {
                continue;
            }
            ++attemptedLocations;
            --traversal.remainingDownloads;
            List<X509Certificate> downloaded = downloadCertificates(chainUrl);
            traversal.candidates.addAll(downloaded);
            X509Certificate issuer = findIssuer(certificate, downloaded, traversal.visited);
            if (issuer != null) {
                logger
                        .info("Certificate {} downloaded from Authority Information Access extension URL {}",
                                issuer.getSubjectX500Principal().getName(), chainUrl);
                return issuer;
            }
        }
        return null;
    }

    private X509Certificate findIssuer(X509Certificate certificate, List<X509Certificate> candidates,
            Set<X509Certificate> visited) {
        return candidates
                .stream()
                .filter(candidate -> !visited.contains(candidate))
                .filter(candidate -> certificate.getIssuerX500Principal().equals(candidate.getSubjectX500Principal()))
                .filter(candidate -> verifySignature(certificate, candidate))
                .findFirst()
                .orElse(null);
    }

    private List<X509Certificate> downloadCertificates(String chainUrl) {
        try {
            if (chainUrl.startsWith("ldap://") || chainUrl.startsWith("ldaps://")) {
                byte[] certificate = LdapUtils.downloadFromLdap(chainUrl, 1000, 1000);
                try (InputStream in = new ByteArrayInputStream(certificate)) {
                    return readCertificates(in);
                }
            } else {
                URL url = URI.create(chainUrl).toURL();
                URLConnection urlConnection = url.openConnection();
                urlConnection.setConnectTimeout(1000);
                urlConnection.setReadTimeout(1000);
                try (InputStream in = urlConnection.getInputStream()) {
                    return readCertificates(in);
                }
            }
        } catch (Exception e) {
            logger.debug("Failed to download certificate chain from {}", chainUrl, e);
        }
        return List.of();
    }

    private List<X509Certificate> readCertificates(InputStream in) throws CertificateException, IOException {
        byte[] encoded = in.readNBytes(MAX_AIA_RESPONSE_BYTES + 1);
        if (encoded.length > MAX_AIA_RESPONSE_BYTES) {
            throw new IOException("Certificate response exceeds 1 MiB");
        }
        return CertificateFactory
                .getInstance("X509")
                .generateCertificates(new ByteArrayInputStream(encoded))
                .stream()
                .map(X509Certificate.class::cast)
                .toList();
    }

    private String toPem(X509Certificate certificate) throws IOException {
        try (StringWriter writer = new StringWriter(); JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(certificate);
            pemWriter.flush();
            return writer.toString();
        }
    }

    private record Issuer(Certificate entity, X509Certificate x509) {
    }

    private static final class Traversal {
        private int remainingDepth;
        private int remainingDownloads = MAX_AIA_DOWNLOADS;
        private final Set<X509Certificate> visited = new HashSet<>();
        private final Set<String> attemptedUrls = new HashSet<>();
        private final List<X509Certificate> candidates = new ArrayList<>();

        private Traversal(int remainingDepth) {
            this.remainingDepth = remainingDepth;
        }
    }
}
