package com.czertainly.core.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.service.CertificateChainService;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.writer.CertificateChainWriter;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.LdapUtils;
import com.czertainly.core.util.OcspUtil;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import java.io.ByteArrayInputStream;
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
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * <p><b>Transactional contract:</b> the bean carries no class-level {@code @Transactional}. Methods inherit the caller's
 * ambient transaction (REQUIRED) or run without one (NOT_SUPPORTED) depending on where they are invoked from.
 */
@Service
public class CertificateChainServiceImpl implements CertificateChainService {

    private static final Logger logger = LoggerFactory.getLogger(CertificateChainServiceImpl.class);

    @Value("${certificate.chain.max-depth:20}")
    private int certificateChainMaxDepth;

    private final CertificateRepository certificateRepository;
    private final CertificateChainWriter chainWriter;
    private final CertificateService certificateService;

    @Autowired
    public CertificateChainServiceImpl(
            CertificateRepository certificateRepository,
            CertificateChainWriter chainWriter,
            @Lazy CertificateService certificateService) {
        this.certificateRepository = certificateRepository;
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
        if (isSelfSigned(subCert, certificate.getUuid())) {
            return;
        }
        boolean issuerInInventory = false;
        for (Certificate issuer : certificateRepository.findBySubjectDnNormalized(certificate.getIssuerDnNormalized())) {
            X509Certificate issCert = parseOrNull(issuer.getCertificateContent().getContent());
            if (issCert != null && verifySignature(subCert, issCert)) {
                certificate.setIssuerSerialNumber(issuer.getSerialNumber());
                certificate.setIssuerCertificateUuid(issuer.getUuid());
                chainWriter.applyIssuerReference(certificate.getUuid(), issuer.getSerialNumber(), issuer.getUuid());
                issuerInInventory = true;
                if (issuer.getIssuerCertificateUuid() == null) {
                    updateCertificateChain(issuer);
                }
                break;
            }
        }
        if (!issuerInInventory) {
            int downloadedCertificates = 0;
            List<String> aiaChain = downloadChainFromAia(certificate, subCert);
            Certificate previousCertificate = certificate;
            for (String chainCertificate : aiaChain) {
                Certificate nextInChain;
                try {
                    nextInChain = certificateService.createCertificateAtomic(chainCertificate, false);
                    assert nextInChain != null;
                    previousCertificate.setIssuerCertificateUuid(nextInChain.getUuid());
                    previousCertificate.setIssuerSerialNumber(nextInChain.getSerialNumber());
                    chainWriter.applyIssuerReference(previousCertificate.getUuid(), nextInChain.getSerialNumber(), nextInChain.getUuid());
                    previousCertificate = nextInChain;
                    ++downloadedCertificates;
                } catch (NoSuchAlgorithmException | CertificateException | NotFoundException e) {
                    break;
                }
            }
            if (downloadedCertificates > 0) {
                updateCertificateChain(previousCertificate);
            }
        }
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
            X509Certificate x509 = CertificateUtil.parseCertificate(lastCertificate.getCertificateContent().getContent());
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
    public Certificate constructCertificateChainFromInventory(Certificate certificate, List<Certificate> certificateChain) {
        List<String> chainUuidStrings = certificateRepository.findCertificateChainUuids(certificate.getUuid(), certificateChainMaxDepth);
        if (chainUuidStrings.size() <= 1) {
            return certificate;
        }

        List<UUID> ancestorUuids = chainUuidStrings.subList(1, chainUuidStrings.size())
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
                lastCertificate.setIssuerSerialNumber(null);
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
        return CertificateUtil.getX509Certificate(
                certificate.replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("\r", "")
                        .replace("\n", "")
                        .replace("-----END CERTIFICATE-----", ""));
    }

    private List<String> downloadChainFromAia(Certificate certificate, X509Certificate certX509) {
        List<String> chainCertificates = new ArrayList<>();
        try {
            String chainUrl = OcspUtil.getChainFromAia(certX509);
            while (chainUrl != null && !chainUrl.isEmpty()) {
                String chainContent = downloadChain(chainUrl);
                if (chainContent.isEmpty()) {
                    chainUrl = null;
                } else {
                    logger.info("Certificate {} downloaded from Authority Information Access extension URL {}",
                            certX509.getSubjectX500Principal().getName(), chainUrl);
                    chainCertificates.add(chainContent);
                    certX509 = getX509(chainContent);
                    chainUrl = verifySignature(certX509, certX509) ? null : OcspUtil.getChainFromAia(certX509);
                }
            }
        } catch (Exception e) {
            logger.debug("Unable to get the chain of certificate {} from Authority Information Access",
                    certificate.getUuid(), e);
        }
        return chainCertificates;
    }

    private String downloadChain(String chainUrl) {
        try {
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            X509Certificate cert;

            if (chainUrl.startsWith("ldap://") || chainUrl.startsWith("ldaps://")) {
                byte[] certificate = LdapUtils.downloadFromLdap(chainUrl);
                if (certificate == null) return "";
                cert = (X509Certificate) fac.generateCertificate(new ByteArrayInputStream(certificate));
            } else {
                URL url = URI.create(chainUrl).toURL();
                URLConnection urlConnection = url.openConnection();
                urlConnection.setConnectTimeout(1000);
                urlConnection.setReadTimeout(1000);
                try (InputStream in = urlConnection.getInputStream()) {
                    cert = (X509Certificate) fac.generateCertificate(in);
                }
            }
            try (StringWriter writer = new StringWriter();
                 JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
                pemWriter.writeObject(cert);
                pemWriter.flush();
                return writer.toString();
            }
        } catch (Exception e) {
            logger.error("Failed to download certificate chain from {}", chainUrl, e);
        }
        return "";
    }
}
