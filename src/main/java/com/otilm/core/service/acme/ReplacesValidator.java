package com.otilm.core.service.acme;

import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.core.acme.AcmeIdentifierType;
import com.otilm.api.model.core.acme.Identifier;
import com.otilm.api.model.core.acme.Problem;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.entity.acme.AcmeAccount;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.acme.AcmeOrderRepository;
import com.otilm.core.service.acme.identifier.AcmeIdentifierPolicy;
import com.otilm.core.util.CertificateUtil;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

/**
 * Checks the {@code replaces} member of a new order (RFC 9773 section 5). Every reason to refuse the named certificate
 * gets the same answer, so that a client cannot learn whether a certificate it does not hold exists, or whom it was
 * issued to.
 */
@Component
public class ReplacesValidator {

    static final String REFUSAL_DETAIL = "The certificate named in replaces cannot be replaced by this order";

    private static final Logger logger = LoggerFactory.getLogger(ReplacesValidator.class);

    private static final String DNS_NAME = "dNSName";
    private static final String IP_ADDRESS = "iPAddress";

    private AriCertificateLookup ariCertificateLookup;
    private AcmeOrderRepository acmeOrderRepository;
    private CertificateRelationRepository certificateRelationRepository;
    private CertificateRepository certificateRepository;

    @Autowired
    public void setAriCertificateLookup(AriCertificateLookup ariCertificateLookup) {
        this.ariCertificateLookup = ariCertificateLookup;
    }

    @Autowired
    public void setAcmeOrderRepository(AcmeOrderRepository acmeOrderRepository) {
        this.acmeOrderRepository = acmeOrderRepository;
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setCertificateRelationRepository(CertificateRelationRepository certificateRelationRepository) {
        this.certificateRelationRepository = certificateRelationRepository;
    }

    /**
     * The certificate the order replaces.
     *
     * @throws AcmeProblemDocumentException {@code malformed} when the identifier is malformed, names no issued
     * certificate of the RA profile, names one not ordered by the account, or one sharing no identifier with the order;
     * {@code alreadyReplaced} when a live order already replaces it or it has an issued successor. Must run inside the
     * transaction that stores the new order, which the certificate's row lock taken here serializes.
     */
    public Certificate validate(String replaces, AcmeAccount account, List<Identifier> identifiers, RaProfile raProfile)
            throws AcmeProblemDocumentException {
        Certificate predecessor = findOrderedByAccount(replaces, account, raProfile)
                .filter(certificate -> sharesIdentifier(certificate, identifiers))
                .orElseThrow(() -> {
                    logger.debug("Refused replaces of an order of ACME account {}", account.getAccountId());
                    return new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED, REFUSAL_DETAIL);
                });
        // Serializes the check and the insert of the order that follows, across replicas, until the order commits.
        certificateRepository.findAndLockFreshByUuid(predecessor.getUuid());
        if (acmeOrderRepository.existsLiveOrderReplacing(predecessor.getUuid(), new Date())
                || certificateRelationRepository
                        .existsByIdPredecessorCertificateUuidAndSuccessorCertificateState(predecessor.getUuid(),
                                CertificateState.ISSUED)) {
            throw new AcmeProblemDocumentException(HttpStatus.CONFLICT, Problem.ALREADY_REPLACED);
        }
        return predecessor;
    }

    private Optional<Certificate> findOrderedByAccount(String replaces, AcmeAccount account, RaProfile raProfile) {
        AriCertId id;
        try {
            id = AriCertId.parse(replaces);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        return ariCertificateLookup
                .find(raProfile.getUuid(), id)
                .filter(certificate -> acmeOrderRepository
                        .existsByCertificateReferenceUuidAndAcmeAccountUuid(certificate.getUuid(), account.getUuid()));
    }

    /**
     * Whether a DNS or IP identifier of the order is one of the certificate's subject alternative names of that type. A
     * DNS identifier may also be the common name. Names compare ignoring case, addresses by their octets.
     */
    private static boolean sharesIdentifier(Certificate certificate, List<Identifier> identifiers) {
        X509CertificateEntity x509 = X509CertificateEntity.fromOrNull(certificate);
        if (x509 == null) {
            return false;
        }
        Map<String, List<String>> sans = CertificateUtil.deserializeSans(x509.getSubjectAlternativeNames());
        List<String> names = new ArrayList<>(sans.getOrDefault(DNS_NAME, List.of()));
        if (certificate.getCommonName() != null) {
            names.add(certificate.getCommonName());
        }
        List<String> addresses = sans.getOrDefault(IP_ADDRESS, List.of());
        return identifiers.stream().anyMatch(identifier -> matchesAny(identifier, names, addresses));
    }

    private static boolean matchesAny(Identifier identifier, List<String> names, List<String> addresses) {
        if (AcmeIdentifierType.DNS.getCode().equalsIgnoreCase(identifier.getType())) {
            return names.stream().anyMatch(name -> name.equalsIgnoreCase(identifier.getValue()));
        }
        if (AcmeIdentifierType.IP.getCode().equalsIgnoreCase(identifier.getType())) {
            Optional<byte[]> ordered = AcmeIdentifierPolicy.addressBytes(identifier.getValue());
            return ordered.isPresent() && addresses
                    .stream()
                    .map(AcmeIdentifierPolicy::addressBytes)
                    .flatMap(Optional::stream)
                    .anyMatch(address -> Arrays.equals(address, ordered.get()));
        }
        return false;
    }
}
