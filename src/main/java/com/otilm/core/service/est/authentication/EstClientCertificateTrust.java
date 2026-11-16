package com.otilm.core.service.est.authentication;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateSubjectType;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.security.authn.ForwardedClientCertificateParser.ParsedCertificate;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.util.CertificateUtil;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.security.auth.x500.X500Principal;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

/**
 * Decides whether the client certificate that the TLS proxy forwarded is trusted by the EST Profile of the route. A
 * path is built from the client certificate, through the chain the client sent, to a CA certificate of the inventory
 * that the profile trusts. The chain the client sent is only material for the path, never trusted itself, and the
 * inventory is not searched for the CA certificates in between. The path is built with the BouncyCastle provider, so
 * that every algorithm Core accepts elsewhere verifies here too.
 * <p>
 * A client certificate that has an extended key usage must allow client authentication, and one that has none allows
 * every purpose. An RA must carry {@code id-kp-cmcRA} in any case. Revocation is checked last, so that every revocation
 * source asked is named by a certificate that a trusted CA issued.
 */
@Slf4j
@Component
public class EstClientCertificateTrust {

    private static final Set<String> CLIENT_AUTHENTICATION = Set.of(KeyPurposeId.id_kp_clientAuth.getId());

    /**
     * The path search tries every certificate of the issuer's subject as the issuer of a certificate, so a chain with
     * many certificates of one subject makes it try every order of them. Two leave room for a CA that was renewed or is
     * cross-certified.
     */
    private static final int MAX_CERTIFICATES_PER_SUBJECT = 2;

    private final CertificateRepository certificateRepository;
    private final EstRevocationCheck revocationCheck;

    public EstClientCertificateTrust(CertificateRepository certificateRepository, EstRevocationCheck revocationCheck) {
        this.certificateRepository = certificateRepository;
        this.revocationCheck = revocationCheck;
    }

    /**
     * @param route the route of the request, whose EST Profile names the CA certificates it trusts
     * @param credentials what the client presented; only the client certificate is read
     * @param requireRaUsage whether the client certificate must carry the {@code id-kp-cmcRA} extended key usage
     * @return the client certificate, which a trusted CA issued and which is not revoked
     * @throws EstException carrying the realm of the route: {@link EstError#CERTIFICATE_REJECTED} when the client
     * certificate is absent or cannot be read, comes with too many certificates of one subject, has no valid path to a
     * CA certificate the profile trusts, does not allow client authentication, lacks the RA usage that is required, or
     * when a certificate of its path is revoked; {@link EstError#SERVICE_UNAVAILABLE} when the revocation sources a
     * certificate of the path names cannot answer
     */
    public X509Certificate verify(EstRoute route, @Sensitive EstClientCredentials credentials, boolean requireRaUsage) {
        ParsedCertificate presented = credentials
                .certificate()
                .orElseThrow(() -> refused(route,
                        credentials.certificateMalformed()
                                ? "the client certificate header is malformed"
                                : "no client certificate was presented"));
        String thumbprint = presented.thumbprint();
        X509Certificate leaf = parse(route, thumbprint, presented.content());
        List<X509Certificate> pathMaterial = pathMaterial(route, thumbprint, leaf, presented.chain());
        Set<TrustAnchor> anchors = trustAnchors(route);
        PKIXCertPathBuilderResult path = buildPath(route, thumbprint, leaf, pathMaterial, anchors);
        if (requireRaUsage && !hasRaUsage(leaf)) {
            throw refused(route, "certificate " + thumbprint + " does not carry the id-kp-cmcRA extended key usage");
        }
        revocationCheck.verify(route, path.getCertPath(), path.getTrustAnchor());
        log
                .debug("EST client certificate {} accepted for realm {}, issued under {}", thumbprint, route.realm(),
                        path.getTrustAnchor().getTrustedCert().getSubjectX500Principal());
        return leaf;
    }

    /**
     * @return the client certificate followed by the chain the client sent, which the path may be built from
     */
    private static List<X509Certificate> pathMaterial(EstRoute route, String thumbprint, X509Certificate leaf,
            List<String> chain) {
        List<X509Certificate> pathMaterial = new ArrayList<>();
        pathMaterial.add(leaf);
        for (String candidate : chain) {
            pathMaterial.add(parse(route, thumbprint, candidate));
        }
        Map<X500Principal, Long> certificatesPerSubject = pathMaterial
                .stream()
                .collect(Collectors.groupingBy(X509Certificate::getSubjectX500Principal, Collectors.counting()));
        if (certificatesPerSubject.values().stream().anyMatch(count -> count > MAX_CERTIFICATES_PER_SUBJECT)) {
            throw refused(route, "the chain sent with certificate " + thumbprint + " carries more than "
                    + MAX_CERTIFICATES_PER_SUBJECT + " certificates of one subject");
        }
        return pathMaterial;
    }

    /**
     * A profile without a usable CA certificate refuses every client, which an operator has to fix, so it is logged at
     * WARN rather than as the refusal of one client.
     *
     * @return the CA certificates of the inventory that the EST Profile trusts; a certificate of another subject type
     * is never an anchor, whatever the profile lists, and one that the inventory marks revoked is left out with a
     * warning
     */
    private Set<TrustAnchor> trustAnchors(EstRoute route) {
        List<UUID> trusted = route.estProfile().getTrustedCaCertificateUuids();
        Set<TrustAnchor> anchors = new HashSet<>();
        for (Certificate certificate : certificateRepository.findAllWithAssociationsByUuidIn(trusted)) {
            if (isMarkedRevoked(certificate)) {
                log
                        .warn("EST Profile {} trusts certificate {} of the inventory, which is revoked",
                                route.estProfile().getName(), certificate.getUuid());
            } else if (isCaWithContent(certificate)) {
                parseInventoryContent(route, certificate).ifPresent(ca -> anchors.add(new TrustAnchor(ca, null)));
            }
        }
        if (anchors.isEmpty()) {
            log.warn("EST Profile {} trusts no usable CA certificate of the inventory", route.estProfile().getName());
            throw new EstException(EstError.CERTIFICATE_REJECTED, route.realm());
        }
        log
                .debug("{} of the {} certificates that the EST Profile of realm {} trusts are CA certificates",
                        anchors.size(), trusted.size(), route.realm());
        return anchors;
    }

    private static boolean isMarkedRevoked(Certificate certificate) {
        return certificate.getState() == CertificateState.REVOKED
                || certificate.getValidationStatus() == CertificateValidationStatus.REVOKED;
    }

    private static boolean isCaWithContent(Certificate certificate) {
        CertificateSubjectType subjectType = certificate.getSubjectType();
        return subjectType != null && subjectType.isCa() && certificate.getCertificateContent() != null;
    }

    /**
     * @return the certificate, or nothing when its stored content cannot be read, so that the other CA certificates the
     * profile trusts still anchor paths
     */
    private static Optional<X509Certificate> parseInventoryContent(EstRoute route, Certificate certificate) {
        try {
            return Optional.of(CertificateUtil.parseCertificate(certificate.getCertificateContent().getContent()));
        } catch (CertificateException | IllegalArgumentException e) {
            log
                    .warn("EST Profile {} trusts certificate {} of the inventory, whose content cannot be read",
                            route.estProfile().getName(), certificate.getUuid());
            return Optional.empty();
        }
    }

    /**
     * The extended key usage criterion of the selector passes a certificate without that extension.
     */
    private static PKIXCertPathBuilderResult buildPath(EstRoute route, String thumbprint, X509Certificate leaf,
            List<X509Certificate> pathMaterial, Set<TrustAnchor> anchors) {
        try {
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(leaf);
            target.setExtendedKeyUsage(CLIENT_AUTHENTICATION);
            PKIXBuilderParameters parameters = new PKIXBuilderParameters(anchors, target);
            parameters
                    .addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(pathMaterial)));
            parameters.setRevocationEnabled(false);
            return (PKIXCertPathBuilderResult) CertPathBuilder
                    .getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME)
                    .build(parameters);
        } catch (CertPathBuilderException e) {
            throw refused(route,
                    "certificate " + thumbprint + " has no valid path to a trusted CA certificate: " + reasonOf(e));
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("The path of an EST client certificate cannot be built", e);
        }
    }

    private static boolean hasRaUsage(X509Certificate leaf) {
        try {
            List<String> purposes = leaf.getExtendedKeyUsage();
            return purposes != null && purposes.contains(KeyPurposeId.id_kp_cmcRA.getId());
        } catch (CertificateParsingException e) {
            return false;
        }
    }

    /**
     * Parses a forwarded certificate the way the header parser read it, and not through {@link CertificateUtil}, which
     * logs the content of a certificate whose public key it cannot decode.
     */
    private static X509Certificate parse(EstRoute route, String thumbprint, String base64Der) {
        try {
            byte[] der = Base64.getDecoder().decode(base64Der);
            return (X509Certificate) new CertificateFactory().engineGenerateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException e) {
            throw refused(route, "a certificate forwarded with certificate " + thumbprint + " cannot be read");
        }
    }

    private static String reasonOf(Exception e) {
        Throwable cause = e.getCause();
        return cause == null ? e.getMessage() : e.getMessage() + " " + cause.getMessage();
    }

    private static EstException refused(EstRoute route, String reason) {
        log.debug("EST client certificate refused for realm {}: {}", route.realm(), reason);
        return new EstException(EstError.CERTIFICATE_REJECTED, route.realm());
    }
}
