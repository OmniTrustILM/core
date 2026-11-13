package com.otilm.core.service.est.impl;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.security.authz.ProtocolEndpoint;
import com.otilm.core.service.est.EstCaCertificates;
import com.otilm.core.service.est.EstConnectorFailures;
import com.otilm.core.service.est.EstCsrAttrsService;
import com.otilm.core.service.est.EstExternalService;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.EstRouteResolver;
import com.otilm.core.service.est.authentication.EstAuthenticators;
import com.otilm.core.service.est.authentication.EstClient;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.enrollment.EstEnrollment;
import com.otilm.core.service.est.enrollment.EstReenrollment;
import com.otilm.core.service.est.enrollment.EstServerKeyGeneration;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.est.message.EstRequestDecoder;
import com.otilm.core.service.est.message.EstResponses;
import com.otilm.core.service.est.message.EstServerKeyGenerationRequest;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

/**
 * The EST operations. Every call resolves its route first and writes nothing itself, and none runs in a transaction,
 * because each can wait for a connector, an OCSP responder or the Auth service. It carries no transactional annotation
 * on purpose: the controller calls it outside any transaction, and even {@code NOT_SUPPORTED} would open a scope whose
 * first read keeps its connection until the call returns. No resource authorization applies: the request runs as the
 * protocol user, the authentication policy of the EST Profile identifies a client that enrolls, and the certificate
 * that a client presents identifies it when it re-enrolls.
 */
@Slf4j
@Service
public class EstServiceImpl implements EstExternalService {

    private final EstRouteResolver routeResolver;
    private final EstCaCertificates caCertificates;
    private final EstCsrAttrsService csrAttrsService;
    private final EstAuthenticators authenticators;
    private final EstEnrollment enrollment;
    private final EstReenrollment reenrollment;
    private final EstServerKeyGeneration serverKeyGeneration;

    public EstServiceImpl(EstRouteResolver routeResolver, EstCaCertificates caCertificates,
            EstCsrAttrsService csrAttrsService, EstAuthenticators authenticators, EstEnrollment enrollment,
            EstReenrollment reenrollment, EstServerKeyGeneration serverKeyGeneration) {
        this.routeResolver = routeResolver;
        this.caCertificates = caCertificates;
        this.csrAttrsService = csrAttrsService;
        this.authenticators = authenticators;
        this.enrollment = enrollment;
        this.reenrollment = reenrollment;
        this.serverKeyGeneration = serverKeyGeneration;
    }

    @Override
    @ProtocolEndpoint
    public ResponseEntity<byte[]> getCaCertificates(String label) {
        EstRoute route = resolveRoute(label);
        List<X509Certificate> chain = caCertificates.fetch(route);
        return EstResponses.caCertificates(chain);
    }

    @Override
    @ProtocolEndpoint
    public ResponseEntity<byte[]> getCsrAttributes(String label) {
        EstRoute route = resolveRoute(label);
        byte[] csrAttrs = buildCsrAttrs(route);
        return EstResponses.csrAttributes(csrAttrs);
    }

    @Override
    @ProtocolEndpoint
    public ResponseEntity<byte[]> simpleEnroll(String label, @Sensitive byte[] request,
            @Sensitive EstClientCredentials credentials) {
        EstRoute route = resolveRoute(label);
        Pkcs10CertificateRequest csr = decodeRequest(request, route);
        EstClient client = authenticators.authenticate(route, credentials, csr);
        verifyProofOfPossession(csr, route, client);
        return enrollment.enroll(route, client, csr, credentials);
    }

    @Override
    @ProtocolEndpoint
    public ResponseEntity<byte[]> simpleReenroll(String label, @Sensitive byte[] request,
            @Sensitive EstClientCredentials credentials) {
        EstRoute route = resolveRoute(label);
        Pkcs10CertificateRequest csr = decodeRequest(request, route);
        return reenrollment.reenroll(route, csr, credentials);
    }

    @Override
    @ProtocolEndpoint
    public ResponseEntity<byte[]> serverKeyGeneration(String label, @Sensitive byte[] request,
            @Sensitive EstClientCredentials credentials) {
        EstRoute route = resolveRoute(label);
        serverKeyGeneration.requireAvailable(route);
        Pkcs10CertificateRequest csr = decodeRequest(request, route);
        requireUnprotectedDelivery(csr, route);
        EstClient client = authenticators.authenticate(route, credentials, csr);
        return serverKeyGeneration.generate(route, client, csr, credentials);
    }

    /**
     * Finds the route of the request and names its EST Profile in the audit record. A label that resolves to nothing,
     * or to two things, is refused as not found: the client learns nothing about which profiles exist.
     */
    private EstRoute resolveRoute(String label) {
        EstRoute route = routeResolver.resolve(label).orElseThrow(() -> new EstException(EstError.NOT_FOUND));
        LoggingHelper
                .putLogResourceInfo(Resource.EST_PROFILE, true, route.estProfile().getUuid().toString(),
                        route.estProfile().getName());
        return route;
    }

    /**
     * Decodes the body of an enrollment, as the authenticators judge a client by the subject and the subject
     * alternative names that the request asks for. The decoder knows no route, so a refusal of it is thrown again with
     * the realm of the route.
     */
    private static Pkcs10CertificateRequest decodeRequest(byte[] body, EstRoute route) {
        try {
            return EstRequestDecoder.decode(body);
        } catch (EstException e) {
            throw e.withRealm(route.realm());
        }
    }

    /**
     * The client's key is not used, so its signature is not verified. The client may not ask for the key to be
     * encrypted, and the refusal is thrown again with the realm of the route, as for decoding.
     */
    private static void requireUnprotectedDelivery(Pkcs10CertificateRequest csr, EstRoute route) {
        try {
            EstServerKeyGenerationRequest.requireUnprotectedDelivery(csr.getJcaObject());
        } catch (EstException e) {
            throw e.withRealm(route.realm());
        }
    }

    /**
     * Checking a signature can take much computing time, so it runs only once the policy of the route has accepted the
     * client. Under {@code certificateRegistration} that is an identification of the registration, whose password is
     * verified when the registration is completed, so the decoder bounds the keys and the signature algorithm that the
     * check builds. A refusal is thrown again with the realm of the route, as for decoding. Under
     * {@code certificateRegistration} it is the refusal of a request that matches no registration, so that a forged
     * request for a registered subject is answered as one for an unknown subject.
     */
    private static void verifyProofOfPossession(Pkcs10CertificateRequest csr, EstRoute route, EstClient client) {
        try {
            EstRequestDecoder.verifyProofOfPossession(csr);
        } catch (EstException e) {
            if (client.policy() == EstAuthenticationPolicy.CERTIFICATE_REGISTRATION) {
                throw new EstException(EstError.REGISTRATION_REJECTED, route.realm());
            }
            throw e.withRealm(route.realm());
        }
    }

    /**
     * Builds the attributes that the RA Profile of the route asks for. Its authority can supply them, so building them
     * can mean a call to the connector. Any failure is answered as the service being unavailable, and logged at ERROR.
     */
    private byte[] buildCsrAttrs(EstRoute route) {
        RaProfile raProfile = route.raProfile();
        try {
            return csrAttrsService.buildCsrAttrs(raProfile);
        } catch (ConnectorException | NotFoundException | IOException | RuntimeException e) {
            if (EstConnectorFailures.isConnectorFailure(e)) {
                log
                        .error("The attribute set of RA Profile {} could not be resolved: {}", raProfile.getUuid(),
                                EstConnectorFailures.classNames(e));
            } else {
                log.error("The attribute set of RA Profile {} could not be resolved", raProfile.getUuid(), e);
            }
            throw unavailable(route);
        }
    }

    private static EstException unavailable(EstRoute route) {
        return new EstException(EstError.SERVICE_UNAVAILABLE, route.realm());
    }

}
