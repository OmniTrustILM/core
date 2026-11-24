package com.otilm.core.service.v2.impl;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.certificate.type.AuthorityCertificateTypes;
import com.otilm.core.certificate.type.CertificateTypeHandler;
import com.otilm.core.certificate.type.CertificateTypeHandlerRegistry;
import com.otilm.core.certificate.type.ParsedCertificate;
import com.otilm.core.certificate.type.ParsedRequest;
import com.otilm.core.certificate.type.RequestFormatResolver;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.registration.RegistrationChallengeGate;
import com.otilm.core.service.v2.ExtendedAttributeService;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** The dry run that decides whether ACME finalize renews, rekeys or issues for the certificate an order replaces. */
@ExtendWith(MockitoExtension.class)
class ClientOperationServiceImplRenewalForTest {

    private static final String REQUEST = "Y3Ny";

    @Mock
    private CertificateRepository certificateRepository;
    @Mock
    private ExtendedAttributeService extendedAttributeService;
    @Mock
    private AuthorityCertificateTypes authorityCertificateTypes;
    @Mock
    private RegistrationChallengeGate registrationChallengeGate;
    @Mock
    private CertificateTypeHandlerRegistry typeHandlerRegistry;
    @Mock
    private RequestFormatResolver requestFormatResolver;
    @Mock
    private CertificateTypeHandler handler;

    private ClientOperationServiceImpl service;
    private Certificate predecessor;
    private SecuredParentUUID authorityUuid;
    private SecuredUUID raProfileUuid;
    private ParsedRequest parsedRequest;
    private ParsedCertificate current;

    @BeforeEach
    void stubAnIssuedPredecessor() throws Exception {
        service = new ClientOperationServiceImpl();
        service.setCertificateRepository(certificateRepository);
        service.setExtendedAttributeService(extendedAttributeService);
        service.setAuthorityCertificateTypes(authorityCertificateTypes);
        service.setRegistrationChallengeGate(registrationChallengeGate);
        service.setTypeHandlerRegistry(typeHandlerRegistry);
        service.setRequestFormatResolver(requestFormatResolver);

        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setUuid(UUID.randomUUID());
        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        raProfile.setEnabled(true);
        raProfile.setAuthorityInstanceReference(authority);
        CertificateContent content = new CertificateContent();
        content.setContent("AQID");
        predecessor = aCertificate()
                .withUuid(UUID.randomUUID())
                .withState(CertificateState.ISSUED)
                .withArchived(false)
                .withRaProfile(raProfile)
                .withRaProfileUuid(raProfile.getUuid())
                .withCertificateContent(content)
                .build();
        authorityUuid = SecuredParentUUID.fromUUID(authority.getUuid());
        raProfileUuid = SecuredUUID.fromUUID(raProfile.getUuid());
        parsedRequest = mock(ParsedRequest.class);
        current = mock(ParsedCertificate.class);

        when(certificateRepository.findByUuid(predecessor.getUuid())).thenReturn(Optional.of(predecessor));
        lenient().when(typeHandlerRegistry.require(CertificateType.X509.getCode())).thenReturn(handler);
        lenient()
                .when(requestFormatResolver.resolve(CertificateRequestFormat.PKCS10, CertificateType.X509))
                .thenReturn(CertificateRequestFormat.PKCS10);
        lenient().when(handler.readRequest(REQUEST, CertificateRequestFormat.PKCS10)).thenReturn(parsedRequest);
        lenient().when(handler.parseCertificate(any())).thenReturn(Optional.of(current));
    }

    @Test
    void answersRenew_whenTheRequestKeepsTheKey() throws Exception {
        // when
        Optional<ResourceAction> renewal = renewalFor();

        // then
        assertThat(renewal).contains(ResourceAction.RENEW);
        verify(extendedAttributeService).mergeAndValidateRenewAttributes(predecessor.getRaProfile(), List.of());
    }

    @Test
    void answersRekey_whenTheRequestBringsANewKeyForTheSameSubject() throws Exception {
        // given
        doThrow(new ValidationException("Public key of certificate and CSR does not match"))
                .when(handler)
                .requireSameKey(parsedRequest, current);

        // when
        Optional<ResourceAction> renewal = renewalFor();

        // then
        assertThat(renewal).contains(ResourceAction.REKEY);
    }

    @Test
    void answersNothing_whenNeitherRenewalNorRekeyAcceptsTheRequest() throws Exception {
        // given
        doThrow(new ValidationException("Public key of certificate and CSR does not match"))
                .when(handler)
                .requireSameKey(parsedRequest, current);
        doThrow(new ValidationException("Subject DN of certificate and CSR does not match"))
                .when(handler)
                .checkRekeyRequest(parsedRequest, current);

        // when
        Optional<ResourceAction> renewal = renewalFor();

        // then
        assertThat(renewal).isEmpty();
    }

    @Test
    void doesNotAskTheAuthorityForTheCertificateType_whenTheReplacementComesThroughAProtocol() throws Exception {
        // when
        Optional<ResourceAction> renewal = renewalFor();

        // then
        assertThat(renewal).contains(ResourceAction.RENEW);
        verifyNoInteractions(authorityCertificateTypes);
    }

    @Test
    void answersNothing_whenTheCertificateRequiresItsRegistrationChallenge() throws Exception {
        // given
        when(registrationChallengeGate.requiresChallenge(predecessor.getUuid())).thenReturn(true);

        // when
        Optional<ResourceAction> renewal = renewalFor();

        // then
        assertThat(renewal).isEmpty();
        verifyNoInteractions(typeHandlerRegistry);
    }

    @Test
    void answersNothing_whenTheCertificateIsArchived() throws Exception {
        // given
        predecessor.setArchived(true);

        // when
        Optional<ResourceAction> renewal = renewalFor();

        // then
        assertThat(renewal).isEmpty();
    }

    @Test
    void propagatesTheFailure_whenTheConnectorCannotBeAsked() throws Exception {
        // given
        ConnectorException unreachable = new ConnectorException("connector unreachable");
        doThrow(unreachable).when(extendedAttributeService).mergeAndValidateRenewAttributes(any(), any());

        // when
        ThrowingCallable renewal = this::renewalFor;

        // then
        assertThatThrownBy(renewal).isSameAs(unreachable);
    }

    @Test
    void propagatesTheFailure_whenAnUnexpectedErrorOccurs() {
        // given
        IllegalStateException databaseFailure = new IllegalStateException("database unavailable");
        when(registrationChallengeGate.requiresChallenge(predecessor.getUuid())).thenThrow(databaseFailure);

        // when
        ThrowingCallable renewal = this::renewalFor;

        // then
        assertThatThrownBy(renewal).isSameAs(databaseFailure);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Optional<ResourceAction> renewalFor() throws Exception {
        return service
                .renewalFor(authorityUuid, raProfileUuid, predecessor.getUuid(), REQUEST,
                        CertificateRequestFormat.PKCS10);
    }
}
