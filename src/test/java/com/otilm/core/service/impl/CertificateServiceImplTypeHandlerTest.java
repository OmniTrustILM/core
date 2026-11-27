package com.otilm.core.service.impl;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceCertificateContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.core.certificate.CertificateDetail;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateRequestDetail;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.certificate.type.CertificateTypeHandler;
import com.otilm.core.certificate.type.CertificateTypeHandlerRegistry;
import com.otilm.core.certificate.type.ParsedRequest;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.service.RaProfileInternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.util.CertificateUtil;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.StubCertificateFixtures.keyPair;
import static com.otilm.core.util.builders.CertificateContentBuilder.aCertificateContent;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateServiceImplTypeHandlerTest {

    private static final CertificateType OTHER_TYPE = CertificateType.SSH;

    @Mock
    private CertificateRepository certificateRepository;
    @Mock
    private RaProfileInternalService raProfileService;
    @Mock
    private CertificateEventHistoryInternalService certificateEventHistoryService;
    @Mock
    private CertificateTypeHandler otherTypeHandler;

    private final CertificateServiceImpl service = new CertificateServiceImpl();

    @BeforeEach
    void wireServiceWithAHandlerOfAnotherType() {
        when(otherTypeHandler.typeCode()).thenReturn(OTHER_TYPE.getCode());
        service.setCertificateRepository(certificateRepository);
        service.setRaProfileService(raProfileService);
        service.setCertificateEventHistoryService(certificateEventHistoryService);
        service.setTypeHandlerRegistry(new CertificateTypeHandlerRegistry(List.of(otherTypeHandler)));
    }

    // ── SubmittedRequest ──────────────────────────────────────────────────────
    @Nested
    class SubmittedRequest {

        private static final String REQUEST_CONTENT = Base64
                .getEncoder()
                .encodeToString("a request of another type".getBytes(StandardCharsets.UTF_8));

        @Mock
        private CertificateRequestRepository certificateRequestRepository;
        @Mock
        private CryptographicKeyInternalService cryptographicKeyService;
        @Mock
        private AttributeEngine attributeEngine;
        @Mock
        private ResourceObjectAssociationService objectAssociationService;
        @Mock
        private Certificate requestedCertificate;
        @Mock
        private CertificateRequestEntity requestEntity;

        private final byte[] encodingTheHandlerRead = "the request as the handler read it"
                .getBytes(StandardCharsets.UTF_8);
        private final ParsedRequest parsedRequest = new ParsedRequest(OTHER_TYPE.getCode(),
                CertificateRequestFormat.PKCS10, encodingTheHandlerRead, "holder", keyPair().getPublic());
        private final UUID raProfileUuid = UUID.randomUUID();

        @BeforeEach
        void stubHandlerAndCollaborators() throws Exception {
            service.setCertificateRequestRepository(certificateRequestRepository);
            service.setCryptographicKeyInternalService(cryptographicKeyService);
            service.setAttributeEngine(attributeEngine);
            service.setObjectAssociationService(objectAssociationService);

            var raProfile = new RaProfile();
            raProfile.setAuthorityInstanceReference(new AuthorityInstanceReference());
            when(raProfileService.getRaProfileEntity(any())).thenReturn(raProfile);

            Certificate emptyCertificate = mock(Certificate.class);
            when(otherTypeHandler.readRequest(REQUEST_CONTENT, CertificateRequestFormat.PKCS10))
                    .thenReturn(parsedRequest);
            when(otherTypeHandler.newCertificate()).thenReturn(emptyCertificate);
            when(otherTypeHandler.stampRequested(emptyCertificate, parsedRequest)).thenReturn(requestedCertificate);
            when(otherTypeHandler.newCertificateRequest(parsedRequest)).thenReturn(requestEntity);
            when(otherTypeHandler.alternativePublicKey(parsedRequest)).thenReturn(Optional.empty());

            var requestDetail = mock(CertificateRequestDetail.class);
            when(requestDetail.getCertificateType()).thenReturn(OTHER_TYPE);
            var detail = mock(CertificateDetail.class);
            when(detail.getCertificateType()).thenReturn(OTHER_TYPE);
            when(detail.getCertificateRequest()).thenReturn(requestDetail);
            when(requestedCertificate.mapToDto()).thenReturn(detail);
            when(requestedCertificate.getUuid()).thenReturn(UUID.randomUUID());
            when(requestEntity.getUuid()).thenReturn(UUID.randomUUID());
            when(requestEntity.getFingerprint()).thenReturn("request-fingerprint");
            when(certificateRepository.save(requestedCertificate)).thenReturn(requestedCertificate);
        }

        @Test
        void storesTheCertificateTheHandlerStamped_whenTheRequestIsOfAnotherType() throws Exception {
            // given — the handler of the other type supplies the requested certificate

            // when
            submit();

            // then
            verify(certificateRepository).save(requestedCertificate);
            verify(requestedCertificate).setState(CertificateState.REQUESTED);
            verify(requestedCertificate).setCertificateRequest(requestEntity);
        }

        @Test
        void storesTheRequestEntityOfTheHandlerWithTheEncodingItRead_whenTheRequestIsOfAnotherType() throws Exception {
            // given
            var storedContent = Base64.getEncoder().encodeToString(encodingTheHandlerRead);

            // when
            submit();

            // then
            verify(certificateRequestRepository).save(requestEntity);
            verify(requestEntity).setContent(storedContent);
        }

        @Test
        void fingerprintsTheEncodingTheHandlerRead_whenTheRequestIsOfAnotherType() throws Exception {
            // given
            var fingerprintOfTheEncodingRead = CertificateUtil.getThumbprint(encodingTheHandlerRead);

            // when
            submit();

            // then
            verify(requestEntity).setFingerprint(fingerprintOfTheEncodingRead);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private CertificateDetail submit() throws Exception {
            return service
                    .submitCertificateRequest(REQUEST_CONTENT, CertificateRequestFormat.PKCS10, List.of(), List.of(),
                            List.of(), List.of(), null, null, raProfileUuid, null, null, OTHER_TYPE);
        }
    }

    // ── RelationType ──────────────────────────────────────────────────────────
    @Nested
    class RelationType {

        @Mock
        private CertificateRelationRepository certificateRelationRepository;

        @BeforeEach
        void wireRelationRepository() {
            service.setCertificateRelationRepository(certificateRelationRepository);
        }

        @ParameterizedTest
        @CsvSource({"true, true, RENEWAL", "true, false, REKEY", "false, true, REPLACEMENT"})
        void takesTheRelationTypeFromTheHandler_whenAssociatingCertificatesOfAnotherType(boolean sameHolderAndIssuer,
                boolean sameKeys, CertificateRelationType expectedRelation) throws Exception {
            // given
            Certificate predecessor = stubIssuedCertificate(OTHER_TYPE, new Date(1_000));
            Certificate successor = stubIssuedCertificate(OTHER_TYPE, new Date(2_000));
            when(otherTypeHandler.sameHolderAndIssuer(successor, predecessor)).thenReturn(sameHolderAndIssuer);
            if (sameHolderAndIssuer) {
                when(otherTypeHandler.sameKeys(successor, predecessor)).thenReturn(sameKeys);
            }

            // when
            service
                    .associateCertificates(SecuredUUID.fromUUID(successor.getUuid()),
                            SecuredUUID.fromUUID(predecessor.getUuid()));

            // then
            assertThat(captureSavedRelation().getRelationType()).isEqualTo(expectedRelation);
        }

        @Test
        void refusesTheAssociation_whenTheCertificatesAreOfDifferentTypes() {
            // given
            UUID x509Predecessor = stubCertificateOfType(CertificateType.X509);
            UUID successor = stubCertificateOfType(OTHER_TYPE);

            // when
            ThrowingCallable associate = () -> service
                    .associateCertificates(SecuredUUID.fromUUID(successor), SecuredUUID.fromUUID(x509Predecessor));

            // then
            assertThatThrownBy(associate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("different types");
            verifyNoInteractions(certificateRelationRepository);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private Certificate stubIssuedCertificate(CertificateType type, Date notBefore) {
            UUID uuid = UUID.randomUUID();
            Certificate certificate = mock(Certificate.class);
            when(certificate.getUuid()).thenReturn(uuid);
            when(certificate.getCertificateType()).thenReturn(type);
            when(certificate.getState()).thenReturn(CertificateState.ISSUED);
            when(certificate.getNotBefore()).thenReturn(notBefore);
            stubFound(uuid, certificate);
            return certificate;
        }

        private UUID stubCertificateOfType(CertificateType type) {
            UUID uuid = UUID.randomUUID();
            Certificate certificate = mock(Certificate.class);
            when(certificate.getUuid()).thenReturn(uuid);
            when(certificate.getCertificateType()).thenReturn(type);
            stubFound(uuid, certificate);
            return uuid;
        }

        private CertificateRelation captureSavedRelation() {
            ArgumentCaptor<CertificateRelation> saved = ArgumentCaptor.forClass(CertificateRelation.class);
            verify(certificateRelationRepository).save(saved.capture());
            return saved.getValue();
        }
    }

    // ── ResourceObjectContent ─────────────────────────────────────────────────
    @Nested
    class ResourceObjectContent {

        @Test
        void reportsTheTypeOfTheCertificate_whenItIsOfAnotherType() throws Exception {
            // given
            UUID uuid = UUID.randomUUID();
            var content = aCertificateContent().withContent("content of another type").build();
            Certificate certificate = mock(Certificate.class);
            when(certificate.getCertificateType()).thenReturn(OTHER_TYPE);
            when(certificate.getCertificateContent()).thenReturn(content);
            stubFound(uuid, certificate);

            // when
            ResourceObjectContentData contentData = service.getResourceObjectContent(uuid);

            // then
            assertThat(contentData)
                    .isInstanceOfSatisfying(ResourceCertificateContentData.class,
                            certificateData -> assertThat(certificateData.getCertificateType()).isEqualTo(OTHER_TYPE));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubFound(UUID uuid, Certificate certificate) {
        when(certificateRepository
                .findByUuid(argThat((SecuredUUID secured) -> secured != null && uuid.equals(secured.getValue()))))
                .thenReturn(Optional.of(certificate));
    }
}
