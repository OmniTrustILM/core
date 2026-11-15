package com.otilm.core.integration.service.est;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.repository.CertificateProtocolAssociationRepository;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.enrollment.EstReenrollmentKind;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.mocks.AuthorityV2ConnectorStubs;
import com.otilm.core.util.seeders.CertificateRequestPolicySeeder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static com.otilm.core.util.EstClientCredentialsFixtures.certificateCredentials;
import static com.otilm.core.util.mocks.AuthorityV2ConnectorStubs.RENEW_PATH;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@code /simplereenroll} through the service, against a connector double that renews at once.
 */
class EstReenrollmentITest extends AbstractEstReenrollmentITest {

    /** Days before the expiry at which renewal opens: more than a certificate is valid for, so it is due at once. */
    private static final int THRESHOLD_BEYOND_THE_VALIDITY = 400;

    @Autowired
    private CertificateRequestPolicySeeder requestPolicies;

    @Autowired
    private ClientOperationInternalService clientOperationService;

    @Autowired
    private CertificateProtocolAssociationRepository protocolAssociationRepository;

    // ── Renewals ──────────────────────────────────────────────────────────────

    @Nested
    class Renewals {

        @Test
        void answersRenewedCertificate_whenCsrCarriesTheSourceKey() throws Exception {
            // given
            X509Certificate source = issueDueCertificate(deviceKeys);
            Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
            X509Certificate renewed = issueFreshCertificate(deviceKeys);
            AuthorityV2ConnectorStubs.on(connector).stubRenew(renewed);
            byte[] requestWithTheSourceKey = signRequest(deviceKeys);

            // when
            ResponseEntity<byte[]> response = reenroll(requestWithTheSourceKey, certificateCredentials(source));

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(readCertificate(response)).isEqualTo(renewed);
            Certificate successor = findInInventory(renewed);
            assertSuccessorOf(seededSource, successor);
            assertAttributedToTheEstProfile(successor);
        }

        @Test
        void answersRekeyedCertificate_whenCsrCarriesANewKey() throws Exception {
            // given
            X509Certificate source = issueDueCertificate(deviceKeys);
            Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
            KeyPair newKeys = PkiFixtures.keyPair();
            X509Certificate rekeyed = issueFreshCertificate(newKeys);
            AuthorityV2ConnectorStubs.on(connector).stubRenew(rekeyed);
            byte[] requestWithANewKey = signRequest(newKeys);

            // when
            ResponseEntity<byte[]> response = reenroll(requestWithANewKey, certificateCredentials(source));

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(readCertificate(response)).isEqualTo(rekeyed);
            Certificate successor = findInInventory(rekeyed);
            assertSuccessorOf(seededSource, successor);
            assertAttributedToTheEstProfile(successor);
        }

        @Test
        void renewsRenewedCertificate_whenItIsDue() throws Exception {
            // given — the renewed certificate is due as soon as it is issued
            renewWithinDays(THRESHOLD_BEYOND_THE_VALIDITY);
            X509Certificate first = issueDueCertificate(deviceKeys);
            routes.seedIssuedCertificate(first, raProfile, estProfile);
            X509Certificate renewed = issueFreshCertificate(deviceKeys);
            AuthorityV2ConnectorStubs.on(connector).stubRenew(renewed);
            reenroll(signRequest(deviceKeys), certificateCredentials(first));
            X509Certificate renewedAgain = issueFreshCertificate(deviceKeys);
            AuthorityV2ConnectorStubs.on(connector).stubRenew(renewedAgain);
            byte[] nextRequest = signRequest(deviceKeys);

            // when
            ResponseEntity<byte[]> response = reenroll(nextRequest, certificateCredentials(renewed));

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(readCertificate(response)).isEqualTo(renewedAgain);
            assertSuccessorOf(findInInventory(renewed), findInInventory(renewedAgain));
        }

        @Test
        void renewsCertificate_whenItWasRenewedOutsideEst() throws Exception {
            // given — an operator renewed the certificate through the platform, which keeps its attribution to EST
            renewWithinDays(THRESHOLD_BEYOND_THE_VALIDITY);
            X509Certificate first = issueDueCertificate(deviceKeys);
            Certificate seededFirst = routes.seedIssuedCertificate(first, raProfile, estProfile);
            X509Certificate renewedByOperator = issueFreshCertificate(deviceKeys);
            AuthorityV2ConnectorStubs.on(connector).stubRenew(renewedByOperator);
            renewAsOperator(seededFirst);
            X509Certificate renewedOverEst = issueFreshCertificate(deviceKeys);
            AuthorityV2ConnectorStubs.on(connector).stubRenew(renewedOverEst);
            byte[] request = signRequest(deviceKeys);

            // when
            ResponseEntity<byte[]> response = reenroll(request, certificateCredentials(renewedByOperator));

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(readCertificate(response)).isEqualTo(renewedOverEst);
            assertSuccessorOf(findInInventory(renewedByOperator), findInInventory(renewedOverEst));
        }

        @ParameterizedTest
        @EnumSource(EstAuthenticationPolicy.class)
        void renewsSource_whenAnyPolicyApplies(EstAuthenticationPolicy policy) throws Exception {
            // given — the source has no registration authorization
            authenticateBy(policy);
            X509Certificate source = issueDueCertificate(deviceKeys);
            routes.seedIssuedCertificate(source, raProfile, estProfile);
            X509Certificate renewed = issueFreshCertificate(deviceKeys);
            AuthorityV2ConnectorStubs.on(connector).stubRenew(renewed);
            byte[] request = signRequest(deviceKeys);

            // when
            ResponseEntity<byte[]> response = reenroll(request, certificateCredentials(source));

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(readCertificate(response)).isEqualTo(renewed);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /** Renews the certificate with the same key through the platform, as an operator does. */
        private void renewAsOperator(Certificate certificate) throws Exception {
            String request = new String(signRequest(deviceKeys), StandardCharsets.US_ASCII);
            ClientCertificateRenewRequestDto renewal = ClientCertificateRenewRequestDto
                    .builder()
                    .request(request)
                    .build();
            clientOperationService
                    .renewCertificate(raProfile.getAuthorityInstanceReference().getSecuredParentUuid(),
                            raProfile.getSecuredUuid(), certificate.getUuid().toString(), renewal);
        }

        private void renewWithinDays(int threshold) {
            estProfile.setRenewalThreshold(threshold);
            estProfile = estProfileRepository.save(estProfile);
        }

        /**
         * The certificate is associated with the EST Profile and has the owner of the profile, which only a renewal or
         * rekey requested through the profile gives it: one requested without a protocol keeps the attribution of the
         * certificate it replaces, but not the owner.
         */
        private void assertAttributedToTheEstProfile(Certificate certificate) {
            assertThat(protocolAssociationRepository.findByCertificateUuid(certificate.getUuid()))
                    .hasValueSatisfying(attribution -> {
                        assertThat(attribution.getProtocol()).isEqualTo(CertificateProtocol.EST);
                        assertThat(attribution.getProtocolProfileUuid()).isEqualTo(estProfile.getUuid());
                    });
            assertThat(certificateRepository.findWithAssociationsByUuid(certificate.getUuid()).orElseThrow().getOwner())
                    .extracting(OwnerAssociation::getOwnerUuid)
                    .isEqualTo(PROFILE_OWNER_UUID);
        }
    }

    // ── Refusals ──────────────────────────────────────────────────────────────

    @Nested
    class Refusals {

        @Test
        void refusesWithPolicyText_whenRequestAttributePolicyIsViolated() throws Exception {
            // given — the default request-attribute set wants a common name, which neither the source nor the request
            // has
            requestPolicies.requireStrictRequestAttributes();
            var subjectWithoutCommonName = "O=Acme";
            X509Certificate source = issueDueCertificate(deviceKeys, subjectWithoutCommonName);
            routes.seedIssuedCertificate(source, raProfile, estProfile);
            byte[] requestWithoutCommonName = EstCsrFixtures.signedRequestBody(deviceKeys, subjectWithoutCommonName);
            EstClientCredentials credentials = certificateCredentials(source);

            // when
            ThrowingCallable reenroll = () -> reenroll(requestWithoutCommonName, credentials);

            // then
            assertThatThrownBy(reenroll).isInstanceOfSatisfying(EstException.class, refusal -> {
                assertThat(refusal.error()).isEqualTo(EstError.POLICY_VIOLATION);
                assertThat(refusal.realm()).contains(EST_PROFILE_NAME);
                assertThat(refusal.detail()).hasValueSatisfying(detail -> assertThat(detail).contains(RA_PROFILE_NAME));
            });
            assertThat(certificateRepository.count()).isOne();
        }

        @Test
        void answersRejected_whenComplianceRejectsTheSuccessor() throws Exception {
            // given — the compliance profile of the RA Profile wants RSA requests, and the device has an EC key
            requestPolicies.requireRsaRequests(raProfile);
            X509Certificate source = issueDueCertificate(deviceKeys);
            Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
            byte[] requestWithAnEcKey = signRequest(deviceKeys);
            EstClientCredentials credentials = certificateCredentials(source);

            // when
            ThrowingCallable reenroll = () -> reenroll(requestWithAnEcKey, credentials);

            // then
            assertThatThrownBy(reenroll).isInstanceOfSatisfying(EstException.class, refusal -> {
                assertThat(refusal.error()).isEqualTo(EstError.REQUEST_REJECTED);
                assertThat(refusal.realm()).contains(EST_PROFILE_NAME);
            });
            assertThat(findTheOnlyCertificateBesides(seededSource).getState()).isEqualTo(CertificateState.REJECTED);
            connector.verify(0, WireMock.postRequestedFor(WireMock.urlPathMatching(RENEW_PATH)));
        }

        @ParameterizedTest
        @EnumSource(EstReenrollmentKind.class)
        void answersIssuanceFailed_whenPublishingFails(EstReenrollmentKind kind) throws Exception {
            // given
            X509Certificate source = issueDueCertificate(deviceKeys);
            Certificate seededSource = routes.seedIssuedCertificate(source, raProfile, estProfile);
            var brokerDown = new IllegalStateException("broker down");
            Mockito.doThrow(brokerDown).when(actionProducer).produceMessage(Mockito.any());
            byte[] request = signRequestFor(kind);
            EstClientCredentials credentials = certificateCredentials(source);

            // when
            ThrowingCallable reenroll = () -> reenroll(request, credentials);

            // then
            assertThatThrownBy(reenroll).isInstanceOfSatisfying(EstException.class, refusal -> {
                assertThat(refusal.error()).isEqualTo(EstError.ISSUANCE_FAILED);
                assertThat(refusal.realm()).contains(EST_PROFILE_NAME);
            });
            assertThat(findTheOnlyCertificateBesides(seededSource).getState()).isEqualTo(CertificateState.FAILED);
        }

        @Test
        void refusesCertificate_whenAnUnacceptedClientSendsAForgedRequest() throws Exception {
            // given — the certificate that the client presents is not in the inventory
            X509Certificate notInTheInventory = issueDueCertificate(deviceKeys, SUBJECT);
            byte[] forgedRequest = EstCsrFixtures.forgedRequestBody(SUBJECT);
            EstClientCredentials credentials = certificateCredentials(notInTheInventory);

            // when
            ThrowingCallable reenroll = () -> reenroll(forgedRequest, credentials);

            // then
            assertThatThrownBy(reenroll).isInstanceOfSatisfying(EstException.class, refusal -> {
                assertThat(refusal.error()).isEqualTo(EstError.CERTIFICATE_REJECTED);
                assertThat(refusal.realm()).contains(EST_PROFILE_NAME);
            });
        }

        @ParameterizedTest
        @EnumSource(EstAuthenticationPolicy.class)
        void refusesInvalidSignature_whenAnAcceptedClientSendsAForgedRequest(EstAuthenticationPolicy policy)
                throws Exception {
            // given — the request asks for the identity of the certificate, so only its signature is wrong
            authenticateBy(policy);
            X509Certificate source = issueDueCertificate(deviceKeys, SUBJECT);
            routes.seedIssuedCertificate(source, raProfile, estProfile);
            byte[] forgedRequest = EstCsrFixtures.forgedRequestBody(SUBJECT);
            EstClientCredentials credentials = certificateCredentials(source);

            // when
            ThrowingCallable reenroll = () -> reenroll(forgedRequest, credentials);

            // then
            assertThatThrownBy(reenroll).isInstanceOfSatisfying(EstException.class, refusal -> {
                assertThat(refusal.error()).isEqualTo(EstError.INVALID_SIGNATURE);
                assertThat(refusal.realm()).contains(EST_PROFILE_NAME);
            });
            assertThat(certificateRepository.count()).isOne();
        }

        @Test
        void answersServiceUnavailable_whenTheAuthorityCannotValidateTheRequest() throws Exception {
            // given — the platform has the authority validate the request before it stores the new certificate
            AuthorityV2ConnectorStubs.on(connector).stubIssueAttributeValidationFailure();
            X509Certificate source = issueDueCertificate(deviceKeys);
            routes.seedIssuedCertificate(source, raProfile, estProfile);
            byte[] request = signRequest(deviceKeys);
            EstClientCredentials credentials = certificateCredentials(source);

            // when
            ThrowingCallable reenroll = () -> reenroll(request, credentials);

            // then
            assertThatThrownBy(reenroll).isInstanceOfSatisfying(EstException.class, refusal -> {
                assertThat(refusal.error()).isEqualTo(EstError.SERVICE_UNAVAILABLE);
                assertThat(refusal.realm()).contains(EST_PROFILE_NAME);
            });
            assertThat(certificateRepository.count()).isOne();
        }

        @Test
        void refusesIdentityMismatch_whenCsrAsksForAnotherName() throws Exception {
            // given
            X509Certificate source = issueDueCertificate(deviceKeys);
            routes.seedIssuedCertificate(source, raProfile, estProfile);
            byte[] requestForAnotherName = EstCsrFixtures.signedRequestBody(deviceKeys, SUBJECT, "device-2.example");
            EstClientCredentials credentials = certificateCredentials(source);

            // when
            ThrowingCallable reenroll = () -> reenroll(requestForAnotherName, credentials);

            // then
            assertThatThrownBy(reenroll).isInstanceOfSatisfying(EstException.class, refusal -> {
                assertThat(refusal.error()).isEqualTo(EstError.IDENTITY_MISMATCH);
                assertThat(refusal.realm()).contains(EST_PROFILE_NAME);
            });
            assertThat(certificateRepository.count()).isOne();
        }

        @Test
        void refusesRenewal_whenNotYetDue() throws Exception {
            // given — a fresh certificate has more than half of its validity left, and the profile sets no threshold
            X509Certificate fresh = issueFreshCertificate(deviceKeys);
            routes.seedIssuedCertificate(fresh, raProfile, estProfile);
            byte[] request = signRequest(deviceKeys);
            EstClientCredentials credentials = certificateCredentials(fresh);

            // when
            ThrowingCallable reenroll = () -> reenroll(request, credentials);

            // then
            assertThatThrownBy(reenroll).isInstanceOfSatisfying(EstException.class, refusal -> {
                assertThat(refusal.error()).isEqualTo(EstError.RENEWAL_NOT_DUE);
                assertThat(refusal.realm()).contains(EST_PROFILE_NAME);
            });
            assertThat(certificateRepository.count()).isOne();
        }

        @Test
        void refusesRekey_whenProfileForbidsIt() throws Exception {
            // given
            forbidRekey();
            X509Certificate source = issueDueCertificate(deviceKeys);
            routes.seedIssuedCertificate(source, raProfile, estProfile);
            byte[] requestWithANewKey = signRequest(PkiFixtures.keyPair());
            EstClientCredentials credentials = certificateCredentials(source);

            // when
            ThrowingCallable reenroll = () -> reenroll(requestWithANewKey, credentials);

            // then
            assertThatThrownBy(reenroll).isInstanceOfSatisfying(EstException.class, refusal -> {
                assertThat(refusal.error()).isEqualTo(EstError.REKEY_NOT_ALLOWED);
                assertThat(refusal.realm()).contains(EST_PROFILE_NAME);
            });
            assertThat(certificateRepository.count()).isOne();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void forbidRekey() {
            estProfile.setAllowRekey(false);
            estProfile = estProfileRepository.save(estProfile);
        }

        /** Signs a request that asks for the kind: with the key of the device to renew, with a new key to rekey. */
        private byte[] signRequestFor(EstReenrollmentKind kind) throws Exception {
            KeyPair keys = kind == EstReenrollmentKind.RENEWAL ? deviceKeys : PkiFixtures.keyPair();
            return signRequest(keys);
        }
    }
}
