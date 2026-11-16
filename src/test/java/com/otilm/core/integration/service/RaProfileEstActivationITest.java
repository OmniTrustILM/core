package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.raprofile.ActivateEstForRaProfileRequestDto;
import com.otilm.api.model.client.raprofile.EditRaProfileRequestDto;
import com.otilm.api.model.client.raprofile.RaProfileEstDetailResponseDto;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeVersion;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.raprofile.RaProfileDto;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import com.otilm.core.dao.repository.scep.ScepProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.service.EstProfileExternalService;
import com.otilm.core.service.RaProfileExternalService;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.builders.AuthorityFixtures;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class RaProfileEstActivationITest extends BaseSpringBootTest {

    private static final String ORIGIN = "https://ilm.example.com";
    private static final String ISSUE_ATTRIBUTES = "/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes";
    private static final String NOT_A_LABEL = "RA Profile name cannot be used as an EST label";
    private static final String EDITED_MEANWHILE = "changed meanwhile";
    private static final String NO_CONNECTOR = "Cannot activate EST protocol for RA profile without associated authority and its connector";
    private static final String CONNECTOR_CHANGED = "The connector of the RA Profile's authority changed at the same time; repeat the request";
    private static final String RA_PROFILE_ATTRIBUTES = "/v1/authorityProvider/authorities/[^/]+/raProfile/attributes";

    private static WireMockServer connectorServer;

    @Autowired
    private RaProfileExternalService raProfileService;

    @Autowired
    private EstProfileExternalService estProfileService;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private EstProfileRepository estProfileRepository;

    @Autowired
    private ScepProfileRepository scepProfileRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private FunctionGroupRepository functionGroupRepository;

    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;

    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private TransactionTemplate transactionTemplate;

    private AuthorityFixtures.Fixture authority;
    private RaProfile raProfile;

    @BeforeAll
    static void startConnector() {
        connectorServer = LoopbackWireMock.start();
    }

    @AfterAll
    static void stopConnector() {
        connectorServer.stop();
    }

    @BeforeEach
    void resetConnectorAndCreateRaProfileUnderAnAuthority() {
        connectorServer.resetAll();
        authority = AuthorityFixtures.v2Authority(collectAuthorityRepos(), connectorServer, "MOCK");
        raProfile = renameRaProfile(authority.raProfile(), "devices-ra");
    }

    // ── ActivateEst ───────────────────────────────────────────────────────────

    @Nested
    class ActivateEst {

        @Test
        void activatesEst_whenConnectorValidatesTheIssueAttributes() throws Exception {
            // given
            var attributeContent = "devices";
            UUID attributeUuid = stubConnector(0);
            EstProfile estProfile = saveEstProfile();
            RequestAttribute issueAttribute = createIssueAttribute(attributeUuid, attributeContent);
            String label = raProfile.getName();

            // when
            RaProfileEstDetailResponseDto activated = activateEst(raProfile, estProfile, issueAttribute);

            // then
            assertThat(activated.isEstAvailable()).isTrue();
            assertThat(activated.getLabel()).isEqualTo(label);
            assertThat(activated.getEstUrl()).isEqualTo(ORIGIN + "/.well-known/est/" + label);
            assertThat(activated.getUuid()).isEqualTo(estProfile.getUuid().toString());
            assertThat(activated.getName()).isEqualTo(estProfile.getName());
            assertThat(activated.getIssueCertificateAttributes())
                    .extracting(ResponseAttribute::getUuid)
                    .containsExactly(attributeUuid);
            assertThat(readContentData(activated.getIssueCertificateAttributes().getFirst()))
                    .containsExactly(attributeContent);
            assertThat(loadEstProfileUuid(raProfile)).isEqualTo(estProfile.getUuid());
            assertThat(loadIssueAttributes(raProfile)).contains(attributeUuid.toString());
            assertThat(loadEnabledProtocols(raProfile)).contains("EST");
        }

        @Test
        void storesEmptyIssueAttributes_whenRequestCarriesNone() throws Exception {
            // given
            stubConnector(0);
            EstProfile estProfile = saveEstProfile();
            ActivateEstForRaProfileRequestDto withoutIssueAttributes = new ActivateEstForRaProfileRequestDto();
            withoutIssueAttributes.setIssueCertificateAttributes(null);

            // when
            RaProfileEstDetailResponseDto activated = raProfileService
                    .activateEstForRaProfile(getAuthorityUuid(), raProfile.getSecuredUuid(), estProfile.getUuid(),
                            withoutIssueAttributes, ORIGIN);

            // then
            assertThat(activated.isEstAvailable()).isTrue();
            assertThat(activated.getIssueCertificateAttributes()).isEmpty();
            assertThat(loadIssueAttributes(raProfile)).isEqualTo("[]");
        }

        @Test
        void replacesEstProfile_whenActivatedAgain() throws Exception {
            // given
            UUID attributeUuid = stubConnector(0);
            EstProfile first = saveEstProfile("est-first");
            EstProfile second = saveEstProfile("est-second");
            activateEst(raProfile, first, createIssueAttribute(attributeUuid));

            // when
            RaProfileEstDetailResponseDto reactivated = activateEst(raProfile, second);

            // then
            assertThat(reactivated.getName()).isEqualTo(second.getName());
            assertThat(loadEstProfileUuid(raProfile)).isEqualTo(second.getUuid());
            assertThat(loadIssueAttributes(raProfile)).isEqualTo("[]");
        }

        @Test
        void keepsAttributesOfOtherProtocols_whenActivatedAgain() throws Exception {
            // given
            UUID attributeUuid = stubConnector(0);
            EstProfile first = saveEstProfile("est-first");
            EstProfile second = saveEstProfile("est-second");
            insertScepIssueAttributes(raProfile);
            activateEst(raProfile, first, createIssueAttribute(attributeUuid));

            // when
            activateEst(raProfile, second);

            // then
            assertThat(countProtocolAttributeRows(raProfile)).isEqualTo(1);
            assertThat(loadScepIssueAttributes(raProfile)).isEqualTo("[]");
        }

        @ParameterizedTest
        @ValueSource(strings = {"CACERTS", "..", "a b"})
        void throwsValidation_whenRaProfileNameCannotBeALabel(String unusableName) {
            // given
            RaProfile unusable = renameRaProfile(raProfile, unusableName);
            EstProfile estProfile = saveEstProfile();

            // when
            ThrowingCallable activateUnderUnusableName = () -> activateEst(unusable, estProfile);

            // then
            assertThatThrownBy(activateUnderUnusableName)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(NOT_A_LABEL);
            assertNothingActivatedOn(unusable);
            assertConnectorNeverCalled();
        }

        @Test
        void throwsValidation_whenRaProfileNameIsAlreadyTheLabelOfAnEstProfile() {
            // given
            String takenLabel = raProfile.getName();
            saveEstProfile(takenLabel);
            EstProfile other = saveEstProfile();

            // when
            ThrowingCallable activateUnderTakenLabel = () -> activateEst(raProfile, other);

            // then
            assertThatThrownBy(activateUnderTakenLabel)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("RA Profile name is already the label of EST Profile " + takenLabel);
            assertNothingActivatedOn(raProfile);
            assertConnectorNeverCalled();
        }

        @Test
        void throwsNotFoundBeforeCallingTheConnector_whenEstProfileDoesNotExist() {
            // given
            EstProfile unknown = anEstProfile().withUuid(UUID.randomUUID()).build();

            // when
            ThrowingCallable activateUnknownEstProfile = () -> activateEst(raProfile, unknown);

            // then
            assertThatThrownBy(activateUnknownEstProfile).isInstanceOf(NotFoundException.class);
            assertNothingActivatedOn(raProfile);
            assertConnectorNeverCalled();
        }

        @Test
        void throwsNotFound_whenRaProfileDoesNotExist() {
            // given
            EstProfile estProfile = saveEstProfile();
            RaProfile unknown = createUnknownRaProfile();

            // when
            ThrowingCallable activateUnknownRaProfile = () -> activateEst(unknown, estProfile);

            // then
            assertThatThrownBy(activateUnknownRaProfile).isInstanceOf(NotFoundException.class);
        }

        /** An RA Profile under no authority is not under the one in the URL either. */
        @Test
        void throwsNotFound_whenRaProfileIsUnderNoAuthority() {
            // given
            RaProfile withoutAuthority = saveRaProfileWithoutAuthority("plain");
            EstProfile estProfile = saveEstProfile();

            // when
            ThrowingCallable activateWithoutAuthority = () -> activateEst(withoutAuthority, estProfile);

            // then
            assertThatThrownBy(activateWithoutAuthority)
                    .isInstanceOf(NotFoundException.class)
                    .hasMessageContaining(getNotFoundMessage(withoutAuthority));
            assertNothingActivatedOn(withoutAuthority);
            assertConnectorNeverCalled();
        }

        @Test
        void throwsNotFound_whenRaProfileIsUnderAnotherAuthority() {
            // given
            stubConnector(0);
            UUID authorityOfRaProfile = authority.authority().getUuid();
            SecuredParentUUID otherAuthority = createOtherAuthority();
            SecuredUUID raProfileUuid = raProfile.getSecuredUuid();
            UUID estProfileUuid = saveEstProfile().getUuid();
            ActivateEstForRaProfileRequestDto request = new ActivateEstForRaProfileRequestDto();

            // when
            ThrowingCallable activateThroughAnotherAuthority = () -> raProfileService
                    .activateEstForRaProfile(otherAuthority, raProfileUuid, estProfileUuid, request, ORIGIN);

            // then
            assertThatThrownBy(activateThroughAnotherAuthority)
                    .isInstanceOf(NotFoundException.class)
                    .hasMessageContaining(getNotFoundMessage(raProfile))
                    .hasMessageNotContaining(authorityOfRaProfile.toString());
            assertNothingActivatedOn(raProfile);
            assertConnectorNeverCalled();
        }

        @Test
        void throwsValidation_whenAuthorityOfRaProfileHasNoConnector() {
            // given
            jdbcTemplate
                    .update("UPDATE " + dbSchema
                            + ".authority_instance_reference SET connector_uuid = NULL WHERE uuid = ?",
                            authority.authority().getUuid());
            EstProfile estProfile = saveEstProfile();

            // when
            ThrowingCallable activateWithoutConnector = () -> activateEst(raProfile, estProfile);

            // then
            assertThatThrownBy(activateWithoutConnector)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(NO_CONNECTOR);
            assertNothingActivatedOn(raProfile);
            assertConnectorNeverCalled();
        }

        @Test
        void throwsValidation_whenConnectorRejectsTheIssueAttributes() {
            // given
            RequestAttribute issueAttribute = createIssueAttribute(stubConnector(0));
            connectorServer
                    .stubFor(WireMock
                            .post(WireMock.urlPathMatching(ISSUE_ATTRIBUTES + "/validate"))
                            .willReturn(WireMock
                                    .aResponse()
                                    .withStatus(422)
                                    .withHeader("Content-Type", "application/json")
                                    .withBody("[\"Issue attributes are invalid\"]")));
            EstProfile estProfile = saveEstProfile();

            // when
            ThrowingCallable activateWithRejectedAttributes = () -> activateEst(raProfile, estProfile, issueAttribute);

            // then
            assertThatThrownBy(activateWithRejectedAttributes).isInstanceOf(ValidationException.class);
            assertNothingActivatedOn(raProfile);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void insertScepIssueAttributes(RaProfile target) {
            jdbcTemplate
                    .update("INSERT INTO " + dbSchema
                            + ".ra_profile_protocol_attribute (uuid, ra_profile_uuid, scep_issue_certificate_attributes) "
                            + "VALUES (?, ?, '[]')", UUID.randomUUID(), target.getUuid());
        }

        private String loadScepIssueAttributes(RaProfile target) {
            return jdbcTemplate
                    .queryForObject(
                            "SELECT scep_issue_certificate_attributes FROM " + dbSchema
                                    + ".ra_profile_protocol_attribute WHERE ra_profile_uuid = ?",
                            String.class, target.getUuid());
        }

        private static List<Object> readContentData(ResponseAttribute attribute) {
            List<? extends AttributeContent> content = attribute.getContent();
            return content.stream().<Object>map(AttributeContent::getData).toList();
        }
    }

    // ── ActivationPermissions ─────────────────────────────────────────────────

    @Nested
    class ActivationPermissions {

        @Test
        void throwsAccessDenied_whenUpdateOfRaProfileIsDenied() {
            // given
            stubConnector(0);
            EstProfile estProfile = saveEstProfile();
            denyResourceAccess(Resource.RA_PROFILE, ResourceAction.UPDATE);

            // when
            ThrowingCallable activateWithoutUpdatePermission = () -> activateEst(raProfile, estProfile);

            // then
            assertThatThrownBy(activateWithoutUpdatePermission).isInstanceOf(AccessDeniedException.class);
            assertNothingActivatedOn(raProfile);
            assertConnectorNeverCalled();
        }

        /**
         * The EST Profile is authorized by its own read, never as one of the RA Profiles the activation is checked on.
         */
        @Test
        void activatesEst_whenRaProfileUpdateIsDeniedOnlyForTheEstProfileUuid() throws Exception {
            // given
            stubConnector(0);
            EstProfile estProfile = saveEstProfile();
            denyResourceAccess(Resource.RA_PROFILE, ResourceAction.UPDATE, estProfile.getUuid());

            // when
            activateEst(raProfile, estProfile);

            // then
            assertThat(loadEstProfileUuid(raProfile)).isEqualTo(estProfile.getUuid());
        }

        @Test
        void throwsAccessDenied_whenCallerCannotSeeTheEstProfile() {
            // given
            stubConnector(0);
            EstProfile estProfile = saveEstProfile();
            denyResourceAccess(Resource.EST_PROFILE, ResourceAction.DETAIL, estProfile.getUuid());

            // when
            ThrowingCallable activateUnseenEstProfile = () -> activateEst(raProfile, estProfile);

            // then
            assertThatThrownBy(activateUnseenEstProfile).isInstanceOf(AccessDeniedException.class);
            assertNothingActivatedOn(raProfile);
            assertConnectorNeverCalled();
        }

        /** Checked before the lookup, so a caller who cannot see EST Profiles cannot tell which UUIDs exist. */
        @Test
        void throwsAccessDeniedRatherThanNotFound_whenCallerCannotSeeEstProfiles() {
            // given
            EstProfile unknown = anEstProfile().withUuid(UUID.randomUUID()).build();
            denyResourceAccess(Resource.EST_PROFILE, ResourceAction.DETAIL);

            // when
            ThrowingCallable activateUnknownEstProfile = () -> activateEst(raProfile, unknown);

            // then
            assertThatThrownBy(activateUnknownEstProfile).isInstanceOf(AccessDeniedException.class);
            assertConnectorNeverCalled();
        }
    }

    // ── ActivationRaces ───────────────────────────────────────────────────────

    @Nested
    class ActivationRaces {

        /**
         * The connector may take as long as it likes, so nothing of the activation may hold a transaction open while it
         * is called: an open transaction is a database session that waits for the client in the state idle in
         * transaction. Only such sessions that hold a lock on the tables the activation works on count, so a
         * transaction of unrelated work on the same database cannot fail the test.
         */
        @Test
        void opensNoTransaction_whenCallingTheConnector() throws Exception {
            // given
            EstProfile estProfile = saveEstProfile();
            Callable<RaProfileEstDetailResponseDto> activation = createSlowActivation(estProfile);
            AtomicLong sessionsInTransaction = new AtomicLong(-1);
            Runnable countSessionsInTransaction = () -> sessionsInTransaction
                    .set(countSessionsInTransactionOnTheActivationsTables());

            // when
            whileTheConnectorIsCalled(countSessionsInTransaction, activation);

            // then
            assertThat(sessionsInTransaction).hasValue(0);
            assertThat(loadEstProfileUuid(raProfile)).isEqualTo(estProfile.getUuid());
        }

        @Test
        void throwsNotFound_whenRaProfileIsDeletedWhileTheConnectorIsCalled() {
            // given
            Callable<RaProfileEstDetailResponseDto> activation = createSlowActivation(saveEstProfile());
            Runnable deletion = () -> deleteRow("ra_profile", raProfile.getUuid());

            // when
            ThrowingCallable activateWhileTheRaProfileIsDeleted = () -> whileTheConnectorIsCalled(deletion, activation);

            // then
            assertThatThrownBy(activateWhileTheRaProfileIsDeleted).isInstanceOf(NotFoundException.class);
            assertThat(countProtocolAttributeRows(raProfile)).isZero();
        }

        /**
         * The label was free when it was checked before the connector call, which is as long ago as the connector is
         * slow.
         */
        @Test
        void throwsValidation_whenEstProfileTakesTheLabelWhileTheConnectorIsCalled() {
            // given
            String takenLabel = raProfile.getName();
            Callable<RaProfileEstDetailResponseDto> activation = createSlowActivation(saveEstProfile());
            Runnable creation = () -> saveEstProfile(takenLabel);

            // when
            ThrowingCallable activateWhileTheLabelIsTaken = () -> whileTheConnectorIsCalled(creation, activation);

            // then
            assertThatThrownBy(activateWhileTheLabelIsTaken)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("RA Profile name is already the label of EST Profile " + takenLabel);
            assertNothingActivatedOn(raProfile);
            assertThat(countProtocolAttributeRows(raProfile)).isZero();
        }

        /**
         * The caller was authorized on the authority the RA Profile was under, and an edit can move it to another one
         * while the connector answers. The activation is then refused as for an RA Profile that is not under the
         * authority.
         */
        @Test
        void throwsNotFound_whenRaProfileIsMovedToAnotherAuthorityWhileTheConnectorIsCalled() {
            // given
            AuthorityInstanceReference otherAuthority = createAnotherAuthorityOfTheConnector();
            stubTheRaProfileEdit(0);
            Callable<RaProfileEstDetailResponseDto> activation = createSlowActivation(saveEstProfile());
            Runnable move = createMoveOfTheRaProfileTo(otherAuthority);

            // when
            ThrowingCallable activateWhileTheRaProfileIsMoved = () -> whileTheConnectorIsCalled(move, activation);

            // then
            assertThatThrownBy(activateWhileTheRaProfileIsMoved)
                    .isInstanceOf(NotFoundException.class)
                    .hasMessageContaining(getNotFoundMessage(raProfile))
                    .hasMessageNotContaining(otherAuthority.getUuid().toString());
            assertNothingActivatedOn(raProfile);
            assertThat(countProtocolAttributeRows(raProfile)).isZero();
            assertThat(
                    raProfileRepository.findById(raProfile.getUuid()).orElseThrow().getAuthorityInstanceReferenceUuid())
                    .describedAs("the move is kept")
                    .isEqualTo(otherAuthority.getUuid());
        }

        /**
         * The issue attributes were validated by the connector of the RA Profile's authority, which can change while it
         * answers. The activation is then refused with a request to repeat it.
         */
        @Test
        void throwsValidation_whenAuthorityGetsAnotherConnectorWhileTheConnectorIsCalled() {
            // given
            UUID otherConnector = AuthorityFixtures.v2Authority(collectAuthorityRepos(), "OTHER").connector().getUuid();
            Callable<RaProfileEstDetailResponseDto> activation = createSlowActivation(saveEstProfile());
            Runnable reconnection = () -> jdbcTemplate
                    .update("UPDATE " + dbSchema
                            + ".authority_instance_reference SET connector_uuid = ? WHERE uuid = ?", otherConnector,
                            authority.authority().getUuid());

            // when
            ThrowingCallable activateWhileTheAuthorityIsReconnected = () -> whileTheConnectorIsCalled(reconnection,
                    activation);

            // then
            assertThatThrownBy(activateWhileTheAuthorityIsReconnected)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(CONNECTOR_CHANGED);
            assertNothingActivatedOn(raProfile);
            assertThat(countProtocolAttributeRows(raProfile)).isZero();
        }

        /** The RA Profile read before the connector call is older than the row once the connector has answered. */
        @Test
        void keepsEdit_whenRaProfileIsEditedWhileTheConnectorIsCalled() throws Exception {
            // given
            EstProfile estProfile = saveEstProfile();
            Callable<RaProfileEstDetailResponseDto> activation = createSlowActivation(estProfile);

            // when
            whileTheConnectorIsCalled(this::editRaProfile, activation);

            // then
            assertEditAndActivationStored(estProfile);
        }

        /**
         * A request keeps what it reads in its persistence context, and every transaction that runs on that context
         * writes back what changed on the copies it holds. The RA Profile the request read before the activation is
         * therefore neither the copy the write transaction may find, nor one that the request's next transaction may
         * write over the edit.
         */
        @Test
        void keepsEdit_whenRequestReadTheRaProfileBeforeTheActivation() throws Exception {
            // given
            EstProfile estProfile = saveEstProfile();
            Callable<RaProfileEstDetailResponseDto> activation = createSlowActivation(estProfile);
            UUID raProfileUuid = raProfile.getUuid();

            // when
            inARequest(request -> {
                request.find(RaProfile.class, raProfileUuid);
                whileTheConnectorIsCalled(this::editRaProfile, activation);
                runTheRequestsNextTransaction();
                return null;
            });

            // then
            assertEditAndActivationStored(estProfile);
        }

        @Test
        void keepsEdit_whenRequestReadNothingBeforeTheActivation() throws Exception {
            // given
            EstProfile estProfile = saveEstProfile();
            Callable<RaProfileEstDetailResponseDto> activation = createSlowActivation(estProfile);

            // when
            inARequest(request -> {
                whileTheConnectorIsCalled(this::editRaProfile, activation);
                runTheRequestsNextTransaction();
                return null;
            });

            // then
            assertEditAndActivationStored(estProfile);
        }

        /**
         * The write reads the RA Profile under its row lock, so a move to another authority still in progress when the
         * write began is waited for, and the activation is refused as for an RA Profile not under the authority.
         */
        @Test
        void throwsNotFound_whenMoveIsInProgressWhenTheActivationIsWritten() {
            // given
            RequestAttribute issueAttribute = createIssueAttribute(stubConnector(0));
            EstProfile estProfile = saveEstProfile();
            UUID otherAuthority = createAnotherAuthorityOfTheConnector().getUuid();
            Callable<RaProfileEstDetailResponseDto> activation = () -> activateEst(raProfile, estProfile,
                    issueAttribute);

            // when
            ThrowingCallable activateWhileAMoveHoldsTheRaProfile = () -> whileAMoveHoldsTheRaProfile(otherAuthority,
                    activation);

            // then
            assertThatThrownBy(activateWhileAMoveHoldsTheRaProfile)
                    .isInstanceOf(NotFoundException.class)
                    .hasMessageContaining(getNotFoundMessage(raProfile))
                    .hasMessageNotContaining(otherAuthority.toString());
            assertNothingActivatedOn(raProfile);
            assertThat(countProtocolAttributeRows(raProfile)).isZero();
        }

        /**
         * An RA Profile edit reads the RA Profile before it asks the connector to validate the edit, so an EST
         * activation can commit while it waits. The edit writes only what it changed, which keeps the activation.
         */
        @Test
        void keepsActivation_whenRaProfileEditReadTheRaProfileBeforeEstWasActivated() throws Exception {
            // given
            UUID attributeUuid = stubConnector(0);
            RequestAttribute issueAttribute = createIssueAttribute(attributeUuid);
            EstProfile estProfile = saveEstProfile();
            stubTheRaProfileEdit(1000);
            Runnable estActivation = asCaller(() -> activateEst(raProfile, estProfile, issueAttribute));
            EditRaProfileRequestDto request = createEditRequest();
            Callable<RaProfileDto> edit = () -> raProfileService
                    .editRaProfile(getAuthorityUuid(), raProfile.getSecuredUuid(), request);

            // when
            whileTheConnectorIsCalled(RA_PROFILE_ATTRIBUTES + "/validate", estActivation, edit);

            // then
            assertEditAndActivationStored(estProfile);
            assertThat(loadIssueAttributes(raProfile)).contains(attributeUuid.toString());
        }

        /**
         * The EST Profile checked before the connector call can be gone when it has answered. The writes then fail, and
         * because one transaction holds them all, the ones that came before the failing one are rolled back with it.
         */
        @Test
        void rollsBackTheActivation_whenEstProfileIsDeletedWhileTheConnectorIsCalled() {
            // given
            EstProfile estProfile = saveEstProfile();
            Callable<RaProfileEstDetailResponseDto> activation = createSlowActivation(estProfile);
            Runnable deletion = () -> deleteRow("est_profile", estProfile.getUuid());

            // when
            ThrowingCallable activateWhileTheEstProfileIsDeleted = () -> whileTheConnectorIsCalled(deletion,
                    activation);

            // then
            assertThatThrownBy(activateWhileTheEstProfileIsDeleted).isInstanceOf(DataAccessException.class);
            assertNothingActivatedOn(raProfile);
            assertThat(countProtocolAttributeRows(raProfile)).isZero();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /** An activation whose connector answers late, which leaves time to act while it waits for the answer. */
        private Callable<RaProfileEstDetailResponseDto> createSlowActivation(EstProfile estProfile) {
            RequestAttribute issueAttribute = createIssueAttribute(stubConnector(1000));
            return () -> activateEst(raProfile, estProfile, issueAttribute);
        }

        private void editRaProfile() {
            jdbcTemplate
                    .update("UPDATE " + dbSchema + ".ra_profile SET description = '" + EDITED_MEANWHILE
                            + "' WHERE uuid = ?", raProfile.getUuid());
        }

        private void deleteRow(String table, UUID uuid) {
            jdbcTemplate.update("DELETE FROM " + dbSchema + "." + table + " WHERE uuid = ?", uuid);
        }

        private void assertEditAndActivationStored(EstProfile estProfile) {
            RaProfile stored = raProfileRepository.findById(raProfile.getUuid()).orElseThrow();
            assertThat(stored.getEstProfileUuid()).isEqualTo(estProfile.getUuid());
            assertThat(stored.getDescription()).isEqualTo(EDITED_MEANWHILE);
        }

        /**
         * Stubs what an RA Profile edit asks the connector, its RA Profile attributes and their validation and the CA
         * chain, and answers the validation after the delay.
         */
        private static void stubTheRaProfileEdit(int validationDelayMillis) {
            connectorServer
                    .stubFor(WireMock
                            .get(WireMock.urlPathMatching(RA_PROFILE_ATTRIBUTES))
                            .willReturn(WireMock.okJson("[]")));
            connectorServer
                    .stubFor(WireMock
                            .post(WireMock.urlPathMatching(RA_PROFILE_ATTRIBUTES + "/validate"))
                            .willReturn(WireMock.okJson("true").withFixedDelay(validationDelayMillis)));
            connectorServer
                    .stubFor(WireMock
                            .post(WireMock.urlPathMatching("/v1/authorityProvider/authorities/[^/]+/caCertificates"))
                            .willReturn(WireMock.okJson("{\"certificates\": []}")));
        }

        /**
         * An edit of the RA Profile through the service that puts it under the authority, run as the caller of this
         * thread.
         */
        private Runnable createMoveOfTheRaProfileTo(AuthorityInstanceReference target) {
            EditRaProfileRequestDto request = createEditRequest();
            SecuredParentUUID targetUuid = target.getSecuredParentUuid();
            SecuredUUID raProfileUuid = raProfile.getSecuredUuid();
            return asCaller(() -> raProfileService.editRaProfile(targetUuid, raProfileUuid, request));
        }

        private static EditRaProfileRequestDto createEditRequest() {
            EditRaProfileRequestDto request = new EditRaProfileRequestDto();
            request.setDescription(EDITED_MEANWHILE);
            request.setAttributes(List.of());
            return request;
        }

        /** The call, to be run on another thread as the caller of this one. */
        private static Runnable asCaller(Callable<?> call) {
            SecurityContext caller = SecurityContextHolder.getContext();
            return () -> {
                SecurityContextHolder.setContext(caller);
                try {
                    call.call();
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                } finally {
                    SecurityContextHolder.clearContext();
                }
            };
        }

        /**
         * Runs the call on this thread while another thread waits for the connector's request to arrive and then does
         * something that changes the database. The connector answers the request late, so the change is made while the
         * call is waiting for it. A call that fails ends the wait, so its failure is the one reported.
         */
        private static <T> T whileTheConnectorIsCalled(Runnable meanwhile, Callable<T> call) throws Exception {
            return whileTheConnectorIsCalled(ISSUE_ATTRIBUTES + "/validate", meanwhile, call);
        }

        /** The same, for the call's request to the given path of the connector. */
        private static <T> T whileTheConnectorIsCalled(String path, Runnable meanwhile, Callable<T> call)
                throws Exception {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> change = executor.submit(() -> {
                    awaitTheConnectorRequest(path);
                    meanwhile.run();
                });
                T result = call.call();
                change.get(30, TimeUnit.SECONDS);
                return result;
            } finally {
                executor.shutdownNow();
            }
        }

        private static void awaitTheConnectorRequest(String path) {
            Awaitility
                    .await()
                    .pollInterval(Duration.ofMillis(10))
                    .atMost(Duration.ofSeconds(10))
                    .until(() -> !connectorServer
                            .findAll(WireMock.postRequestedFor(WireMock.urlPathMatching(path)))
                            .isEmpty());
        }

        /**
         * A transaction keeps the lock of every table it has read or written until it ends, also while it waits idle,
         * which the last statement it ran would not tell: that may have been on any table.
         */
        private long countSessionsInTransactionOnTheActivationsTables() {
            return jdbcTemplate.queryForObject("""
                    SELECT count(DISTINCT a.pid)
                      FROM pg_stat_activity a
                      JOIN pg_locks l ON l.pid = a.pid AND l.granted AND l.locktype = 'relation'
                     WHERE a.datname = current_database()
                       AND a.state = 'idle in transaction'
                       AND l.relation IN (to_regclass(?), to_regclass(?))
                    """, Long.class, dbSchema + ".ra_profile", dbSchema + ".est_profile");
        }

        /** Runs on the request's own persistence context again, and so writes back what that context still holds. */
        private void runTheRequestsNextTransaction() {
            transactionTemplate
                    .executeWithoutResult(status -> raProfileRepository.findByUuid(raProfile.getSecuredUuid()));
        }

        /**
         * Runs the call with one EntityManager bound to the thread and no transaction around it, as a request that is
         * not inside a transactional method does, so the call's reads answer from that persistence context. A change
         * committed through JDBC is one the context cannot learn of, as a request on another node commits it.
         */
        private <T> T inARequest(RequestCall<T> call) throws Exception {
            EntityManager bound = entityManagerFactory.createEntityManager();
            TransactionSynchronizationManager.bindResource(entityManagerFactory, new EntityManagerHolder(bound));
            try {
                return call.run(bound);
            } finally {
                TransactionSynchronizationManager.unbindResource(entityManagerFactory);
                bound.close();
            }
        }

        @FunctionalInterface
        private interface RequestCall<T> {

            T run(EntityManager request) throws Exception;
        }
    }

    // ── DeactivateEst ─────────────────────────────────────────────────────────

    @Nested
    class DeactivateEst {

        @Test
        void throwsNotFound_whenRaProfileIsUnderAnotherAuthority() throws Exception {
            // given
            stubConnector(0);
            EstProfile estProfile = saveEstProfile();
            activateEst(raProfile, estProfile);
            UUID authorityOfRaProfile = authority.authority().getUuid();
            SecuredParentUUID otherAuthority = createOtherAuthority();
            SecuredUUID raProfileUuid = raProfile.getSecuredUuid();

            // when
            ThrowingCallable deactivateThroughAnotherAuthority = () -> raProfileService
                    .deactivateEstForRaProfile(otherAuthority, raProfileUuid);

            // then
            assertThatThrownBy(deactivateThroughAnotherAuthority)
                    .isInstanceOf(NotFoundException.class)
                    .hasMessageContaining(getNotFoundMessage(raProfile))
                    .hasMessageNotContaining(authorityOfRaProfile.toString());
            assertThat(loadEstProfileUuid(raProfile)).isEqualTo(estProfile.getUuid());
            assertThat(loadIssueAttributes(raProfile)).isEqualTo("[]");
        }

        @Test
        void clearsActivation_whenDeactivated() throws Exception {
            // given
            UUID attributeUuid = stubConnector(0);
            activateEst(raProfile, saveEstProfile(), createIssueAttribute(attributeUuid));
            assertThat(loadIssueAttributes(raProfile)).isNotNull();

            // when
            deactivateEst(raProfile);

            // then
            assertThat(loadEstProfileUuid(raProfile)).isNull();
            assertThat(loadIssueAttributes(raProfile)).isNull();
            assertThat(readEst(raProfile).isEstAvailable()).isFalse();
        }

        @Test
        void keepsOtherProtocolsActivated_whenEstIsDeactivated() throws Exception {
            // given
            stubConnector(0);
            activateScepOn(raProfile);
            activateEst(raProfile, saveEstProfile());

            // when
            deactivateEst(raProfile);

            // then
            assertThat(loadEnabledProtocols(raProfile)).describedAs("the other protocol stays").containsExactly("SCEP");
        }

        /**
         * Deactivation reads the RA Profile under its row lock, so a move to another authority still in progress is
         * waited for, and the deactivation is refused as for an RA Profile not under the authority.
         */
        @Test
        void throwsNotFound_whenMoveIsInProgressWhenEstIsDeactivated() throws Exception {
            // given
            stubConnector(0);
            EstProfile estProfile = saveEstProfile();
            activateEst(raProfile, estProfile);
            UUID otherAuthority = createAnotherAuthorityOfTheConnector().getUuid();
            Callable<Void> deactivation = () -> {
                deactivateEst(raProfile);
                return null;
            };

            // when
            ThrowingCallable deactivateWhileAMoveHoldsTheRaProfile = () -> whileAMoveHoldsTheRaProfile(otherAuthority,
                    deactivation);

            // then
            assertThatThrownBy(deactivateWhileAMoveHoldsTheRaProfile)
                    .isInstanceOf(NotFoundException.class)
                    .hasMessageContaining(getNotFoundMessage(raProfile))
                    .hasMessageNotContaining(otherAuthority.toString());
            assertThat(loadEstProfileUuid(raProfile)).isEqualTo(estProfile.getUuid());
        }

        @Test
        void changesNothing_whenRaProfileNeverHadEstActivated() throws Exception {
            // given — an RA Profile that never had EST activated

            // when
            deactivateEst(raProfile);

            // then
            assertNothingActivatedOn(raProfile);
        }

        @Test
        void throwsNotFound_whenRaProfileDoesNotExist() {
            // given
            RaProfile unknown = createUnknownRaProfile();

            // when
            ThrowingCallable deactivateUnknownRaProfile = () -> deactivateEst(unknown);

            // then
            assertThatThrownBy(deactivateUnknownRaProfile).isInstanceOf(NotFoundException.class);
        }

        @Test
        void throwsAccessDenied_whenUpdateOfRaProfileIsDenied() throws Exception {
            // given
            UUID attributeUuid = stubConnector(0);
            EstProfile estProfile = saveEstProfile();
            activateEst(raProfile, estProfile, createIssueAttribute(attributeUuid));
            // forget the activation's connector calls, so only the deactivation's are checked
            connectorServer.resetRequests();
            denyResourceAccess(Resource.RA_PROFILE, ResourceAction.UPDATE);

            // when
            ThrowingCallable deactivateWithoutUpdatePermission = () -> deactivateEst(raProfile);

            // then
            assertThatThrownBy(deactivateWithoutUpdatePermission).isInstanceOf(AccessDeniedException.class);
            assertThat(loadEstProfileUuid(raProfile)).isEqualTo(estProfile.getUuid());
            assertThat(loadIssueAttributes(raProfile)).contains(attributeUuid.toString());
            assertConnectorNeverCalled();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void deactivateEst(RaProfile target) throws Exception {
            raProfileService.deactivateEstForRaProfile(getAuthorityUuid(), target.getSecuredUuid());
        }

        private void activateScepOn(RaProfile target) {
            UUID scepProfileUuid = createScepProfile("scep-devices");
            jdbcTemplate
                    .update("UPDATE " + dbSchema + ".ra_profile SET scep_profile_uuid = ? WHERE uuid = ?",
                            scepProfileUuid, target.getUuid());
        }

        private UUID createScepProfile(String name) {
            ScepProfile scepProfile = new ScepProfile();
            scepProfile.setName(name);
            return scepProfileRepository.save(scepProfile).getUuid();
        }
    }

    // ── ReadEst ───────────────────────────────────────────────────────────────

    @Nested
    class ReadEst {

        @Test
        void returnsActivatedDetail_whenEstIsActivated() throws Exception {
            // given
            UUID attributeUuid = stubConnector(0);
            RaProfileEstDetailResponseDto activated = activateEst(raProfile, saveEstProfile(),
                    createIssueAttribute(attributeUuid));

            // when
            RaProfileEstDetailResponseDto read = readEst(raProfile);

            // then
            assertThat(read).describedAs("a read returns what the activation returned").isEqualTo(activated);
        }

        /**
         * The caller is authorized on the authority the URL names, so an RA Profile under another authority is not
         * found under it, in the words used for an RA Profile that does not exist.
         */
        @Test
        void throwsNotFound_whenRaProfileIsUnderAnotherAuthority() {
            // given
            UUID authorityOfRaProfile = authority.authority().getUuid();
            SecuredParentUUID otherAuthority = createOtherAuthority();
            SecuredUUID raProfileUuid = raProfile.getSecuredUuid();

            // when
            ThrowingCallable readThroughAnotherAuthority = () -> raProfileService
                    .getEstForRaProfile(otherAuthority, raProfileUuid, ORIGIN);

            // then
            assertThatThrownBy(readThroughAnotherAuthority)
                    .isInstanceOf(NotFoundException.class)
                    .hasMessageContaining(getNotFoundMessage(raProfile))
                    .hasMessageNotContaining(authorityOfRaProfile.toString());
        }

        @Test
        void reportsUnavailable_whenEstIsNotActivated() throws Exception {
            // given — an RA Profile that never had EST activated

            // when
            RaProfileEstDetailResponseDto detail = readEst(raProfile);

            // then
            assertThat(detail.isEstAvailable()).isFalse();
            assertThat(detail.getUuid()).isNull();
            assertThat(detail.getName()).isNull();
            assertThat(detail.getLabel()).isNull();
            assertThat(detail.getEstUrl()).isNull();
            assertThat(detail.getIssueCertificateAttributes()).isNull();
        }

        @Test
        void throwsNotFound_whenRaProfileDoesNotExist() {
            // given
            RaProfile unknown = createUnknownRaProfile();

            // when
            ThrowingCallable readUnknownRaProfile = () -> readEst(unknown);

            // then
            assertThatThrownBy(readUnknownRaProfile).isInstanceOf(NotFoundException.class);
        }

        @Test
        void returnsDetail_whenOnlyUpdateOfRaProfileIsDenied() throws Exception {
            // given
            denyResourceAccess(Resource.RA_PROFILE, ResourceAction.UPDATE);

            // when
            RaProfileEstDetailResponseDto detail = readEst(raProfile);

            // then
            assertThat(detail).isNotNull();
        }

        @Test
        void throwsAccessDenied_whenDetailOfRaProfileIsDenied() {
            // given
            denyResourceAccess(Resource.RA_PROFILE, ResourceAction.DETAIL);

            // when
            ThrowingCallable readWithoutDetailPermission = () -> readEst(raProfile);

            // then
            assertThatThrownBy(readWithoutDetailPermission).isInstanceOf(AccessDeniedException.class);
        }
    }

    // ── DeleteRaProfile ───────────────────────────────────────────────────────

    @Nested
    class DeleteRaProfile {

        @Test
        void throwsValidation_whenRaProfileIsTheDefaultOfAnEstProfile() {
            // given
            EstProfile estProfile = estProfileRepository.save(anEstProfile().withRaProfile(raProfile).build());

            // when
            ThrowingCallable deleteDefaultRaProfile = () -> deleteRaProfile(raProfile);

            // then
            assertThatThrownBy(deleteDefaultRaProfile)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Cannot remove as RA Profile is the default of EST Profiles (1)")
                    .hasMessageNotContaining(estProfile.getName());
            assertThat(raProfileRepository.existsById(raProfile.getUuid())).isTrue();
            assertThat(estProfileRepository.findById(estProfile.getUuid()).orElseThrow().getRaProfileUuid())
                    .isEqualTo(raProfile.getUuid());
        }

        @Test
        void throwsValidationCountingEveryEstProfile_whenSeveralUseTheRaProfile() {
            // given
            var firstName = "est-a";
            var secondName = "est-b";
            estProfileRepository.save(anEstProfile().withName(firstName).withRaProfile(raProfile).build());
            estProfileRepository.save(anEstProfile().withName(secondName).withRaProfile(raProfile).build());
            SecuredUUID raProfileUuid = raProfile.getSecuredUuid();

            // when
            ThrowingCallable deleteRaProfileUsedByTwo = () -> raProfileService.deleteRaProfile(raProfileUuid);

            // then
            assertThatThrownBy(deleteRaProfileUsedByTwo)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Cannot remove as RA Profile is the default of EST Profiles (2)")
                    .hasMessageNotContaining(firstName)
                    .hasMessageNotContaining(secondName);
        }

        /**
         * The delete runs in one transaction, which a bulk delete shares with the items before it, so nothing is asked
         * of the authorization service about EST Profiles while it holds their locks.
         */
        @Test
        void asksTheAuthorizationServiceNothingAboutEstProfiles_whenRefusingToDelete() {
            // given
            estProfileRepository.save(anEstProfile().withRaProfile(raProfile).build());

            // when
            ThrowingCallable deleteDefaultRaProfile = () -> deleteRaProfile(raProfile);

            // then
            assertThatThrownBy(deleteDefaultRaProfile).isInstanceOf(ValidationException.class);
            verify(opaClient, never())
                    .checkResourceAccess(any(), argThat(asksAbout(Resource.EST_PROFILE)), any(), any());
            verify(opaClient, never()).checkObjectAccess(any(), argThat(asksAbout(Resource.EST_PROFILE)), any(), any());
        }

        @Test
        void deletesUnusedRaProfile_whenCallerMayNotListEstProfiles() throws Exception {
            // given
            RaProfile unused = saveRaProfileWithoutAuthority("unused-ra");
            estProfileRepository.save(anEstProfile().withName("est-a").withRaProfile(raProfile).build());
            estProfileRepository.save(anEstProfile().withName("est-b").withRaProfile(raProfile).build());
            denyResourceAccess(Resource.EST_PROFILE, ResourceAction.LIST);

            // when
            raProfileService.deleteRaProfile(unused.getSecuredUuid());

            // then
            assertThat(raProfileRepository.existsById(unused.getUuid())).isFalse();
        }

        @Test
        void throwsValidationWithCountOnly_whenCallerMayNotListEstProfiles() {
            // given
            var firstName = "est-a";
            var secondName = "est-b";
            estProfileRepository.save(anEstProfile().withName(firstName).withRaProfile(raProfile).build());
            estProfileRepository.save(anEstProfile().withName(secondName).withRaProfile(raProfile).build());
            denyResourceAccess(Resource.EST_PROFILE, ResourceAction.LIST);

            // when
            ThrowingCallable deleteDefaultRaProfile = () -> deleteRaProfile(raProfile);

            // then
            assertThatThrownBy(deleteDefaultRaProfile)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Cannot remove as RA Profile is the default of EST Profiles (2)")
                    .hasMessageNotContaining(firstName)
                    .hasMessageNotContaining(secondName);
            assertThat(raProfileRepository.existsById(raProfile.getUuid())).isTrue();
        }

        @Test
        void deletesRaProfile_whenItIsNoLongerTheDefaultOfAnEstProfile() throws Exception {
            // given
            EstProfile estProfile = estProfileRepository.save(anEstProfile().withRaProfile(raProfile).build());
            ThrowingCallable deleteWhileDefault = () -> deleteRaProfile(raProfile);
            assertThatThrownBy(deleteWhileDefault).isInstanceOf(ValidationException.class);
            estProfileService.updateRaProfile(estProfile.getSecuredUuid(), null);

            // when
            deleteRaProfile(raProfile);

            // then
            assertThat(raProfileRepository.existsById(raProfile.getUuid())).isFalse();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void deleteRaProfile(RaProfile target) throws Exception {
            raProfileService.deleteRaProfile(getAuthorityUuid(), target.getSecuredUuid());
        }

        private static ArgumentMatcher<OpaRequestedResource> asksAbout(Resource resource) {
            return request -> request != null && request.getProperties() != null
                    && resource.getCode().equals(request.getProperties().get("name"));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private RaProfileEstDetailResponseDto activateEst(RaProfile target, EstProfile estProfile,
            RequestAttribute... issueAttributes) throws Exception {
        ActivateEstForRaProfileRequestDto request = new ActivateEstForRaProfileRequestDto();
        request.setIssueCertificateAttributes(List.of(issueAttributes));
        return raProfileService
                .activateEstForRaProfile(getAuthorityUuid(), target.getSecuredUuid(), estProfile.getUuid(), request,
                        ORIGIN);
    }

    private RaProfileEstDetailResponseDto readEst(RaProfile target) throws Exception {
        return raProfileService.getEstForRaProfile(getAuthorityUuid(), target.getSecuredUuid(), ORIGIN);
    }

    private EstProfile saveEstProfile() {
        return estProfileRepository.save(anEstProfile().build());
    }

    private EstProfile saveEstProfile(String name) {
        return estProfileRepository.save(anEstProfile().withName(name).build());
    }

    private RaProfile renameRaProfile(RaProfile target, String name) {
        target.setName(name);
        return raProfileRepository.save(target);
    }

    private RaProfile saveRaProfileWithoutAuthority(String name) {
        RaProfile bare = new RaProfile();
        bare.setName(name);
        bare.setEnabled(true);
        return raProfileRepository.save(bare);
    }

    private static RaProfile createUnknownRaProfile() {
        RaProfile unknown = new RaProfile();
        unknown.setUuid(UUID.randomUUID());
        return unknown;
    }

    /** Another authority of the fixture's connector, which the connector's stubs answer for alike. */
    private AuthorityInstanceReference createAnotherAuthorityOfTheConnector() {
        AuthorityInstanceReference other = new AuthorityInstanceReference();
        other.setAuthorityInstanceUuid(UUID.randomUUID().toString());
        other.setName("other-authority");
        other.setStatus("connected");
        other.setKind("MOCK");
        other.setConnector(authority.connector());
        other.setConnectorName(authority.connector().getName());
        return authorityInstanceReferenceRepository.save(other);
    }

    private SecuredParentUUID getAuthorityUuid() {
        return authority.authority().getSecuredParentUuid();
    }

    private SecuredParentUUID createOtherAuthority() {
        return AuthorityFixtures.v2Authority(collectAuthorityRepos(), "OTHER").authority().getSecuredParentUuid();
    }

    private AuthorityFixtures.Repos collectAuthorityRepos() {
        return new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                connector2FunctionGroupRepository, authorityInstanceReferenceRepository, raProfileRepository,
                connectorInterfaceRepository);
    }

    /** Stubs the connector's issue attribute schema and validation, and answers the validation after the delay. */
    private static UUID stubConnector(int validationDelayMillis) {
        UUID attributeUuid = UUID.randomUUID();
        connectorServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(ISSUE_ATTRIBUTES + "/validate"))
                        .willReturn(WireMock.okJson("true").withFixedDelay(validationDelayMillis)));
        connectorServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching(ISSUE_ATTRIBUTES))
                        .willReturn(WireMock
                                .okJson(AttributeDefinitionUtils
                                        .serialize(List.of(createIssueAttributeDefinition(attributeUuid))))));
        return attributeUuid;
    }

    private static DataAttributeV2 createIssueAttributeDefinition(UUID uuid) {
        DataAttributeV2 definition = new DataAttributeV2();
        definition.setUuid(uuid.toString());
        definition.setName("profileName");
        definition.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("Profile name");
        definition.setProperties(properties);
        return definition;
    }

    private static RequestAttributeV2 createIssueAttribute(UUID uuid) {
        return createIssueAttribute(uuid, "devices");
    }

    private static RequestAttributeV2 createIssueAttribute(UUID uuid, String content) {
        return new RequestAttributeV2(uuid, "profileName", AttributeContentType.STRING,
                List.of(new StringAttributeContentV2(content)), AttributeVersion.V2);
    }

    /**
     * Runs the call on this thread while a transaction of another thread holds an uncommitted move of the RA Profile to
     * the authority, which it commits once a statement of the call waits for it.
     */
    private <T> T whileAMoveHoldsTheRaProfile(UUID authorityUuid, Callable<T> call) throws Exception {
        CountDownLatch moveHeld = new CountDownLatch(1);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<?> move = executor.submit(() -> transactionTemplate.executeWithoutResult(status -> {
                entityManager
                        .createNativeQuery("UPDATE " + dbSchema + ".ra_profile SET authority_instance_ref_uuid = "
                                + ":authority WHERE uuid = :uuid")
                        .setParameter("authority", authorityUuid)
                        .setParameter("uuid", raProfile.getUuid())
                        .executeUpdate();
                moveHeld.countDown();
                awaitAStatementOnTheRaProfileBlockedBy(loadTransactionBackendPid());
            }));
            assertThat(moveHeld.await(10, TimeUnit.SECONDS)).isTrue();
            T result = call.call();
            move.get(30, TimeUnit.SECONDS);
            return result;
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * The database backend of the transaction this runs in, asked through the entity manager, which joins that
     * transaction.
     */
    private int loadTransactionBackendPid() {
        return ((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult()).intValue();
    }

    /**
     * Waits until a statement on ra_profile is blocked by the given backend, so neither a waiting transaction of
     * another test nor one of a background job can end the wait.
     */
    private void awaitAStatementOnTheRaProfileBlockedBy(int lockHolderPid) {
        Awaitility.await().atMost(Duration.ofSeconds(10)).until(() -> jdbcTemplate.queryForObject("""
                SELECT count(*) FROM pg_stat_activity
                 WHERE ? = ANY(pg_blocking_pids(pid)) AND query ILIKE '%ra_profile%'
                """, Long.class, lockHolderPid) >= 1);
    }

    private UUID loadEstProfileUuid(RaProfile target) {
        return raProfileRepository.findById(target.getUuid()).orElseThrow().getEstProfileUuid();
    }

    /** The stored issue attributes, or null when the column is null; the profile must have a protocol attribute row. */
    private String loadIssueAttributes(RaProfile target) {
        return jdbcTemplate
                .queryForObject(
                        "SELECT est_issue_certificate_attributes FROM " + dbSchema
                                + ".ra_profile_protocol_attribute WHERE ra_profile_uuid = ?",
                        String.class, target.getUuid());
    }

    private int countProtocolAttributeRows(RaProfile target) {
        return jdbcTemplate
                .queryForObject(
                        "SELECT count(*) FROM " + dbSchema + ".ra_profile_protocol_attribute WHERE ra_profile_uuid = ?",
                        Integer.class, target.getUuid());
    }

    private List<String> loadEnabledProtocols(RaProfile target) {
        return raProfileService
                .listRaProfiles(SecurityFilter.create(), Optional.empty())
                .stream()
                .filter(dto -> dto.getUuid().equals(target.getUuid().toString()))
                .findFirst()
                .map(RaProfileDto::getEnabledProtocols)
                .orElseThrow();
    }

    private void assertNothingActivatedOn(RaProfile target) {
        assertThat(loadEstProfileUuid(target)).isNull();
        assertThat(jdbcTemplate
                .queryForObject(
                        "SELECT count(*) FROM " + dbSchema + ".ra_profile_protocol_attribute "
                                + "WHERE ra_profile_uuid = ? AND est_issue_certificate_attributes IS NOT NULL",
                        Integer.class, target.getUuid()))
                .isZero();
    }

    private static void assertConnectorNeverCalled() {
        connectorServer.verify(0, WireMock.anyRequestedFor(WireMock.anyUrl()));
    }

    /** What the caller is told of an RA Profile that does not exist. */
    private static String getNotFoundMessage(RaProfile target) {
        return new NotFoundException(RaProfile.class, target.getUuid()).getMessage();
    }
}
