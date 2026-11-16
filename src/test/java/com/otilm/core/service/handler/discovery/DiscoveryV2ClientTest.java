package com.otilm.core.service.handler.discovery;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ConnectorClientException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v2.DiscoverySyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSecretContentData;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDrainRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStatusResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStopResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryV2ScopedRequestDto;
import com.otilm.api.model.connector.secrets.content.ApiKeySecretContent;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.util.DiscoveryCheckpointFixture;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * What Core puts on the wire for a v2 connector call.
 *
 * <p>
 * A discovery v2 connector keeps no Core-visible state, so every call replays the run's identity, the connector's own
 * handle and the run's whole attribute configuration. Getting any of that wrong addresses the wrong run or sends a
 * request the connector rejects on every attempt, which is why it is worth pinning rather than trusting.
 */
@ExtendWith(MockitoExtension.class)
class DiscoveryV2ClientTest {

    @Mock
    private ConnectorApiFactory connectorApiFactory;
    @Mock
    private ConnectorRepository connectorRepository;
    @Mock
    private AttributeEngine attributeEngine;
    @Mock
    private OperationAttributeResolver operationAttributeResolver;
    @Mock
    private DiscoverySyncApiClient apiClient;

    private static final String OFFERED_MODES = "checkpointed,buffered";
    private static final String BUFFERED_ONLY = "buffered";

    private DiscoveryV2Client client;
    private Discovery run;

    @BeforeEach
    void createClientAndRun() {
        client = clientOffering(OFFERED_MODES);

        run = new Discovery();
        run.setUuid(UUID.randomUUID());
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorUuid(UUID.randomUUID());
        run.setLastAppliedSequence(17L);
        run.setCheckpoint(DiscoveryCheckpointFixture.checkpoint("connectorRunId", "run-42"));

        Connector connector = new Connector();
        connector.setUuid(run.getConnectorUuid());
        connector.setName("network-discovery");
        connector.setUrl("https://connector.example.com");
        lenient().when(connectorRepository.findByUuid(run.getConnectorUuid())).thenReturn(Optional.of(connector));
        lenient().when(connectorApiFactory.getDiscoveryApiClientV2(any())).thenReturn(apiClient);
        lenient()
                .when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), any(), any(), any()))
                .thenReturn(List.<DataAttribute>of());
    }

    @Test
    void statusCall_replaysTheRunIdentityAndTheConnectorHandle() throws Exception {
        when(apiClient.status(any(), any())).thenReturn(new DiscoveryStatusResponseDto());

        client.status(run);

        ArgumentCaptor<DiscoveryRunRequestDto> sent = ArgumentCaptor.forClass(DiscoveryRunRequestDto.class);
        verify(apiClient).status(any(ConnectorDto.class), sent.capture());
        assertThat(sent.getValue().getRunId()).isEqualTo(run.getUuid());
        assertThat(sent.getValue().getCheckpoint())
                .as("the connector is stateless; without its own handle it cannot resolve the run")
                .isEqualTo(run.getCheckpoint());
    }

    @ParameterizedTest
    @ValueSource(strings = {"initiate", "status", "results", "stop", "resume", "cancel"})
    void offersTheConfiguredModes_whenSendingAnyCall(String operation) throws Exception {
        // given — the client offers checkpointed, then buffered

        // when
        DiscoveryV2ScopedRequestDto sent = sendAndCapture(operation);

        // then
        assertThat(sent.getDeliveryModes())
                .containsExactly(DiscoveryDeliveryMode.CHECKPOINTED, DiscoveryDeliveryMode.BUFFERED);
    }

    @Test
    void offersCheckpointed_whenACheckpointedRunDrainsWhileOnlyBufferedIsConfigured() throws Exception {
        // given
        client = clientOffering(BUFFERED_ONLY);
        run.setDeliveryMode(DiscoveryDeliveryMode.CHECKPOINTED);

        // when
        DiscoveryV2ScopedRequestDto sent = sendAndCapture("results");

        // then
        assertThat(sent.getDeliveryModes())
                .containsExactly(DiscoveryDeliveryMode.CHECKPOINTED, DiscoveryDeliveryMode.BUFFERED);
    }

    @Test
    void offersCheckpointed_whenACheckpointedRunIsAcknowledgedWhileOnlyBufferedIsConfigured() throws Exception {
        // given
        client = clientOffering(BUFFERED_ONLY);
        run.setDeliveryMode(DiscoveryDeliveryMode.CHECKPOINTED);
        when(apiClient.results(any(), any())).thenReturn(new DiscoveryResultsResponseDto());

        // when
        client.acknowledge(run, 42L);

        // then
        assertThat(capturedDrain().getDeliveryModes())
                .containsExactly(DiscoveryDeliveryMode.CHECKPOINTED, DiscoveryDeliveryMode.BUFFERED);
    }

    @ParameterizedTest
    @EnumSource(value = DiscoveryDeliveryMode.class, names = {"CHECKPOINTED", "BUFFERED"})
    void offersOnlyTheConfiguredModes_whenAResumeIsSentWhileOnlyBufferedIsConfigured(DiscoveryDeliveryMode recorded)
            throws Exception {
        // given
        client = clientOffering(BUFFERED_ONLY);
        run.setDeliveryMode(recorded);

        // when
        DiscoveryV2ScopedRequestDto sent = sendAndCapture("resume");

        // then
        assertThat(sent.getDeliveryModes()).containsExactly(DiscoveryDeliveryMode.BUFFERED);
    }

    @Test
    void offersOnlyTheConfiguredModes_whenABufferedRunDrainsWhileOnlyBufferedIsConfigured() throws Exception {
        // given
        client = clientOffering(BUFFERED_ONLY);
        run.setDeliveryMode(DiscoveryDeliveryMode.BUFFERED);

        // when
        DiscoveryV2ScopedRequestDto sent = sendAndCapture("results");

        // then
        assertThat(sent.getDeliveryModes()).containsExactly(DiscoveryDeliveryMode.BUFFERED);
    }

    @Test
    void aNonInitiateCall_stillCarriesTheRunsResourceSet() throws Exception {
        run.setResources(List.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY));
        when(apiClient.resume(any(), any())).thenReturn(new DiscoveryInitiateResponseDto());

        client.resume(run);

        ArgumentCaptor<DiscoveryRunRequestDto> sent = ArgumentCaptor.forClass(DiscoveryRunRequestDto.class);
        verify(apiClient).resume(any(ConnectorDto.class), sent.capture());
        assertThat(sent.getValue().getResources())
                .as("a connector rebuilding a resumed run after a restart cannot recover its scope from "
                        + "resourceAttributes, which omits any resource declaring no attributes of its own")
                .containsExactly(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY);
    }

    @Test
    void drainCall_asksForEverythingPastTheCursor() throws Exception {
        when(apiClient.results(any(), any())).thenReturn(new DiscoveryResultsResponseDto());

        client.results(run, 500, 5_242_880L);

        DiscoveryDrainRequestDto sent = capturedDrain();
        assertThat(sent.getAfterSequence()).as("anything at or below the cursor is already ingested").isEqualTo(17L);
        assertThat(sent.getMaxItems()).isEqualTo(500);
        assertThat(sent.getMaxBytes()).isEqualTo(5_242_880L);
    }

    @Test
    void configuredMaxBytesAboveTheContractCap_isClampedRatherThanSent() throws Exception {
        when(apiClient.results(any(), any())).thenReturn(new DiscoveryResultsResponseDto());

        client.results(run, 500, DiscoveryDrainRequestDto.MAX_BYTES_CAP * 4);

        // Unclamped, a misconfigured value produces a request the connector rejects on every single drain --
        // and over MQ that rejection arrives as an unchecked exception.
        assertThat(capturedDrain().getMaxBytes()).isEqualTo(DiscoveryDrainRequestDto.MAX_BYTES_CAP);
    }

    @Test
    void asksForTenMebibytesLessTheReserve_whenACheckpointedRunDrainsAtTheTransportCap() throws Exception {
        // given
        var tenMebibytes = 10_485_760L;
        run.setDeliveryMode(DiscoveryDeliveryMode.CHECKPOINTED);
        when(apiClient.results(any(), any())).thenReturn(new DiscoveryResultsResponseDto());

        // when
        client.results(run, 500, tenMebibytes);

        // then
        assertThat(capturedDrain().getMaxBytes()).isEqualTo(10_354_688L);
    }

    @Test
    void asksForTheConfiguredBytes_whenABufferedRunDrainsAtTheTransportCap() throws Exception {
        // given
        var tenMebibytes = 10_485_760L;
        run.setDeliveryMode(DiscoveryDeliveryMode.BUFFERED);
        when(apiClient.results(any(), any())).thenReturn(new DiscoveryResultsResponseDto());

        // when
        client.results(run, 500, tenMebibytes);

        // then
        assertThat(capturedDrain().getMaxBytes()).isEqualTo(tenMebibytes);
    }

    @Test
    void acknowledgement_positionsPastTheLastItemTheConnectorCounted() throws Exception {
        when(apiClient.results(any(), any())).thenReturn(new DiscoveryResultsResponseDto());

        client.acknowledge(run, 42L);

        DiscoveryDrainRequestDto sent = capturedDrain();
        assertThat(sent.getAfterSequence())
                .as("the ack is a drain at the run-wide high-water mark, not at Core's cursor")
                .isEqualTo(42L);
        assertThat(sent.getMaxItems()).as("the body is not the point; the cursor it carries is").isEqualTo(1);
    }

    @Test
    void perResourceAttributes_areCollectedForEachResourceTheRunTargets() throws Exception {
        run.setResources(List.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY));
        when(apiClient.status(any(), any())).thenReturn(new DiscoveryStatusResponseDto());

        client.status(run);

        // Run-level attributes are read with a null operation; each resource is read under its own wire code.
        verify(attributeEngine).getDefinitionObjectAttributeContent(any(), any(), isNull(), any(), any());
        verify(attributeEngine).getDefinitionObjectAttributeContent(any(), any(), eq("certificates"), any(), any());
        verify(attributeEngine).getDefinitionObjectAttributeContent(any(), any(), eq("keys"), any(), any());
    }

    @Test
    void aDefinitionTwoScopesShare_isResolvedOnceRatherThanPerScope() throws Exception {
        // given
        run.setResources(List.of(Resource.CERTIFICATE));
        // The same credential declared at run level and again on the resource: two definitions, one referent.
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), isNull(), any(), any()))
                .thenReturn(List.of(definition("credential", "reference-only", AttributeContentType.CREDENTIAL)));
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), eq("certificates"), any(), any()))
                .thenReturn(List.of(definition("credential", "reference-only", AttributeContentType.CREDENTIAL)));
        resolvingEachTo(new StringAttributeContentV3("s3cret"));
        when(apiClient.status(any(), any())).thenReturn(new DiscoveryStatusResponseDto());

        // when
        client.status(run);

        // then
        // For a SECRET reference a lookup is a connector round trip, so resolving once per scope would pay for
        // the same secret as many times as the run targets resources.
        ArgumentCaptor<List<RequestAttribute>> resolved = ArgumentCaptor.captor();
        verify(operationAttributeResolver).resolveWithNestedReferencesAsSystem(any(), resolved.capture());
        assertThat(resolved.getValue()).hasSize(1);
        assertThat(capturedStatus().getResourceAttributes().get(Resource.CERTIFICATE))
                .as("the scope that shared the definition still carries it")
                .singleElement()
                .extracting(RequestAttribute::getName)
                .isEqualTo("credential");
    }

    @Test
    void resolvedContent_reachesEveryScopeThatDeclaredTheDefinition() throws Exception {
        // given
        run.setResources(List.of(Resource.CERTIFICATE));
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), isNull(), any(), any()))
                .thenReturn(List.of(definition("credential", "reference-only", AttributeContentType.CREDENTIAL)));
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), eq("certificates"), any(), any()))
                .thenReturn(List.of(definition("credential", "reference-only", AttributeContentType.CREDENTIAL)));
        resolvingEachTo(new StringAttributeContentV3("s3cret"));
        when(apiClient.status(any(), any())).thenReturn(new DiscoveryStatusResponseDto());

        // when
        client.status(run);

        // then
        // Deduping must not cost the skipped scope its content: the connector needs the resolved value in both.
        DiscoveryRunRequestDto sent = capturedStatus();
        assertThat(firstData(sent.getAttributes().getFirst().getContent())).isEqualTo("s3cret");
        assertThat(firstData(sent.getResourceAttributes().get(Resource.CERTIFICATE).getFirst().getContent()))
                .isEqualTo("s3cret");
    }

    @Test
    void resolvesThroughTheResolverOfAuthorityOperations_whenTheRunReferencesAnObject() throws Exception {
        // given
        run.setResources(List.of(Resource.CERTIFICATE));
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), isNull(), any(), any()))
                .thenReturn(List.of(definition("authority", "reference-only", AttributeContentType.RESOURCE)));
        resolvingEachTo(new StringAttributeContentV3("resolved"));
        when(apiClient.status(any(), any())).thenReturn(new DiscoveryStatusResponseDto());

        // when
        client.status(run);

        // then
        verify(operationAttributeResolver).resolveWithNestedReferencesAsSystem(eq(run.getConnectorUuid()), anyList());
        assertThat(firstData(capturedStatus().getAttributes().getFirst().getContent())).isEqualTo("resolved");
    }

    @Test
    void failsRatherThanMisplacingContent_whenTheResolverAnswersForFewerAttributes() throws Exception {
        // given
        run.setResources(List.of(Resource.CERTIFICATE));
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), isNull(), any(), any()))
                .thenReturn(List.of(definition("authority", "reference-only", AttributeContentType.RESOURCE)));
        when(operationAttributeResolver.resolveWithNestedReferencesAsSystem(any(), anyList())).thenReturn(List.of());

        // when
        ThrowingCallable status = () -> client.status(run);

        // then
        assertThatThrownBy(status).isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(apiClient);
    }

    @Test
    void reportsAConnectorFailure_whenTheResolverRefusesAReferenceOnAStatusTick() throws Exception {
        // given
        run.setResources(List.of(Resource.CERTIFICATE));
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), isNull(), any(), any()))
                .thenReturn(List.of(definition("authority", "reference-only", AttributeContentType.RESOURCE)));
        ValidationException goneSecret = new ValidationException(
                "Attribute 'OAuth client' of Authority 'otpki' refers to Secret 'oauth', which does not exist.");
        when(operationAttributeResolver.resolveWithNestedReferencesAsSystem(any(), anyList())).thenThrow(goneSecret);

        // when
        ThrowingCallable status = () -> client.status(run);

        // then
        assertThatThrownBy(status)
                .isInstanceOf(ConnectorException.class)
                .isNotInstanceOf(ValidationException.class)
                .hasMessageContaining(goneSecret.getMessage())
                .hasCause(goneSecret);
        verifyNoInteractions(apiClient);
    }

    @Test
    void refusesTheStopNamingTheReference_whenTheResolverRefusesIt() throws Exception {
        // given
        run.setResources(List.of(Resource.CERTIFICATE));
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), isNull(), any(), any()))
                .thenReturn(List.of(definition("authority", "reference-only", AttributeContentType.RESOURCE)));
        ValidationException disabledSecret = new ValidationException("Secret 'oauth' is not enabled.");
        when(operationAttributeResolver.resolveWithNestedReferencesAsSystem(any(), anyList()))
                .thenThrow(disabledSecret);

        // when
        ThrowingCallable stop = () -> client.stop(run);

        // then
        assertThatThrownBy(stop).isSameAs(disabledSecret);
        verifyNoInteractions(apiClient);
    }

    @Test
    void skipsTheResolver_whenNothingIsReferenced() throws Exception {
        // given
        run.setResources(List.of(Resource.CERTIFICATE));
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), any(), any(), any()))
                .thenReturn(List.of(definition("host", "10.0.0.0/24", AttributeContentType.STRING)));
        when(apiClient.status(any(), any())).thenReturn(new DiscoveryStatusResponseDto());

        // when
        client.status(run);

        // then
        // Nothing to resolve, and this path runs on every tick for the whole life of the run — so it must not spend
        // the resolver's auth-service round trip proving that.
        verifyNoInteractions(operationAttributeResolver);
        assertThat(capturedStatus().getAttributes())
                .as("the definition still reaches the connector, just unresolved")
                .singleElement()
                .extracting(RequestAttribute::getName)
                .isEqualTo("host");
    }

    /**
     * Every request carries the run's resolved credentials and secrets, so the connector holds them legitimately; what
     * it must not do is hand them back in fields Core persists and serves. Refused as the connector call it was, so the
     * tick spends budget on it like any other bad answer, and nothing of the response is read first.
     */
    @Test
    void aResponseEchoingASecretResolvedForTheRun_isRefusedAsAConnectorFailure() throws Exception {
        // given
        run.setResources(List.of(Resource.CERTIFICATE));
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), isNull(), any(), any()))
                .thenReturn(List.of(definition("vaultToken", "reference-only", AttributeContentType.RESOURCE)));
        resolvingEachTo(new ResourceObjectContent("vault",
                new ResourceSecretContentData("u", "vault", new ApiKeySecretContent("s3cr3t-token"))));
        DiscoveryStatusResponseDto echo = new DiscoveryStatusResponseDto();
        echo.setMeta(DiscoveryCheckpointFixture.checkpoint("lastToken", "s3cr3t-token"));
        when(apiClient.status(any(), any())).thenReturn(echo);

        // when
        ThrowingCallable status = () -> client.status(run);

        // then
        assertThatThrownBy(status).isInstanceOf(ConnectorException.class).hasMessageNotContaining("s3cr3t-token");
    }

    @Test
    void anInitiateResponseEchoingASecret_isStillAcceptedSoTheOpenRunIsNotOrphaned() throws Exception {
        givenARunResolvingASecret();
        DiscoveryInitiateResponseDto echo = new DiscoveryInitiateResponseDto();
        echo.setCheckpoint(DiscoveryCheckpointFixture.checkpoint("lastToken", "s3cr3t-token"));
        when(apiClient.initiate(any(), any())).thenReturn(echo);

        // The connector has opened the run by now; refusing would leave it scanning with nothing in Core to
        // cancel it by.
        assertThat(client.initiate(run).getCheckpoint()).isEqualTo(echo.getCheckpoint());
    }

    /**
     * A refusal of the initiate reaches the API caller, who may not read the secrets the request carried, so the words
     * go and the verdict stays: still a 422 refusal of the configuration.
     */
    @Test
    void dropsTheConnectorsWordsButNotItsVerdict_whenAnInitiateRefusalAnswersARunCarryingASecret() throws Exception {
        // given
        givenARunResolvingASecret();
        when(apiClient.initiate(any(), any())).thenThrow(validationRefusal("token s3cr3t-token is not valid"));

        // when
        ThrowingCallable initiate = () -> client.initiate(run);

        // then
        assertThatThrownBy(initiate).isInstanceOfSatisfying(ConnectorProblemException.class, refused -> {
            assertThat(refused.getMessage()).isEqualTo("The connector refused the run (VALIDATION_FAILED).");
            assertThat(refused.getProblemDetail().getErrorCode()).isEqualTo(ErrorCode.VALIDATION_FAILED);
            assertThat(refused.getProblemDetail().getStatus()).isEqualTo(422);
        });
    }

    @Test
    void dropsTheConnectorsWords_whenAnInitiateRefusalCarryingNoSecretAnswersARunCarryingOne() throws Exception {
        // given
        givenARunResolvingASecret();
        String wordsWithoutTheSecret = "authority \"otpki-staging\" does not belong to this connector";
        when(apiClient.initiate(any(), any())).thenThrow(validationRefusal(wordsWithoutTheSecret));

        // when
        ThrowingCallable initiate = () -> client.initiate(run);

        // then
        assertThatThrownBy(initiate)
                .isInstanceOf(ConnectorProblemException.class)
                .hasMessage("The connector refused the run (VALIDATION_FAILED).");
    }

    @Test
    void dropsTheConnectorsWords_whenAPlainValidationRefusalAnswersARunCarryingASecret() throws Exception {
        // given
        givenARunResolvingASecret();
        when(apiClient.initiate(any(), any())).thenThrow(new ValidationException("token s3cr3t-token is not valid"));

        // when
        ThrowingCallable initiate = () -> client.initiate(run);

        // then
        assertThatThrownBy(initiate).isInstanceOf(ValidationException.class).hasMessageNotContaining("s3cr3t-token");
    }

    @Test
    void dropsTheConnectorsWords_whenAStopRefusalAnswersARunCarryingASecret() throws Exception {
        // given
        givenARunResolvingASecret();
        when(apiClient.stop(any(), any())).thenThrow(validationRefusal("token s3cr3t-token cannot be used"));

        // when
        ThrowingCallable stop = () -> client.stop(run);

        // then
        assertThatThrownBy(stop)
                .isInstanceOf(ConnectorProblemException.class)
                .hasMessage("The connector refused the run (VALIDATION_FAILED).");
    }

    @Test
    void dropsTheConnectorsWords_whenAPlainClientErrorRefusesAStopOfARunCarryingASecret() throws Exception {
        // given
        givenARunResolvingASecret();
        when(apiClient.stop(any(), any()))
                .thenThrow(new ConnectorClientException("token s3cr3t-token cannot be used", HttpStatus.BAD_REQUEST));

        // when
        ThrowingCallable stop = () -> client.stop(run);

        // then
        assertThatThrownBy(stop).isInstanceOfSatisfying(ConnectorClientException.class, refused -> {
            assertThat(refused.getMessage()).isEqualTo("The connector refused the run.");
            assertThat(refused.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
        });
    }

    @Test
    void dropsTheConnectorsWords_whenAResumeRefusalAnswersARunCarryingASecret() throws Exception {
        // given
        givenARunResolvingASecret();
        when(apiClient.resume(any(), any())).thenThrow(validationRefusal("token s3cr3t-token cannot be used"));

        // when
        ThrowingCallable resume = () -> client.resume(run);

        // then
        assertThatThrownBy(resume)
                .isInstanceOf(ConnectorProblemException.class)
                .hasMessage("The connector refused the run (VALIDATION_FAILED).");
    }

    @Test
    void dropsTheConnectorsWords_whenACancelRefusalAnswersARunCarryingASecret() throws Exception {
        // given
        givenARunResolvingASecret();
        when(apiClient.cancel(any(), any())).thenThrow(validationRefusal("token s3cr3t-token cannot be used"));

        // when
        ThrowingCallable cancel = () -> client.cancel(run);

        // then
        assertThatThrownBy(cancel)
                .isInstanceOf(ConnectorProblemException.class)
                .hasMessage("The connector refused the run (VALIDATION_FAILED).");
    }

    /** A status refusal goes to the tick worker's log, and the worker backs off by the hint it keeps. */
    @Test
    void keepsTheRetryHintButNotTheWords_whenAStatusRefusalAnswersARunCarryingASecret() throws Exception {
        // given
        givenARunResolvingASecret();
        int retryAfterSeconds = 45;
        ProblemDetailExtended busy = ProblemDetailExtended
                .fromErrorCode(ErrorCode.SERVICE_UNAVAILABLE, "token s3cr3t-token is rate limited", null, null);
        busy.setRetryAfterSeconds(retryAfterSeconds);
        when(apiClient.status(any(), any())).thenThrow(new ConnectorProblemException(busy));

        // when
        ThrowingCallable status = () -> client.status(run);

        // then
        assertThatThrownBy(status).isInstanceOfSatisfying(ConnectorProblemException.class, refused -> {
            assertThat(refused.getMessage()).doesNotContain("s3cr3t-token");
            assertThat(refused.getProblemDetail().getRetryAfterSeconds()).isEqualTo(retryAfterSeconds);
            assertThat(refused.getProblemDetail().getErrorCode()).isEqualTo(ErrorCode.SERVICE_UNAVAILABLE);
        });
    }

    /** Nothing secret went out, so the connector's words are the caller's best account of what to correct. */
    @Test
    void anInitiateRefusalForARunWithoutSecrets_keepsTheConnectorsWords() throws Exception {
        when(apiClient.initiate(any(), any()))
                .thenThrow(validationRefusal("data_hosts entry \"10.0.0.999\" is not valid"));

        assertThatThrownBy(() -> client.initiate(run))
                .isInstanceOf(ConnectorProblemException.class)
                .hasMessageContaining("10.0.0.999");
    }

    private static ConnectorProblemException validationRefusal(String detail) {
        return new ConnectorProblemException(ProblemDetailExtended
                .fromErrorCode(ErrorCode.VALIDATION_FAILED, detail,
                        URI.create("https://connector.example.com/v2/discoveryProvider/discoveries/initiate"), null));
    }

    @Test
    void aResumeResponseEchoingASecret_isStillAcceptedSoCoreDoesNotStayStopped() throws Exception {
        givenARunResolvingASecret();
        DiscoveryInitiateResponseDto echo = new DiscoveryInitiateResponseDto();
        echo.setCheckpoint(DiscoveryCheckpointFixture.checkpoint("lastToken", "s3cr3t-token"));
        when(apiClient.resume(any(), any())).thenReturn(echo);

        // The divergence that cannot repair itself: only an explicit resume moves Core out of STOPPED.
        assertThat(client.resume(run).getCheckpoint()).isEqualTo(echo.getCheckpoint());
    }

    /** A run whose attributes carry a resource reference Core expands into a real secret before the call. */
    private void givenARunResolvingASecret() throws Exception {
        run.setResources(List.of(Resource.CERTIFICATE));
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), isNull(), any(), any()))
                .thenReturn(List.of(definition("vaultToken", "reference-only", AttributeContentType.RESOURCE)));
        resolvingEachTo(new ResourceObjectContent("vault",
                new ResourceSecretContentData("u", "vault", new ApiKeySecretContent("s3cr3t-token"))));
    }

    @Test
    void missingConnectorRow_failsRatherThanCallingSomethingElse() {
        when(connectorRepository.findByUuid(run.getConnectorUuid())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> client.status(run)).isInstanceOf(NotFoundException.class);
    }

    private static DataAttribute definition(String name, String value, AttributeContentType contentType) {
        DataAttributeV3 attribute = new DataAttributeV3();
        attribute.setUuid("11111111-1111-1111-1111-111111111111");
        attribute.setName(name);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(contentType);
        attribute.setContent(List.of(new StringAttributeContentV3(value)));
        return attribute;
    }

    private static Object firstData(List<?> content) {
        return content.getFirst() instanceof StringAttributeContentV3 item ? item.getData() : null;
    }

    private DiscoveryRunRequestDto capturedStatus() throws Exception {
        ArgumentCaptor<DiscoveryRunRequestDto> sent = ArgumentCaptor.forClass(DiscoveryRunRequestDto.class);
        verify(apiClient).status(any(ConnectorDto.class), sent.capture());
        return sent.getValue();
    }

    private DiscoveryV2ScopedRequestDto sendAndCapture(String operation) throws Exception {
        ArgumentCaptor<DiscoveryRunRequestDto> runRequest = ArgumentCaptor.forClass(DiscoveryRunRequestDto.class);
        switch (operation) {
            case "initiate" -> {
                ArgumentCaptor<DiscoveryInitiateRequestDto> sent = ArgumentCaptor
                        .forClass(DiscoveryInitiateRequestDto.class);
                when(apiClient.initiate(any(), any())).thenReturn(new DiscoveryInitiateResponseDto());
                client.initiate(run);
                verify(apiClient).initiate(any(ConnectorDto.class), sent.capture());
                return sent.getValue();
            }
            case "results" -> {
                when(apiClient.results(any(), any())).thenReturn(new DiscoveryResultsResponseDto());
                client.results(run, 500, 5_242_880L);
                return capturedDrain();
            }
            case "status" -> {
                when(apiClient.status(any(), any())).thenReturn(new DiscoveryStatusResponseDto());
                client.status(run);
                verify(apiClient).status(any(ConnectorDto.class), runRequest.capture());
            }
            case "stop" -> {
                when(apiClient.stop(any(), any())).thenReturn(new DiscoveryStopResponseDto());
                client.stop(run);
                verify(apiClient).stop(any(ConnectorDto.class), runRequest.capture());
            }
            case "resume" -> {
                when(apiClient.resume(any(), any())).thenReturn(new DiscoveryInitiateResponseDto());
                client.resume(run);
                verify(apiClient).resume(any(ConnectorDto.class), runRequest.capture());
            }
            case "cancel" -> {
                client.cancel(run);
                verify(apiClient).cancel(any(ConnectorDto.class), runRequest.capture());
            }
            default -> throw new IllegalArgumentException("No such call: " + operation);
        }
        return runRequest.getValue();
    }

    private DiscoveryV2Client clientOffering(String modes) {
        return new DiscoveryV2Client(connectorApiFactory, connectorRepository, attributeEngine,
                operationAttributeResolver, new OutboundSecretContainment(new ObjectMapper().findAndRegisterModules()),
                new DiscoveryDeliveryModeOffer(modes));
    }

    /** Has the resolver answer every attribute it is given with the content given, as resolving a reference does. */
    private void resolvingEachTo(BaseAttributeContentV3<?> resolvedContent) throws Exception {
        when(operationAttributeResolver.resolveWithNestedReferencesAsSystem(any(), anyList()))
                .thenAnswer(invocation -> invocation
                        .<List<RequestAttribute>>getArgument(1)
                        .stream()
                        .<RequestAttribute>map(attribute -> {
                            List<BaseAttributeContentV3<?>> content = new ArrayList<>();
                            content.add(resolvedContent);
                            return new RequestAttributeV3(attribute.getUuid(), attribute.getName(),
                                    attribute.getContentType(), content);
                        })
                        .toList());
    }

    private DiscoveryDrainRequestDto capturedDrain() throws Exception {
        ArgumentCaptor<DiscoveryDrainRequestDto> sent = ArgumentCaptor.forClass(DiscoveryDrainRequestDto.class);
        verify(apiClient).results(any(ConnectorDto.class), sent.capture());
        return sent.getValue();
    }
}
