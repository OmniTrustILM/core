package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.client.v2.DiscoverySyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDrainRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStatusResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.ResourceInternalService;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.DiscoveryRunMetaFixture;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
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
    private CredentialInternalService credentialService;
    @Mock
    private ResourceInternalService resourceService;
    @Mock
    private AuthHelper authHelper;
    @Mock
    private DiscoverySyncApiClient apiClient;

    private DiscoveryV2Client client;
    private Discovery run;

    @BeforeEach
    void setUp() {
        client = new DiscoveryV2Client(connectorApiFactory, connectorRepository, attributeEngine, credentialService,
                resourceService, authHelper);
        // Runs the elevated body inline: the bare mock returns null without invoking it, so every assertion about
        // what the loaders received would pass while resolving nothing.
        lenient()
                .when(authHelper.runAsSystem(eq(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME), any()))
                .thenAnswer(invocation -> invocation.<AuthHelper.ThrowingSupplier<?, ?>>getArgument(1).get());

        run = new Discovery();
        run.setUuid(UUID.randomUUID());
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorUuid(UUID.randomUUID());
        run.setLastAppliedSequence(17L);
        run.setRunMeta(DiscoveryRunMetaFixture.runMeta("connectorRunId", "run-42"));

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
        assertThat(sent.getValue().getMeta())
                .as("the connector is stateless; without its own handle it cannot resolve the run")
                .isEqualTo(run.getRunMeta());
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
        run.setResources(List.of(Resource.CERTIFICATE));
        // The same credential declared at run level and again on the resource: two definitions, one referent.
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), isNull(), any(), any()))
                .thenReturn(List.of(definition("credential", "reference-only", AttributeContentType.CREDENTIAL)));
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), eq("certificates"), any(), any()))
                .thenReturn(List.of(definition("credential", "reference-only", AttributeContentType.CREDENTIAL)));
        when(apiClient.status(any(), any())).thenReturn(new DiscoveryStatusResponseDto());

        client.status(run);

        // For a SECRET reference a lookup is a connector round trip, so resolving once per scope would pay for
        // the same secret as many times as the run targets resources.
        ArgumentCaptor<List<DataAttribute>> resolved = ArgumentCaptor.captor();
        verify(resourceService).loadResourceObjectContentData(resolved.capture());
        assertThat(resolved.getValue()).hasSize(1);
        assertThat(capturedStatus().getResourceAttributes().get(Resource.CERTIFICATE))
                .as("the scope that shared the definition still carries it")
                .singleElement()
                .extracting(RequestAttribute::getName)
                .isEqualTo("credential");
    }

    @Test
    void resolvedContent_reachesEveryScopeThatDeclaredTheDefinition() throws Exception {
        run.setResources(List.of(Resource.CERTIFICATE));
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), isNull(), any(), any()))
                .thenReturn(List.of(definition("credential", "reference-only", AttributeContentType.CREDENTIAL)));
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), eq("certificates"), any(), any()))
                .thenReturn(List.of(definition("credential", "reference-only", AttributeContentType.CREDENTIAL)));
        doAnswer(invocation -> {
            List<DataAttribute> resolving = invocation.getArgument(0);
            resolving.forEach(attribute -> attribute.setContent(List.of(new StringAttributeContentV3("s3cret"))));
            return null;
        }).when(resourceService).loadResourceObjectContentData(anyList());
        when(apiClient.status(any(), any())).thenReturn(new DiscoveryStatusResponseDto());

        client.status(run);

        // Deduping must not cost the skipped scope its content: the connector needs the resolved value in both.
        DiscoveryRunRequestDto sent = capturedStatus();
        assertThat(firstData(sent.getAttributes().getFirst().getContent())).isEqualTo("s3cret");
        assertThat(firstData(sent.getResourceAttributes().get(Resource.CERTIFICATE).getFirst().getContent()))
                .isEqualTo("s3cret");
    }

    @Test
    void aReferenceToDereference_isResolvedUnderTheSystemIdentity() throws Exception {
        run.setResources(List.of(Resource.CERTIFICATE));
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), isNull(), any(), any()))
                .thenReturn(List.of(definition("credential", "reference-only", AttributeContentType.CREDENTIAL)));
        when(apiClient.status(any(), any())).thenReturn(new DiscoveryStatusResponseDto());

        client.status(run);

        // Tick workers and the reaper's sweep hold no principal, and the credential loader is gated on
        // CREDENTIAL:DETAIL at method entry.
        verify(authHelper).runAsSystem(eq(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME), any());
        verify(credentialService).loadFullCredentialData(anyList());
    }

    @Test
    void nothingToDereference_skipsTheLoadersAndTheElevation() throws Exception {
        run.setResources(List.of(Resource.CERTIFICATE));
        when(attributeEngine.getDefinitionObjectAttributeContent(any(), any(), any(), any(), any()))
                .thenReturn(List.of(definition("host", "10.0.0.0/24", AttributeContentType.STRING)));
        when(apiClient.status(any(), any())).thenReturn(new DiscoveryStatusResponseDto());

        client.status(run);

        // Nothing for either loader to do, and this path runs on every tick for the whole life of the run — so it
        // must not spend an auth-service round trip proving that.
        verifyNoInteractions(authHelper);
        verifyNoInteractions(credentialService);
        verifyNoInteractions(resourceService);
        assertThat(capturedStatus().getAttributes())
                .as("the definition still reaches the connector, just unresolved")
                .singleElement()
                .extracting(RequestAttribute::getName)
                .isEqualTo("host");
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

    private DiscoveryDrainRequestDto capturedDrain() throws Exception {
        ArgumentCaptor<DiscoveryDrainRequestDto> sent = ArgumentCaptor.forClass(DiscoveryDrainRequestDto.class);
        verify(apiClient).results(any(ConnectorDto.class), sent.capture());
        return sent.getValue();
    }
}
