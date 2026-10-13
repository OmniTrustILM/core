package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorClientException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.client.v1.DiscoverySyncApiClient;
import com.otilm.api.model.connector.discovery.DiscoveryProviderDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.mapper.discovery.DiscoveryDtoMapper;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.DiscoveryProperties;
import com.otilm.core.service.ResourceInternalService;
import com.otilm.core.service.handler.CertificateHandler;
import com.otilm.core.service.writer.DiscoveryWriter;
import com.otilm.core.service.writer.discovery.DiscoveryMessageWriter;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.PlatformTransactionManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Pins that the v1 interface rejects the lifecycle operations it never supported, and what text a run that cannot be
 * prepared ends with.
 */
class DiscoveryProviderV1AdapterTest {

    private final DiscoveryRepository discoveryRepository = mock(DiscoveryRepository.class);
    private final ConnectorRepository connectorRepository = mock(ConnectorRepository.class);
    private final AttributeEngine attributeEngine = mock(AttributeEngine.class);
    private final CredentialInternalService credentialService = mock(CredentialInternalService.class);
    private final ResourceInternalService resourceService = mock(ResourceInternalService.class);
    private final DiscoveryDetailCounts detailCounts = mock(DiscoveryDetailCounts.class);
    private final DiscoveryProperties discoveryProperties = mock(DiscoveryProperties.class);
    private final ConnectorApiFactory connectorApiFactory = mock(ConnectorApiFactory.class);
    private final DiscoverySyncApiClient providerClient = mock(DiscoverySyncApiClient.class);
    private final EventProducer eventProducer = mock(EventProducer.class);
    private final DiscoveryWriter discoveryWriter = mock(DiscoveryWriter.class);

    private final DiscoveryProviderV1Adapter adapter = new DiscoveryProviderV1Adapter(discoveryProperties,
            mock(PlatformTransactionManager.class), discoveryRepository, connectorRepository,
            mock(CertificateRepository.class), mock(DiscoveryCertificateRepository.class), attributeEngine,
            mock(CertificateHandler.class), credentialService, resourceService, connectorApiFactory, eventProducer,
            detailCounts, mock(DiscoveryMessageWriter.class), discoveryWriter);

    /** A legacy connector's error arrives with its response body as the message. */
    private static final String CONNECTOR_BODY = "<html><body>upstream 10.0.0.5:8443 refused</body></html>";

    private final Discovery run = new Discovery();

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void stopIsUnsupported() {
        assertThatThrownBy(() -> adapter.stop(run)).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void resumeIsUnsupported() {
        assertThatThrownBy(() -> adapter.resume(run)).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void cancelIsUnsupported() {
        assertThatThrownBy(() -> adapter.cancel(run)).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void aLoadFailureThatIsNotACorePlatformExceptionEndsTheRunWithTheFixedText() throws NotFoundException {
        connectAs();
        prepareRun();
        doThrow(new IllegalStateException("select * from secret"))
                .when(credentialService)
                .loadFullCredentialData(any(List.class));

        var detail = adapter.start(run.getUuid(), null);

        assertThat(detail.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(detail.getConnectorStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(detail.getMessage()).isEqualTo("Discovery could not be prepared in Core.");
        assertThat(detail.getMessage()).doesNotContain("select");
    }

    @Test
    void aStartFailureThatIsNotACorePlatformExceptionEndsTheRunWithTheFixedText() throws ConnectorException {
        connectAs();
        prepareRun();
        when(providerClient.discoverCertificates(any(), any()))
                .thenThrow(new IllegalStateException("Cannot deserialize value of type com.example.Secret"));

        var detail = adapter.start(run.getUuid(), null);

        assertThat(detail.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(detail.getMessage()).isEqualTo("Failed to run discovery at the provider.");
        assertThat(detail.getMessage()).doesNotContain("deserialize");
    }

    @Test
    void aPollFailureThatIsNotACorePlatformExceptionEndsTheRunWithTheFixedText() throws ConnectorException {
        connectAs();
        prepareRun();
        when(discoveryProperties.sleepTimeMs()).thenReturn(1);
        DiscoveryProviderDto started = new DiscoveryProviderDto();
        started.setUuid("provider-run");
        started.setName("unit-run");
        started.setStatus(DiscoveryStatus.IN_PROGRESS);
        when(providerClient.discoverCertificates(any(), any())).thenReturn(started);
        when(providerClient.getDiscoveryData(any(), any(), any()))
                .thenThrow(new IllegalStateException("Cannot deserialize value of type com.example.Secret"));

        var detail = adapter.start(run.getUuid(), null);

        assertThat(detail.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(detail.getMessage()).isEqualTo("Error in provider during discovery.");
        assertThat(detail.getMessage()).doesNotContain("deserialize");
    }

    @Test
    void aConnectorFailureWhileLoadingTheContextEndsTheRunWithTheFixedText()
            throws NotFoundException, AttributeException, ConnectorException {
        connectAs();
        prepareRun();
        doThrow(new ConnectorServerException(CONNECTOR_BODY, HttpStatus.BAD_GATEWAY))
                .when(resourceService)
                .loadResourceObjectContentData(any(List.class));

        var detail = adapter.start(run.getUuid(), null);

        assertThat(detail.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(detail.getMessage()).isEqualTo("Discovery could not be prepared in Core.");
    }

    @Test
    void aConnectorFailureAtStartEndsTheRunWithoutTheConnectorsText() throws ConnectorException {
        connectAs();
        prepareRun();
        when(providerClient.discoverCertificates(any(), any()))
                .thenThrow(new ConnectorServerException(CONNECTOR_BODY, HttpStatus.BAD_GATEWAY));

        var detail = adapter.start(run.getUuid(), null);

        assertThat(detail.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(detail.getMessage()).isEqualTo("Failed to run discovery at the provider.");
    }

    @Test
    void aConnectorFailureWhilePollingEndsTheRunWithCoreText() throws ConnectorException {
        connectAs();
        prepareRun();
        when(discoveryProperties.sleepTimeMs()).thenReturn(1);
        DiscoveryProviderDto started = new DiscoveryProviderDto();
        started.setUuid("provider-run");
        started.setName("unit-run");
        started.setStatus(DiscoveryStatus.IN_PROGRESS);
        when(providerClient.discoverCertificates(any(), any())).thenReturn(started);
        when(providerClient.getDiscoveryData(any(), any(), any()))
                .thenThrow(new ConnectorClientException(CONNECTOR_BODY, HttpStatus.BAD_REQUEST));

        var detail = adapter.start(run.getUuid(), null);

        assertThat(detail.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(detail.getMessage())
                .isEqualTo("Discovery has failed on connector side while waiting for completion");
    }

    @Test
    void aRunTheLastResortEndedStaysEndedWhenItsDetailCannotBeRead() throws ConnectorException {
        connectAs();
        prepareRun();
        when(providerClient.discoverCertificates(any(), any())).thenThrow(new IllegalStateException("provider failed"));
        IllegalStateException failure = new IllegalStateException("save refused");
        when(discoveryRepository.save(any())).thenThrow(failure);
        when(discoveryWriter.markFailedUnlessEnded(run.getUuid(), "Discovery failed in Core.")).thenReturn(true);
        when(discoveryRepository.findByUuid(run.getUuid())).thenReturn(Optional.of(run));
        when(detailCounts.forRun(run)).thenThrow(new IllegalStateException("counts unreadable"));

        assertThatThrownBy(() -> adapter.start(run.getUuid(), null))
                .isSameAs(failure)
                .satisfies(e -> assertThat(e.getSuppressed())
                        .extracting(Throwable::getMessage)
                        .containsExactly("counts unreadable"));
        verify(eventProducer).produceMessage(any());
    }

    private void connectAs() {
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(new AuthenticationInfo(
                        AuthMethod.USER_PROXY, UUID.randomUUID().toString(), "operator", List.of()))));
    }

    /** A run whose context loads cleanly and whose provider client is {@link #providerClient}. */
    private void prepareRun() {
        UUID connectorUuid = UUID.randomUUID();
        run.setUuid(UUID.randomUUID());
        run.setName("unit-run");
        run.setConnectorUuid(connectorUuid);
        Connector connector = mock(Connector.class);
        when(connector.getUuid()).thenReturn(connectorUuid);
        when(connector.mapToDto()).thenReturn(new ConnectorDto());
        when(discoveryRepository.findWithTriggersByUuid(run.getUuid())).thenReturn(run);
        when(connectorRepository.findByUuid(connectorUuid)).thenReturn(Optional.of(connector));
        when(attributeEngine
                .getDefinitionObjectAttributeContent(any(), any(), any(), any(Resource.class), any(UUID.class)))
                .thenReturn(List.of());
        when(detailCounts.forRun(run)).thenReturn(new DiscoveryDtoMapper.DetailCounts(0, 0, 0, 0));
        when(connectorApiFactory.getDiscoveryApiClient(any())).thenReturn(providerClient);
    }
}
