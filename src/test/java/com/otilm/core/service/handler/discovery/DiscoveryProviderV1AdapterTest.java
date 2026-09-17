package com.otilm.core.service.handler.discovery;

import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryMessageRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.DiscoveryProperties;
import com.otilm.core.service.ResourceInternalService;
import com.otilm.core.service.handler.CertificateHandler;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/** Pins that the v1 interface rejects the lifecycle operations it never supported. */
class DiscoveryProviderV1AdapterTest {

    private final DiscoveryProviderV1Adapter adapter = new DiscoveryProviderV1Adapter(mock(DiscoveryProperties.class),
            mock(PlatformTransactionManager.class), mock(DiscoveryRepository.class), mock(ConnectorRepository.class),
            mock(CertificateRepository.class), mock(DiscoveryCertificateRepository.class), mock(AttributeEngine.class),
            mock(CertificateHandler.class), mock(CredentialInternalService.class), mock(ResourceInternalService.class),
            mock(ConnectorApiFactory.class), mock(EventProducer.class), mock(DiscoveryMessageRepository.class),
            mock(DiscoveryDetailCounts.class));

    private final Discovery run = new Discovery();

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
}
