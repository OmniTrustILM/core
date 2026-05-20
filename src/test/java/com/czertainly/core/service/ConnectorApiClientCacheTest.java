package com.czertainly.core.service;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.core.connector.v2.ConnectorUpdateRequestDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.core.config.cache.CacheConfig;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.service.v2.ConnectorService;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

class ConnectorApiClientCacheTest extends BaseSpringBootTest {

    @Autowired
    private ConnectorService connectorService;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private CacheManager cacheManager;

    private Cache cache;
    private WireMockServer mockServer;

    @BeforeEach
    void prepareCache() {
        cache = cacheManager.getCache(CacheConfig.CONNECTOR_API_CLIENT_CACHE);
        Assertions.assertNotNull(cache, "connectorApiClient cache must be registered");
        cache.clear();
    }

    @AfterEach
    void tearDown() {
        if (cache != null) {
            cache.clear();
        }
        if (mockServer != null) {
            mockServer.stop();
            mockServer = null;
        }
    }

    private Connector persistConnector(ConnectorVersion version, String url) {
        Connector connector = new Connector();
        connector.setName("test-" + UUID.randomUUID());
        connector.setVersion(version);
        connector.setUrl(url);
        connector.setStatus(ConnectorStatus.CONNECTED);
        return connectorRepository.saveAndFlush(connector);
    }

    private String startMockServer() {
        mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());
        mockServer.stubFor(WireMock.get("/v1").willReturn(WireMock.okJson("[]")));
        return "http://localhost:" + mockServer.port();
    }

    @Test
    void firstLookupPopulatesCache() throws NotFoundException {
        Connector c = persistConnector(ConnectorVersion.V2, "http://test/v2");
        Assertions.assertNull(cache.get(c.getUuid()), "cache should be cold");

        ApiClientConnectorInfo info = connectorService.getConnectorForApiClient(c.getUuid());

        Assertions.assertNotNull(info);
        Assertions.assertNotNull(cache.get(c.getUuid()), "cache entry should be present");
        Assertions.assertEquals(c.getUuid().toString(), info.getUuid());
    }

    @Test
    void secondLookupReturnsSameInstance() throws NotFoundException {
        Connector c = persistConnector(ConnectorVersion.V2, "http://test/v2");

        ApiClientConnectorInfo first = connectorService.getConnectorForApiClient(c.getUuid());
        ApiClientConnectorInfo second = connectorService.getConnectorForApiClient(c.getUuid());

        Assertions.assertSame(first, second, "second lookup must return the cached object");
    }

    @Test
    void v1ConnectorFieldsArePopulated() throws NotFoundException {
        Connector c = persistConnector(ConnectorVersion.V1, "http://test/v1");

        ApiClientConnectorInfo info = connectorService.getConnectorForApiClient(c.getUuid());

        Assertions.assertEquals(c.getUuid().toString(), info.getUuid());
        Assertions.assertEquals(c.getName(), info.getName());
        Assertions.assertEquals("http://test/v1", info.getUrl());
        Assertions.assertEquals(ConnectorStatus.CONNECTED, info.getStatus());
    }

    @Test
    void v2ConnectorFieldsArePopulated() throws NotFoundException {
        Connector c = persistConnector(ConnectorVersion.V2, "http://test/v2");

        ApiClientConnectorInfo info = connectorService.getConnectorForApiClient(c.getUuid());

        Assertions.assertEquals(c.getUuid().toString(), info.getUuid());
        Assertions.assertEquals(c.getName(), info.getName());
        Assertions.assertEquals("http://test/v2", info.getUrl());
        Assertions.assertEquals(ConnectorStatus.CONNECTED, info.getStatus());
    }

    @Test
    void cachedInstanceExposesNoSetters() throws NotFoundException {
        Connector c = persistConnector(ConnectorVersion.V2, "http://test/v2");

        ApiClientConnectorInfo info = connectorService.getConnectorForApiClient(c.getUuid());

        for (var m : info.getClass().getMethods()) {
            Assertions.assertFalse(m.getName().startsWith("set"),
                    "cached connector info must not expose setters; found " + m.getName());
        }
    }

    @Test
    void missingConnectorThrowsNotFound() {
        Assertions.assertThrows(NotFoundException.class,
                () -> connectorService.getConnectorForApiClient(UUID.randomUUID()));
    }

    @Test
    void cacheIsEvictedAfterEditConnector() throws NotFoundException, ConnectorException, AttributeException {
        String mockUrl = startMockServer();
        Connector c = persistConnector(ConnectorVersion.V1, mockUrl);
        ApiClientConnectorInfo warmed = connectorService.getConnectorForApiClient(c.getUuid());
        Assertions.assertNotNull(cache.get(c.getUuid()));

        ConnectorUpdateRequestDto request = new ConnectorUpdateRequestDto();
        request.setUrl(mockUrl);

        connectorService.editConnector(c.getSecuredUuid(), request);

        Assertions.assertNull(cache.get(c.getUuid()),
                "editConnector must register an afterCommit eviction");

        ApiClientConnectorInfo reloaded = connectorService.getConnectorForApiClient(c.getUuid());
        Assertions.assertNotSame(warmed, reloaded,
                "post-eviction lookup must materialise a fresh instance");
    }

    @Test
    void cacheIsEvictedAfterDelete() throws NotFoundException {
        Connector c = persistConnector(ConnectorVersion.V2, "http://test/del");
        UUID uuid = c.getUuid();
        connectorService.getConnectorForApiClient(uuid);
        Assertions.assertNotNull(cache.get(uuid));

        connectorService.deleteConnector(c.getSecuredUuid());

        Assertions.assertNull(cache.get(uuid),
                "deleteConnector must register an afterCommit eviction");
        Assertions.assertThrows(NotFoundException.class,
                () -> connectorService.getConnectorForApiClient(uuid));
    }

    @Test
    void concurrentCacheMissesShareOneLoad() throws Exception {
        Connector c = persistConnector(ConnectorVersion.V2, "http://test/concurrent");
        cache.clear();

        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch go = new CountDownLatch(1);
        AtomicReference<ApiClientConnectorInfo> ref1 = new AtomicReference<>();
        AtomicReference<ApiClientConnectorInfo> ref2 = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();

        try {
            pool.submit(() -> {
                try {
                    ready.countDown();
                    go.await();
                    ref1.set(connectorService.getConnectorForApiClient(c.getUuid()));
                } catch (Throwable t) {
                    failure.set(t);
                }
            });
            pool.submit(() -> {
                try {
                    ready.countDown();
                    go.await();
                    ref2.set(connectorService.getConnectorForApiClient(c.getUuid()));
                } catch (Throwable t) {
                    failure.set(t);
                }
            });

            Assertions.assertTrue(ready.await(5, TimeUnit.SECONDS));
            go.countDown();

            pool.shutdown();
            Assertions.assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }

        Assertions.assertNull(failure.get(), "no thread should have thrown");
        Assertions.assertNotNull(ref1.get());
        Assertions.assertNotNull(ref2.get());
        Assertions.assertSame(ref1.get(), ref2.get(),
                "both threads should observe the same cached instance — sync=true serialises the miss");
    }
}
