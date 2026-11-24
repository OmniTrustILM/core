package com.otilm.core.integration.service;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.FunctionGroup;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.messaging.jms.producers.NotificationProducer;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.util.BaseMessagingIntTest;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

@ActiveProfiles(value = {"messaging-int-test"}, inheritProfiles = false)
class DiscoveryServiceMessagingITest extends BaseMessagingIntTest {

    private static final String DISCOVERY_NAME = "testDiscovery1";

    @Autowired
    private DiscoveryExternalService discoveryService;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;

    @MockitoSpyBean
    private NotificationProducer notificationProducer;

    private Discovery discovery;

    @BeforeEach
    void setUp() {
        // Mock authentication for all threads
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

        Authentication authentication = getAuthentication();
        SecurityContextHolder.getContext().setAuthentication(authentication);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.DISCOVERY_PROVIDER);
        functionGroup.setName(FunctionGroupCode.DISCOVERY_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        discovery = new Discovery();
        discovery.setName(DISCOVERY_NAME);
        discovery.setStatus(DiscoveryStatus.IN_PROGRESS);
        discovery.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        discovery = discoveryRepository.save(discovery);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        // back to an original strategy
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
    }

    @Test
    void notifiesThatTheRunsAreDeleted_whenABulkDeleteCommits() throws Exception {
        // given — a v1 run, which deletes in any state

        // when
        discoveryService.bulkRemoveDiscovery(List.of(discovery.getSecuredUuid()));

        // then
        verify(notificationProducer, timeout(5000).atLeastOnce())
                .produceInternalNotificationMessage(eq(Resource.DISCOVERY), isNull(), anyList(),
                        eq("Discovery histories have been deleted."), isNull());

        assertThat(discoveryRepository.findByUuid(discovery.getUuid())).isEmpty();
    }
}
