package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import com.czertainly.core.dao.entity.DiscoveryHistory;
import com.czertainly.core.dao.entity.FunctionGroup;
import com.czertainly.core.dao.repository.DiscoveryRepository;
import com.czertainly.core.dao.repository.FunctionGroupRepository;
import com.czertainly.core.messaging.jms.producers.NotificationProducer;
import com.czertainly.core.util.BaseMessagingIntTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

@ActiveProfiles({"messaging-int-test"})
class DiscoveryServiceIntTest extends BaseMessagingIntTest {

    private static final String DISCOVERY_NAME = "testDiscovery1";

    @Autowired
    private DiscoveryService discoveryService;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;

    @MockitoSpyBean
    private NotificationProducer notificationProducer;

    private DiscoveryHistory discovery;

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

        discovery = new DiscoveryHistory();
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
    void testBulkRemove() throws NotFoundException {
        discoveryService.bulkRemoveDiscovery(List.of(discovery.getSecuredUuid()));

        // Verify that notification was sent via messaging
        // Note: We verify the producer was called because the full messaging flow
        // (producer -> broker -> listener -> database) is complex to test end-to-end
        verify(notificationProducer, timeout(5000).atLeastOnce())
                .produceInternalNotificationMessage(
                        eq(Resource.DISCOVERY),
                        isNull(),
                        anyList(),
                        eq("Discovery histories have been deleted."),
                        isNull()
                );

        // Verify discovery was actually deleted
        Assertions.assertFalse(discoveryRepository.findByUuid(discovery.getUuid()).isPresent(),
                "Discovery should be deleted from repository");
    }
}
