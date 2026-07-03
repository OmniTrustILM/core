package com.otilm.core.integration.repository;

import com.otilm.core.Application;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.repository.ConnectorRepository;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@SpringBootTest(classes = Application.class)
@Transactional
@Rollback
class ConnectorRepositoryITest {

    @Autowired
    private ConnectorRepository connectorRepository;

    @Test
    void testCreateConnector() {
        Connector request = new Connector();
        request.setName("testConnector");
        request.setUrl("testUrl");
        request.setFunctionGroups(Collections.emptySet());

        Connector result = connectorRepository.save(request);
        Assertions.assertNotNull(result.getUuid());
    }
}
