package com.otilm.core.cluster;

import jakarta.persistence.EntityManager;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class ClusterOperationSynchronizerTest {

    @Mock
    private EntityManager entityManager;

    @Test
    void lockingNoKeysRunsNoStatement() {
        new ClusterOperationSynchronizer(entityManager).lockAll(List.of());

        verifyNoInteractions(entityManager);
    }
}
