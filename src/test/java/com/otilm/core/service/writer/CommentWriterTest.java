package com.otilm.core.service.writer;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.repository.CommentRepository;
import com.otilm.core.service.ResourceInternalService;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class CommentWriterTest {

    @Mock
    private CommentRepository commentRepository;

    @Mock
    private ResourceInternalService resourceService;

    @Mock
    private ClusterOperationSynchronizer synchronizer;

    @Test
    void purgingNoHostsTakesNoLockAndRunsNoStatement() {
        CommentWriter writer = new CommentWriter(commentRepository, resourceService, synchronizer);

        assertThat(writer.deleteAllForObjects(Resource.CERTIFICATE, List.of())).isZero();

        verifyNoInteractions(synchronizer, commentRepository);
    }
}
