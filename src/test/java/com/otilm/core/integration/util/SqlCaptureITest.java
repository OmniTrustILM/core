package com.otilm.core.integration.util;

import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SqlCapture;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

class SqlCaptureITest extends BaseSpringBootTest {

    @Autowired
    private GroupRepository groupRepository;

    @Test
    void recordsTheStatementsARecordingSends() throws Exception {
        SqlCapture.Captured<List<Group>> captured = SqlCapture.during(() -> groupRepository.findAll());

        assertThat(captured.statements()).anyMatch(sql -> sql.contains("\"group\""));
        assertThat(captured.result()).isEmpty();
    }

    @Test
    void recordingEndsWhenTheActionReturns() throws Exception {
        boolean recordingInside = SqlCapture.during(SqlCapture::isRecording).result();

        assertThat(recordingInside).isTrue();
        assertThat(SqlCapture.isRecording()).isFalse();
    }
}
