package com.otilm.core.messaging.model;

import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IssueActionDataTest {

    @Test
    void readsTheRequest_whenTheDataIsTheRecord() {
        // given
        UUID queuedFor = UUID.randomUUID();

        // when
        UUID read = IssueActionData.certificateRequestUuidOf(new IssueActionData(queuedFor));

        // then
        assertThat(read).isEqualTo(queuedFor);
    }

    @Test
    void readsTheRequest_whenTheDataCameBackAsJson() throws Exception {
        // given — the shape the broker and an approval's stored data hand back
        UUID queuedFor = UUID.randomUUID();
        var mapper = ObjectMapperFactory.wire();
        Object roundTripped = mapper.readValue(mapper.writeValueAsString(new IssueActionData(queuedFor)), Object.class);

        // when
        UUID read = IssueActionData.certificateRequestUuidOf(roundTripped);

        // then
        assertThat(read).isEqualTo(queuedFor);
    }

    @Test
    void readsNoRequest_whenTheActionCarriesNoData() {
        // given — an action queued before its data named the request

        // when
        UUID read = IssueActionData.certificateRequestUuidOf(null);

        // then
        assertThat(read).isNull();
    }

    @Test
    void readsNoRequest_whenTheDataIsOfAnotherShape() {
        // given
        Map<String, Object> otherData = Map.of("reason", "superseded");

        // when
        UUID read = IssueActionData.certificateRequestUuidOf(otherData);

        // then
        assertThat(read).isNull();
    }
}
