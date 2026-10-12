package com.otilm.core.messaging.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.core.reference.ObjectRef;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import static org.assertj.core.api.Assertions.assertThat;

/** During a rolling upgrade an older Core reads these messages and refuses any member added after it. */
class SecretActionDataTest {

    private final ObjectMapper jmsMessageMapper = ObjectMapperFactory.jmsMessage(Jackson2ObjectMapperBuilder.json());

    @Test
    void omitsTheOwner_whenTheDeleteHasNone() {
        // given
        var unownedDelete = SecretActionData.builder().deleteInVault(true).originalState(SecretState.ACTIVE).build();

        // when
        JsonNode data = jmsMessageMapper.valueToTree(unownedDelete);

        // then
        assertThat(data.has("releasedBy")).isFalse();
    }

    @Test
    void carriesTheOwner_whenTheDeleteHasOne() {
        // given
        var owner = new ObjectRef(Resource.TSP_PROFILE_BASIC_CREDENTIAL, UUID.randomUUID());
        var ownedDelete = SecretActionData.builder().releasedBy(owner).build();

        // when
        JsonNode data = jmsMessageMapper.valueToTree(ownedDelete);

        // then
        assertThat(data.path("releasedBy").path("uuid").asText()).isEqualTo(owner.uuid().toString());
    }
}
