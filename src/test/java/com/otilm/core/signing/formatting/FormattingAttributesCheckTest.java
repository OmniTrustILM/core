package com.otilm.core.signing.formatting;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v2.GroupAttributeV2;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.DataAttributeV3Builder.aDataAttribute;
import static com.otilm.core.util.builders.RequestAttributeV3Builder.aCustomAttribute;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FormattingAttributesCheckTest {

    private static final String PROFILE_NAME = "sp-formatting";

    @Test
    void rejectsAsMisconfigured_whenTheFormatterDoesNotDefineAConfiguredName() {
        // given
        var undefinedName = "data_retiredPolicy";
        List<BaseAttribute> definitions = List.of(stringDefinition("data_formattingPolicy"));
        List<RequestAttribute> attributes = List.of(stringAttribute(undefinedName));

        // when
        ThrowingCallable check = () -> FormattingAttributesCheck.requireValid(PROFILE_NAME, definitions, attributes);

        // then
        assertThatThrownBy(check).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
            assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
            assertThat(refusal.operatorMessage()).contains(undefinedName);
        });
    }

    @Test
    void acceptsAConfiguredName_whenTheFormatterPublishesAGroup() {
        // given — a group's members are known only once its callback runs
        List<BaseAttribute> definitions = List.of(group("group_formattingPolicies"));
        List<RequestAttribute> attributes = List.of(stringAttribute("data_groupMember"));

        // when
        ThrowingCallable check = () -> FormattingAttributesCheck.requireValid(PROFILE_NAME, definitions, attributes);

        // then
        assertThatCode(check).doesNotThrowAnyException();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static BaseAttribute stringDefinition(String name) {
        return aDataAttribute().withName(name).build();
    }

    private static GroupAttributeV2 group(String name) {
        GroupAttributeV2 group = new GroupAttributeV2();
        group.setUuid(UUID.randomUUID().toString());
        group.setName(name);
        return group;
    }

    private static RequestAttribute stringAttribute(String name) {
        return aCustomAttribute().withName(name).withStringContent("value").build();
    }
}
