package com.otilm.core.signing.formatting;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.GroupAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

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

    private static DataAttributeV2 stringDefinition(String name) {
        DataAttributeV2 definition = new DataAttributeV2();
        definition.setUuid(UUID.randomUUID().toString());
        definition.setName(name);
        definition.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel(name);
        definition.setProperties(properties);
        return definition;
    }

    private static GroupAttributeV2 group(String name) {
        GroupAttributeV2 group = new GroupAttributeV2();
        group.setUuid(UUID.randomUUID().toString());
        group.setName(name);
        return group;
    }

    private static RequestAttribute stringAttribute(String name) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setUuid(UUID.randomUUID());
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV2("value", "value")));
        return attribute;
    }
}
