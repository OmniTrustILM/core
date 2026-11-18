package com.otilm.core.signing.contentsigning.formatting;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.constraint.RegexpAttributeConstraint;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RequestAttributesCheckTest {

    private static final String PROFILE_NAME = "pades-profile";
    private static final String SUB_FILTER = "data_subFilter";
    private static final String VISIBLE_SIGNATURE = "visibleSignature";
    private static final String PAGE = "data_visibleSignaturePage";
    private static final String TEXT = "data_visibleSignatureText";
    private static final String LOCATION = "data_location";
    private static final String REASON = "data_reason";
    private static final String SCOPE = "data_signatureScope";
    private static final String LETTERS_ONLY = "^[A-Za-z ]+$";

    private static final ContentSigningFormattingDefinitions DEFINITIONS = new ContentSigningFormattingDefinitions(
            List.of(definition(SUB_FILTER, null)),
            List
                    .of(definition(PAGE, VISIBLE_SIGNATURE), definition(TEXT, VISIBLE_SIGNATURE),
                            definition(LOCATION, null), definition(REASON, null), definition(SCOPE, null)));

    @Nested
    class RequireAccepted {

        @Test
        void acceptsTheAttributesOfAnAllowedGroup() {
            // given
            var allowed = Set.of(VISIBLE_SIGNATURE);
            var requested = List.of(value(PAGE, "1"), value(TEXT, "Signed"));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, allowed, requested);

            // then
            assertThatCode(check).doesNotThrowAnyException();
        }

        @Test
        void acceptsAnUngroupedAttribute_whenTheProfileAllowsItsName() {
            // given
            var allowed = Set.of(LOCATION);
            var requested = List.of(value(LOCATION, "Prague"));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, allowed, requested);

            // then
            assertThatCode(check).doesNotThrowAnyException();
        }

        @Test
        void refusesAProfileAttribute() {
            // given
            var requested = List.of(value(SUB_FILTER, "ETSI.CAdES.detached"));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(LOCATION), requested);

            // then
            assertRefusalSays(check, SUB_FILTER, "profile attribute");
        }

        @Test
        void refusesAnUndeclaredName() {
            // given
            var undeclared = "data_contactInfo";
            var requested = List.of(value(undeclared, "someone"));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(undeclared), requested);

            // then
            assertRefusalSays(check, undeclared);
        }

        @Test
        void refusesAnAttributeSentTwice() {
            // given
            var requested = List.of(value(LOCATION, "Prague"), value(LOCATION, "Brno"));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(LOCATION), requested);

            // then
            assertRefusalSays(check, LOCATION);
        }

        @Test
        void refusesAGroupedAttribute_whenTheProfileDoesNotAllowItsGroup() {
            // given
            var requested = List.of(value(PAGE, "1"));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(LOCATION), requested);

            // then
            assertRefusalSays(check, PAGE, VISIBLE_SIGNATURE);
        }

        @Test
        void refusesAGroupedAttribute_whenTheProfileAllowsOnlyItsOwnName() {
            // given
            var requested = List.of(value(PAGE, "1"));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(PAGE), requested);

            // then
            assertRefusalSays(check, PAGE, VISIBLE_SIGNATURE);
        }

        @Test
        void refusesAnUngroupedAttribute_whenTheProfileDoesNotAllowItsName() {
            // given
            var requested = List.of(value(REASON, "Approval"));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(LOCATION), requested);

            // then
            assertRefusalSays(check, REASON);
        }

        @Test
        void refusesEveryRequestAttribute_whenTheAllowedListIsEmpty() {
            // given
            var requested = List.of(value(LOCATION, "Prague"));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(), requested);

            // then
            assertRefusalSays(check, LOCATION);
        }

        @Test
        void refusesAValue_whenItsDefinitionRefusesIt() {
            // given
            var notLettersOnly = "Prague 1";
            var requested = List.of(value(LOCATION, notLettersOnly));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(LOCATION), requested);

            // then
            assertRefusalSays(check, LOCATION);
        }

        @Test
        void refusesAV2Attribute_whenItsDefinitionIsV3() {
            // given
            var requested = List.of(v2Value(LOCATION, "Prague"));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(LOCATION), requested);

            // then
            assertRefusalSays(check, LOCATION, "v2", "v3");
        }

        @Test
        void refusesAContentType_whenItDiffersFromTheDefinitions() {
            // given
            var integerTypedString = new RequestAttributeV3(uuidOf(LOCATION), LOCATION, AttributeContentType.INTEGER,
                    List.of(new StringAttributeContentV3("Prague")));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(LOCATION), List.of(integerTypedString));

            // then
            assertRefusalSays(check, LOCATION, "content type");
        }

        @Test
        void refusesAnAttributeWithoutContent() {
            // given
            var withoutContent = attributeCarrying(LOCATION, null);

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(LOCATION), List.of(withoutContent));

            // then
            assertRefusalSays(check, LOCATION, "no value");
        }

        @Test
        void refusesAnAttributeWithEmptyContent() {
            // given
            var withEmptyContent = attributeCarrying(LOCATION, List.of());

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(LOCATION), List.of(withEmptyContent));

            // then
            assertRefusalSays(check, LOCATION, "no value");
        }

        @Test
        void refusesAnAttributeWithANullItem() {
            // given
            var withNullItem = attributeCarrying(LOCATION, Collections.singletonList(null));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(LOCATION), List.of(withNullItem));

            // then
            assertRefusalSays(check, LOCATION, "without data");
        }

        @Test
        void refusesAnAttributeWithAnItemWithoutData() {
            // given
            var withoutData = attributeCarrying(LOCATION, List.of(new StringAttributeContentV3()));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(LOCATION), List.of(withoutData));

            // then
            assertRefusalSays(check, LOCATION, "without data");
        }

        @Test
        void refusesSeveralValues_whenTheDefinitionTakesOne() {
            // given
            var twoReasons = attributeCarrying(REASON,
                    List.of(new StringAttributeContentV3("Approval"), new StringAttributeContentV3("Review")));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(REASON), List.of(twoReasons));

            // then
            assertRefusalSays(check, REASON, "takes one");
        }

        @Test
        void refusesAValueOutsideTheOptionsOfAClosedList() {
            // given
            var labelInsteadOfCode = "Revision";

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(SCOPE),
                            List.of(value(SCOPE, labelInsteadOfCode)));

            // then
            assertRefusalSays(check, SCOPE, "options");
        }

        @Test
        void acceptsAnOptionOfAClosedList() {
            // given
            var requested = List.of(value(SCOPE, "revision"));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(SCOPE), requested);

            // then
            assertThatCode(check).doesNotThrowAnyException();
        }

        @Test
        void leavesTheValueOutOfTheRefusal_whenItsDefinitionRefusesIt() {
            // given
            var notLettersOnly = "Prague 1";
            var requested = List.of(value(LOCATION, notLettersOnly));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(LOCATION), requested);

            // then
            assertThatThrownBy(check).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
                assertThat(refusal.clientMessage()).doesNotContain(notLettersOnly);
                assertThat(refusal.getMessage()).doesNotContain(notLettersOnly);
            });
        }

        @Test
        void namesTheDuplicateAndTheGroup_whenAnAttributeOfADisallowedGroupIsSentTwice() {
            // given
            var requested = List.of(value(PAGE, "1"), value(PAGE, "2"));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(LOCATION), requested);

            // then
            assertRefusalSays(check, "sent 2 times", VISIBLE_SIGNATURE);
        }

        @Test
        void namesEveryProblemInOneRefusal() {
            // given
            var undeclared = "data_contactInfo";
            var notLettersOnly = "Prague 1";
            var requested = List
                    .of(value(SUB_FILTER, "ETSI.CAdES.detached"), value(undeclared, "someone"),
                            value(REASON, "Approval"), value(REASON, "Review"), value(PAGE, "1"),
                            value(LOCATION, notLettersOnly));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, DEFINITIONS, Set.of(LOCATION, REASON), requested);

            // then
            assertRefusalSays(check, SUB_FILTER, undeclared, REASON, PAGE, VISIBLE_SIGNATURE, LOCATION);
        }
    }

    @Nested
    class UndeclaredAllowedNames {

        @Test
        void returnsNothing_whenEachNameIsADeclaredGroupOrAnUngroupedRequestAttribute() {
            // given
            var allowed = Set.of(VISIBLE_SIGNATURE, LOCATION);

            // when
            List<String> undeclared = RequestAttributesCheck.undeclaredAllowedNames(DEFINITIONS, allowed);

            // then
            assertThat(undeclared).isEmpty();
        }

        @Test
        void returnsAGroupedAttributesOwnName() {
            // when
            List<String> undeclared = RequestAttributesCheck.undeclaredAllowedNames(DEFINITIONS, Set.of(PAGE));

            // then
            assertThat(undeclared).containsExactly(PAGE);
        }

        @Test
        void returnsAProfileAttributesName() {
            // when
            List<String> undeclared = RequestAttributesCheck.undeclaredAllowedNames(DEFINITIONS, Set.of(SUB_FILTER));

            // then
            assertThat(undeclared).containsExactly(SUB_FILTER);
        }

        @Test
        void returnsANameTheFormatterDoesNotDeclare() {
            // given
            var unknown = "data_contactInfo";

            // when
            List<String> undeclared = RequestAttributesCheck.undeclaredAllowedNames(DEFINITIONS, Set.of(unknown));

            // then
            assertThat(undeclared).containsExactly(unknown);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static void assertRefusalSays(ThrowingCallable check, String... fragments) {
        assertThatThrownBy(check).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
            assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
            assertThat(refusal.clientMessage()).contains(fragments);
        });
    }

    private static DataAttributeV3 definition(String name, String group) {
        DataAttributeV3 definition = new DataAttributeV3();
        definition.setUuid(uuidOf(name).toString());
        definition.setName(name);
        definition.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel(name);
        properties.setGroup(group);
        definition.setProperties(properties);
        if (LOCATION.equals(name)) {
            definition
                    .setConstraints(List
                            .of(new RegexpAttributeConstraint("Letters only", "Location must hold letters only",
                                    LETTERS_ONLY)));
        }
        if (SCOPE.equals(name)) {
            properties.setList(true);
            definition
                    .setContent(List
                            .of(new StringAttributeContentV3("Document", "document"),
                                    new StringAttributeContentV3("Revision", "revision")));
        }
        return definition;
    }

    private static RequestAttribute value(String name, String data) {
        return new RequestAttributeV3(uuidOf(name), name, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3(data)));
    }

    private static RequestAttribute attributeCarrying(String name, List<BaseAttributeContentV3<?>> content) {
        return new RequestAttributeV3(uuidOf(name), name, AttributeContentType.STRING, content);
    }

    private static RequestAttribute v2Value(String name, String data) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setUuid(uuidOf(name));
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV2(data, data)));
        return attribute;
    }

    private static UUID uuidOf(String name) {
        return UUID.nameUUIDFromBytes(name.getBytes());
    }
}
