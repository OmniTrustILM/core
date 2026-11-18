package com.otilm.core.signing.contentsigning.formatting;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.constraint.RegexpAttributeConstraint;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.FileAttributeContentData;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.FileAttributeContentV3;
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

import static com.otilm.core.util.builders.DataAttributeV3Builder.aDataAttribute;
import static com.otilm.core.util.builders.RequestAttributeV3Builder.aCustomAttribute;
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
    private static final String SIGNER_IMAGE = "data_signerImage";
    private static final String LETTERS_ONLY = "^[A-Za-z ]+$";

    private static final ContentSigningFormattingDefinitions DEFINITIONS = new ContentSigningFormattingDefinitions(
            List.of(definition(SUB_FILTER, null)),
            List
                    .of(definition(PAGE, VISIBLE_SIGNATURE), definition(TEXT, VISIBLE_SIGNATURE),
                            definition(LOCATION, null), definition(REASON, null), definition(SCOPE, null)));

    // ── RequireAccepted ───────────────────────────────────────────────────────

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
            RequestAttributeV3 integerTypedString = aCustomAttribute()
                    .withUuid(uuidOf(LOCATION))
                    .withName(LOCATION)
                    .withStringContent("Prague")
                    .build();
            integerTypedString.setContentType(AttributeContentType.INTEGER);

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
        void refusesAFile_whenItsContentDataLacksAFileName() {
            // given
            var fileDefinition = definition(SIGNER_IMAGE, null);
            fileDefinition.setContentType(AttributeContentType.FILE);
            var definitions = new ContentSigningFormattingDefinitions(List.of(), List.of(fileDefinition));
            var withoutFileName = new FileAttributeContentData();
            withoutFileName.setContent("aW1hZ2U=");
            withoutFileName.setMimeType("image/png");
            RequestAttributeV3 image = aCustomAttribute().withUuid(uuidOf(SIGNER_IMAGE)).withName(SIGNER_IMAGE).build();
            image.setContentType(AttributeContentType.FILE);
            image.setContent(List.of(new FileAttributeContentV3(null, withoutFileName)));

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, definitions, Set.of(SIGNER_IMAGE), List.of(image));

            // then
            assertRefusalSays(check, SIGNER_IMAGE, "incomplete content data");
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
        void acceptsAValueOutsideTheOptions_whenTheListIsExtensible() {
            // given
            var extensibleScope = definition(SCOPE, null);
            extensibleScope.getProperties().setExtensibleList(true);
            var definitions = new ContentSigningFormattingDefinitions(List.of(), List.of(extensibleScope));
            var notAnOption = "amendment";

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, definitions, Set.of(SCOPE), List.of(value(SCOPE, notAnOption)));

            // then
            assertThatCode(check).doesNotThrowAnyException();
        }

        @Test
        void acceptsAValueOtherThanTheDefault_whenTheAttributeIsNotAList() {
            // given
            var scopeWithADefault = definition(SCOPE, null);
            scopeWithADefault.getProperties().setList(false);
            var definitions = new ContentSigningFormattingDefinitions(List.of(), List.of(scopeWithADefault));
            var notTheDefault = "amendment";

            // when
            ThrowingCallable check = () -> RequestAttributesCheck
                    .requireAccepted(PROFILE_NAME, definitions, Set.of(SCOPE), List.of(value(SCOPE, notTheDefault)));

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

    // ── UndeclaredAllowedNames ────────────────────────────────────────────────

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
            // given
            var allowed = Set.of(PAGE);

            // when
            List<String> undeclared = RequestAttributesCheck.undeclaredAllowedNames(DEFINITIONS, allowed);

            // then
            assertThat(undeclared).containsExactly(PAGE);
        }

        @Test
        void returnsAProfileAttributesName() {
            // given
            var allowed = Set.of(SUB_FILTER);

            // when
            List<String> undeclared = RequestAttributesCheck.undeclaredAllowedNames(DEFINITIONS, allowed);

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
        DataAttributeV3 definition = aDataAttribute().withUuid(uuidOf(name)).withName(name).build();
        DataAttributeProperties properties = definition.getProperties();
        properties.setGroup(group);
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
        return aCustomAttribute().withUuid(uuidOf(name)).withName(name).withStringContent(data).build();
    }

    private static RequestAttribute attributeCarrying(String name, List<BaseAttributeContentV3<?>> content) {
        RequestAttributeV3 attribute = aCustomAttribute().withUuid(uuidOf(name)).withName(name).build();
        attribute.setContent(content);
        return attribute;
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
