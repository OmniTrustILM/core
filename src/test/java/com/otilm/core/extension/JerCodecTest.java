package com.otilm.core.extension;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ValidationException;
import com.otilm.core.extension.ExtensionType.Choice;
import com.otilm.core.extension.ExtensionType.Member;
import com.otilm.core.extension.ExtensionType.Opaque;
import com.otilm.core.extension.ExtensionType.Primitive;
import com.otilm.core.extension.ExtensionType.Range;
import com.otilm.core.extension.ExtensionType.Repeated;
import com.otilm.core.extension.ExtensionType.Scalar;
import com.otilm.core.extension.ExtensionType.Structure;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Golden vectors come from an independent JER/DER implementation (asn1tools) rather than from this codec, so a shared
 * misreading of X.697 cannot make them pass.
 */
class JerCodecTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static Scalar of(Primitive primitive) {
        return new Scalar(primitive);
    }

    private static String der(String json, ExtensionType type) throws Exception {
        JsonNode value = MAPPER.readTree(json);
        return HexFormat.of().formatHex(JerCodec.encode(value, type)).toUpperCase();
    }

    // RFC 5280 Basic Constraints: cA defaulting to FALSE, then an optional non-negative path length.
    private static final Structure BASIC_CONSTRAINTS = new Structure(List
            .of(new Member("cA", of(Primitive.BOOLEAN), null, false, false, Boolean.FALSE),
                    new Member(
                            "pathLenConstraint", new Scalar(Primitive.INTEGER,
                                    List.of(new Range(java.math.BigInteger.ZERO, null)), List.of()),
                            null, false, true, null)));

    // A custom SEQUENCE with every scalar kind, a SEQUENCE OF CHOICE and an optional tagged member.
    private static final Structure SERVICE_ENTITLEMENT = new Structure(List
            .of(new Member("serviceId", new Scalar(Primitive.UTF8_STRING, List.of(), List.of(Range.of(5, 32)))),
                    new Member("tier", new Scalar(Primitive.INTEGER, List.of(Range.of(1, 3)), List.of())),
                    new Member("scopes", new Repeated(new Choice(
                            List.of(new Member("name", of(Primitive.IA5_STRING)), new Member("id", of(Primitive.OID)))),
                            false, List.of(Range.of(1, 8)))),
                    new Member("expires", of(Primitive.GENERALIZED_TIME), 0, false, true, null)));

    @Nested
    class GoldenVectors {

        @Test
        void basicConstraintsCaTruePathLenZero() throws Exception {
            assertThat(der("{\"cA\":true,\"pathLenConstraint\":0}", BASIC_CONSTRAINTS)).isEqualTo("30060101FF020100");
        }

        @Test
        void anEndEntityIsTheEmptySequence() throws Exception {
            assertThat(der("{}", BASIC_CONSTRAINTS)).isEqualTo("3000");
        }

        @Test
        void writingADefaultOmitsItRatherThanEncodingIt() throws Exception {
            // DER forbids encoding a DEFAULT value, so cA false is the same encoding as cA absent.
            assertThat(der("{\"cA\":false}", BASIC_CONSTRAINTS)).isEqualTo("3000");
        }

        @Test
        void serviceEntitlementWithEveryMember() throws Exception {
            assertThat(der("""
                    {"serviceId":"svc-billing","tier":1,
                     "scopes":[{"name":"read"},{"id":"1.3.6.1.4.1.99999.2.1"}],
                     "expires":"20271231235959Z"}
                    """, SERVICE_ENTITLEMENT))
                    .isEqualTo("30350C0B7376632D62696C6C696E670201013012160472656164060A2B0601040186"
                            + "8D1F0201800F32303237313233313233353935395A");
        }

        @Test
        void anOmittedOptionalMemberSimplyDoesNotAppear() throws Exception {
            assertThat(der("{\"serviceId\":\"svc-billing\",\"tier\":1,\"scopes\":[{\"name\":\"read\"}]}",
                    SERVICE_ENTITLEMENT)).isEqualTo("30180C0B7376632D62696C6C696E670201013006160472656164");
        }

        @Test
        void anImplicitlyTaggedOctetStringReplacesItsTag() throws Exception {
            Structure addr = new Structure(
                    List.of(new Member("ip", of(Primitive.OCTET_STRING), 7, false, false, null)));

            assertThat(der("{\"ip\":\"C0000200\"}", addr)).isEqualTo("30068704C0000200");
        }

        @Test
        void aSequenceOfTakesAnArray() throws Exception {
            assertThat(der("[5]", new Repeated(of(Primitive.INTEGER)))).isEqualTo("3003020105");
        }
    }

    @Nested
    class Refusals {

        @Test
        void aMemberTheExtensionDoesNotDeclare() {
            assertThatThrownBy(() -> der(
                    "{\"serviceId\":\"svc-x\",\"tier\":1," + "\"scopes\":[{\"name\":\"a\"}],\"region\":\"eu\"}",
                    SERVICE_ENTITLEMENT))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.region")
                    .hasMessageContaining("not a member");
        }

        @Test
        void aMissingRequiredMember() {
            assertThatThrownBy(() -> der("{\"serviceId\":\"svc-x\"}", SERVICE_ENTITLEMENT))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.tier")
                    .hasMessageContaining("required");
        }

        @Test
        void aValueOutsideTheModulesRange() {
            assertThatThrownBy(() -> der("{\"serviceId\":\"svc-x\",\"tier\":4,\"scopes\":[{\"name\":\"a\"}]}",
                    SERVICE_ENTITLEMENT))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.tier")
                    .hasMessageContaining("permitted range");
        }

        @Test
        void aStringOutsideTheModulesSize() {
            assertThatThrownBy(
                    () -> der("{\"serviceId\":\"svc\",\"tier\":1,\"scopes\":[{\"name\":\"a\"}]}", SERVICE_ENTITLEMENT))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.serviceId")
                    .hasMessageContaining("3 characters");
        }

        @Test
        void anAlternativeTheChoiceDoesNotOffer() {
            assertThatThrownBy(() -> der("{\"serviceId\":\"svc-x\",\"tier\":1,\"scopes\":[{\"nickname\":\"a\"}]}",
                    SERVICE_ENTITLEMENT))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.scopes[0].nickname")
                    .hasMessageContaining("not an alternative");
        }

        @Test
        void tooManyElementsForTheModulesSize() {
            String scopes = "{\"name\":\"a\"},".repeat(9);
            String value = "{\"serviceId\":\"svc-x\",\"tier\":1,\"scopes\":[" + scopes.substring(0, scopes.length() - 1)
                    + "]}";
            assertThatThrownBy(() -> der(value, SERVICE_ENTITLEMENT))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.scopes")
                    .hasMessageContaining("9 elements");
        }
    }

    @Nested
    class OpaqueMembers {

        @Test
        void anUndescribedMemberCarriesItsOwnDer() throws Exception {
            Structure withAny = new Structure(
                    List.of(new Member("type", of(Primitive.OID)), new Member("value", new Opaque("AttributeValue"))));

            assertThat(der("{\"type\":\"1.2.3\",\"value\":\"0C0474657374\"}", withAny))
                    .isEqualTo("300A06022A030C0474657374");
        }

        @Test
        void bytesThatAreNotDerAreRefused() {
            Structure withAny = new Structure(List.of(new Member("value", new Opaque("AttributeValue"))));

            assertThatThrownBy(() -> der("{\"value\":\"FFFF\"}", withAny))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("AttributeValue");
        }
    }

    @Nested
    class WrittenOrBytes {

        @Test
        void everyJerRootFormIsWritten() {
            for (String value : List
                    .of("{\"a\":1}", "[1]", "\"010203\"", "5", "-1", "true", "false", "null", "  {\"a\":1}", "\n[1]")) {
                assertThat(JerCodec.tryParse(value)).as(value).isPresent();
            }
        }

        @Test
        void aNumberThatIsAlsoCompleteDerIsBytes() {
            // 108 digits: a JSON integer, and base64 of 81 bytes that are a complete private-class DER value
            // (D7 4F + 79 content bytes). 1234 decodes to a length its bytes cannot fill, and a complete value
            // followed by anything is not one value.
            String bothReadings = "108" + "0".repeat(105);
            assertThat(JerCodec.tryParse(bothReadings)).isEmpty();
            assertThat(JerCodec.tryParse("1234")).isPresent();
            assertThat(JerCodec.tryParse(bothReadings + "0000")).isPresent();
        }

        @Test
        void base64DerIsBytes() {
            // First characters of base64 for the tag bytes an extension value can start with.
            // "1AEA" is D4 01 00, a private-class tag: base64 that begins with a digit and must still be bytes.
            for (String value : List
                    .of("MAYBAf8CAQA=", "BAMBAgM=", "AgEB", "AQH/", "oA==", "gA8y", "MBIWBA==", "1AEA")) {
                assertThat(JerCodec.tryParse(value)).as(value).isEmpty();
            }
            assertThat(JerCodec.tryParse("")).isEmpty();
            assertThat(JerCodec.tryParse(null)).isEmpty();
        }

        @Test
        void aValueThatBeginsAsJsonButIsMalformedIsRefusedWithTheReason() {
            // Base64 cannot begin with { [ " or -, so such a value was written, and its fault is reported rather
            // than passed on as bytes for the renderer to fail on.
            for (String value : List.of("{\"a\":1,}", "{\"a\":1,\"a\":2}", "{\"a\":1} x", "[1,2", "\"abc", "-")) {
                assertThatThrownBy(() -> JerCodec.tryParse(value))
                        .as(value)
                        .isInstanceOf(ValidationException.class)
                        .hasMessageContaining("not well-formed JSON");
            }
            assertThatThrownBy(() -> JerCodec.tryParse("{\"a\":1,\"a\":2}")).hasMessageContaining("Duplicate");
        }
    }

    @Nested
    class ComponentConstraints {

        private final Structure atLeastOne = new Structure(
                List
                        .of(new Member("a", of(Primitive.INTEGER), 0, false, true, null),
                                new Member("b", of(Primitive.INTEGER), 1, false, true, null)),
                false,
                List
                        .of(List.of(new ExtensionType.ComponentRule("a", ExtensionType.Presence.PRESENT, null)),
                                List.of(new ExtensionType.ComponentRule("b", ExtensionType.Presence.PRESENT, null))));

        @Test
        void oneSatisfiedAlternativeIsEnough() throws Exception {
            assertThat(der("{\"b\":2}", atLeastOne)).isEqualTo("3003810102");
        }

        @Test
        void noSatisfiedAlternativeIsRefusedNamingThem() {
            assertThatThrownBy(() -> der("{}", atLeastOne))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("must have a, or have b");
        }
    }

    @Nested
    class WrittenNull {

        private final Structure withMarker = new Structure(
                List.of(new Member("marker", of(Primitive.NULL), null, false, true, null)));

        @Test
        void aWrittenNullIsAnAsn1Null_notAnOmission() throws Exception {
            assertThat(der("{\"marker\":null}", withMarker)).isEqualTo("30020500");
            assertThat(der("{}", withMarker)).isEqualTo("3000");
        }

        @Test
        void aWrittenNullForAnotherTypeIsRefusedByThatType() {
            Structure optionalInteger = new Structure(
                    List.of(new Member("tier", of(Primitive.INTEGER), null, false, true, null)));

            assertThatThrownBy(() -> der("{\"tier\":null}", optionalInteger))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.tier")
                    .hasMessageContaining("whole number");
        }
    }

    @Nested
    class BitStringMembers {

        private final Structure withBits = new Structure(List.of(new Member("ku", of(Primitive.BIT_STRING))));

        @Test
        void aMisspeltLengthIsRefusedNotDefaulted() {
            // Ignored, "lenght" would leave every bit of the octet significant and encode 03 02 00 80 for a value
            // whose author meant one bit.
            assertThatThrownBy(() -> der("{\"ku\":{\"value\":\"80\",\"lenght\":1}}", withBits))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.ku.lenght")
                    .hasMessageContaining("value and length");
        }

        @Test
        void aLengthThatIsNotAWholeNumberIsRefusedNotCoerced() {
            for (String length : List.of("\"1\"", "1.5", "true")) {
                assertThatThrownBy(() -> der("{\"ku\":{\"value\":\"80\",\"length\":" + length + "}}", withBits))
                        .as(length)
                        .isInstanceOf(ValidationException.class)
                        .hasMessageContaining("$.ku.length");
            }
        }

        @Test
        void theSpelledMembersStillEncode() throws Exception {
            assertThat(der("{\"ku\":{\"value\":\"80\",\"length\":1}}", withBits)).isEqualTo("3004" + "03020780");
        }
    }

    @Nested
    class FixedSizeBitString {

        private final Structure eightBits = new Structure(
                List.of(new Member("ku", new Scalar(Primitive.BIT_STRING, List.of(), List.of(Range.of(8, 8))))));

        @Test
        void isWrittenAsItsOctetsAlone() throws Exception {
            // X.697 24.2: fixed size means the octets carry it; the size says how many bits count.
            assertThat(der("{\"ku\":\"80\"}", eightBits)).isEqualTo("3004" + "03020080");
        }

        @Test
        void theObjectFormIsStillAccepted() throws Exception {
            assertThat(der("{\"ku\":{\"value\":\"80\",\"length\":8}}", eightBits)).isEqualTo("3004" + "03020080");
        }

        @Test
        void theWrongNumberOfOctetsIsRefused() {
            assertThatThrownBy(() -> der("{\"ku\":\"8000\"}", eightBits))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("8 bits");
        }

        @Test
        void theObjectFormRequiresBothMembers() {
            Structure variable = new Structure(List.of(new Member("ku", of(Primitive.BIT_STRING))));
            for (String value : List.of("{\"ku\":{\"value\":\"80\"}}", "{\"ku\":{\"length\":1}}")) {
                assertThatThrownBy(() -> der(value, variable))
                        .as(value)
                        .isInstanceOf(ValidationException.class)
                        .hasMessageContaining("$.ku")
                        .hasMessageContaining("a length in bits");
            }
        }

        @Test
        void aVariableSizeBitStringRefusesTheBareForm() {
            Structure variable = new Structure(List.of(new Member("ku", of(Primitive.BIT_STRING))));
            assertThatThrownBy(() -> der("{\"ku\":\"80\"}", variable))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("fixed size");
        }
    }

    @Nested
    class StringSizes {

        @Test
        void countCharactersNotUtf16Units() throws Exception {
            // A character outside the basic plane is two UTF-16 units; SIZE (5) must still admit five characters.
            Scalar five = new Scalar(Primitive.UTF8_STRING, List.of(), List.of(Range.of(5, 5)));
            assertThat(der("\"abcd\\uD83D\\uDE00\"", five)).startsWith("0C08");
            assertThatThrownBy(() -> der("\"abcdef\"", five))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("6 characters");
        }
    }

    @Nested
    class NamedRefusals {

        private Structure of(String name, Primitive primitive) {
            return new Structure(List.of(new Member(name, JerCodecTest.of(primitive))));
        }

        @Test
        void anOidThatIsNotOne() {
            Structure oid = of("o", Primitive.OID);
            assertThatThrownBy(() -> der("{\"o\":\"1.2.x\"}", oid))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.o")
                    .hasMessageContaining("OBJECT IDENTIFIER");
        }

        @Test
        void textOutsideAStringTypesAlphabet() {
            Structure printable = of("s", Primitive.PRINTABLE_STRING);
            Structure ia5 = of("s", Primitive.IA5_STRING);
            assertThatThrownBy(() -> der("{\"s\":\"a@b\"}", printable))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.s")
                    .hasMessageContaining("PrintableString");
            assertThatThrownBy(() -> der("{\"s\":\"caf\u00e9\"}", ia5))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.s")
                    .hasMessageContaining("IA5String");
        }

        @Test
        void aGeneralizedTimeNotInDerForm() throws Exception {
            Structure time = of("t", Primitive.GENERALIZED_TIME);
            assertThat(der("{\"t\":\"20260101000000Z\"}", time)).isEqualTo("3011180F32303236303130313030303030305A");
            // X.690 11.7 keeps a fraction that is not zero and forbids trailing zeros in it.
            assertThat(der("{\"t\":\"20260101000000.5Z\"}", time)).startsWith("30131811");
            for (String value : List
                    .of("2026-01-01", "20260101000000+0100", "20260101000000", "20260101000000.0Z",
                            "20260101000000.50Z", "20260101000000.Z")) {
                assertThatThrownBy(() -> der("{\"t\":\"" + value + "\"}", time))
                        .as(value)
                        .isInstanceOf(ValidationException.class)
                        .hasMessageContaining("$.t")
                        .hasMessageContaining("DER form");
            }
            assertThatThrownBy(() -> der("{\"t\":\"20261301000000Z\"}", time))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("calendar");
        }

        @Test
        void anEmptyOpaqueValue() {
            Structure withAny = new Structure(List.of(new Member("value", new Opaque("AttributeValue"))));
            assertThatThrownBy(() -> der("{\"value\":\"\"}", withAny))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.value")
                    .hasMessageContaining("cannot be empty");
        }

        @Test
        void aPrimitiveUnderAnImplicitlyTaggedOpaqueMember() throws Exception {
            // An implicit tag replaces the INTEGER's own; nothing could read 83 01 01 back as one.
            Structure holder = new Structure(List.of(new Member("a", new Opaque("ORAddress"), 3, false, false, null)));
            assertThat(der("{\"a\":\"3000\"}", holder)).isEqualTo("3002A300");
            assertThatThrownBy(() -> der("{\"a\":\"020101\"}", holder))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.a")
                    .hasMessageContaining("must be a SEQUENCE");
        }
    }

    @Nested
    class DefaultLiterals {

        @Test
        void aDefaultMatchesOnlyAValueOfItsOwnType() throws Exception {
            Structure counted = new Structure(List
                    .of(new Member("v", new Scalar(Primitive.INTEGER, List.of(), List.of()), null, false, false,
                            BigInteger.valueOf(5))));
            assertThat(der("{\"v\":5}", counted)).isEqualTo("3000");
            assertThatThrownBy(() -> der("{\"v\":\"5\"}", counted))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("$.v");
        }
    }
}
