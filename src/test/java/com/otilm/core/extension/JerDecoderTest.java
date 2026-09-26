package com.otilm.core.extension;

import com.fasterxml.jackson.databind.JsonNode;
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
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JerDecoderTest {

    private static Scalar of(Primitive primitive) {
        return new Scalar(primitive);
    }

    private static final Structure BASIC_CONSTRAINTS = new Structure(List
            .of(new Member("cA", of(Primitive.BOOLEAN), null, false, false, Boolean.FALSE),
                    new Member("pathLenConstraint",
                            new Scalar(Primitive.INTEGER, List.of(new Range(BigInteger.ZERO, null)), List.of()), null,
                            false, true, null)));

    private static final Structure SERVICE_ENTITLEMENT = new Structure(List
            .of(new Member("serviceId", of(Primitive.UTF8_STRING)), new Member("tier", of(Primitive.INTEGER)),
                    new Member("scopes", new Repeated(new Choice(List
                            .of(new Member("name", of(Primitive.IA5_STRING)), new Member("id", of(Primitive.OID)))))),
                    new Member("expires", of(Primitive.GENERALIZED_TIME), 0, false, true, null)));

    // PrivateKeyUsagePeriod: both members optional and identically typed, told apart only by their tags.
    private static final Structure PKUP = new Structure(List
            .of(new Member("notBefore", of(Primitive.GENERALIZED_TIME), 0, false, true, null),
                    new Member("notAfter", of(Primitive.GENERALIZED_TIME), 1, false, true, null)));

    private static JsonNode decode(String hex, ExtensionType type) {
        return JerDecoder.decode(HexFormat.of().parseHex(hex), type);
    }

    private static void roundTrips(String hex, ExtensionType type) {
        assertThat(HexFormat.of().formatHex(JerCodec.encode(decode(hex, type), type)).toUpperCase()).isEqualTo(hex);
    }

    @Test
    void readsBasicConstraints() {
        assertThat(decode("30060101FF020100", BASIC_CONSTRAINTS)).hasToString("{\"cA\":true,\"pathLenConstraint\":0}");
    }

    @Test
    void anOmittedDefaultComesBackAsItsDefault() {
        assertThat(decode("3000", BASIC_CONSTRAINTS)).hasToString("{\"cA\":false}");
    }

    @Test
    void readsEveryMemberOfANestedSequence() {
        assertThat(decode("30350C0B7376632D62696C6C696E670201013012160472656164060A2B06010401868D1F0201"
                + "800F32303237313233313233353935395A", SERVICE_ENTITLEMENT))
                .hasToString("{\"serviceId\":\"svc-billing\",\"tier\":1,"
                        + "\"scopes\":[{\"name\":\"read\"},{\"id\":\"1.3.6.1.4.1.99999.2.1\"}],"
                        + "\"expires\":\"20271231235959Z\"}");
    }

    @Test
    void tellsTwoIdenticallyTypedOptionalMembersApartByTheirTags() {
        assertThat(decode("3011810F32303237313233313233353935395A", PKUP))
                .hasToString("{\"notAfter\":\"20271231235959Z\"}");
        assertThat(decode("3011800F32303237313233313233353935395A", PKUP))
                .hasToString("{\"notBefore\":\"20271231235959Z\"}");
    }

    @Test
    void anUndescribedMemberComesBackAsItsOwnDer() {
        Structure withAny = new Structure(
                List.of(new Member("type", of(Primitive.OID)), new Member("value", new Opaque("AttributeValue"))));

        assertThat(decode("300A06022A030C0474657374", withAny))
                .hasToString("{\"type\":\"1.2.3\",\"value\":\"0C0474657374\"}");
    }

    @Test
    void decodingThenEncodingReproducesTheSameBytes() {
        roundTrips("30060101FF020100", BASIC_CONSTRAINTS);
        roundTrips("3000", BASIC_CONSTRAINTS);
        roundTrips("30180C0B7376632D62696C6C696E670201013006160472656164", SERVICE_ENTITLEMENT);
        roundTrips("3011810F32303237313233313233353935395A", PKUP);
    }

    @Test
    void anOmittedDefaultBeforeAPresentMemberStillAligns() {
        // SEQUENCE { INTEGER 1 } is a path length with cA defaulted away, not a malformed cA. Keeping the
        // members aligned across an omission is the whole job of matching on type rather than on position.
        assertThat(decode("3003020101", BASIC_CONSTRAINTS)).hasToString("{\"cA\":false,\"pathLenConstraint\":1}");
    }

    @Test
    void bytesThatAreNotTheDeclaredTypeAreRefused() {
        assertThatThrownBy(() -> decode("020101", BASIC_CONSTRAINTS))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("not the SEQUENCE");
    }

    @Test
    void aMissingRequiredMemberIsRefused() {
        assertThatThrownBy(() -> decode("3000", SERVICE_ENTITLEMENT))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("$.serviceId")
                .hasMessageContaining("missing");
    }

    @Test
    void trailingComponentsTheTypeDoesNotDeclareAreRefused() {
        assertThatThrownBy(() -> decode("30090101FF0201000201FF", BASIC_CONSTRAINTS))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("more members");
    }

    @Test
    void whatIsNotDerIsRefused() {
        assertThatThrownBy(() -> decode("FFFF", BASIC_CONSTRAINTS))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("not valid DER");
    }

    @Test
    void anImplicitlyTaggedOpaqueSequenceIsReadBack() {
        // ORAddress in Name Constraints: the implicit tag replaced the SEQUENCE tag, and the type says only "opaque".
        // The encoding still records that it is constructed, which is what restores the SEQUENCE.
        Structure withOpaque = new Structure(
                List.of(new Member("x400Address", new Opaque("ORAddress"), 3, false, false, null)));
        String der = "3005" + "A303" + "020105"; // an implicitly tagged 3 around a sequence of the integer 5

        assertThat(decode(der, withOpaque)).hasToString("{\"x400Address\":\"3003020105\"}");
        roundTrips(der, withOpaque);
    }

    @Test
    void anImplicitlyTaggedOpaquePrimitiveIsRefused() {
        // 81 02 AB CD could be an OCTET STRING, an INTEGER or anything else primitive; nothing says which.
        Structure withOpaque = new Structure(
                List.of(new Member("blob", new Opaque("Anything"), 1, false, false, null)));

        assertThatThrownBy(() -> decode("3004" + "8102" + "ABCD", withOpaque))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("$.blob");
    }

    @Test
    void stringTypesAreToldApart() {
        // The reader lets UTF8String and IA5String sit in one optional run because their tags differ; the decoder
        // has to agree, or it would hand an IA5String to the UTF8String member.
        Structure two = new Structure(List
                .of(new Member("u", new Scalar(Primitive.UTF8_STRING), null, false, true, null),
                        new Member("i", new Scalar(Primitive.IA5_STRING))));

        assertThat(decode("3003" + "160161", two)).hasToString("{\"i\":\"a\"}");
    }

    @Test
    void aSetIsReadByTagWhateverOrderDerPutItsMembersIn() {
        // SET { a INTEGER, b BOOLEAN } encodes the BOOLEAN first (tag 1 sorts before tag 2); a positional walk
        // would report a missing.
        Structure set = new Structure(
                List.of(new Member("a", new Scalar(Primitive.INTEGER)), new Member("b", new Scalar(Primitive.BOOLEAN))),
                true);

        assertThat(decode("3106" + "0101FF" + "020105", set)).hasToString("{\"a\":5,\"b\":true}");
        roundTrips("31060101FF020105", set);
    }

    @Test
    void aFixedSizeBitStringReadsBackAsItsOctetsAlone() {
        Structure eightBits = new Structure(
                List.of(new Member("ku", new Scalar(Primitive.BIT_STRING, List.of(), List.of(Range.of(8, 8))))));

        assertThat(decode("300403020080", eightBits)).hasToString("{\"ku\":\"80\"}");
        roundTrips("300403020080", eightBits);
    }

    @Test
    void aVariableSizeBitStringReadsBackAsAnObject() {
        Structure variable = new Structure(List.of(new Member("ku", new Scalar(Primitive.BIT_STRING))));

        assertThat(decode("300403020780", variable)).hasToString("{\"ku\":{\"value\":\"80\",\"length\":1}}");
    }

    @Test
    void aTagOfAnotherClassIsNotTheMembersTag() {
        // [1] in a module is context-specific; APPLICATION 1 (41) and PRIVATE 1 (C1) are other types altogether.
        Structure tagged = new Structure(
                List.of(new Member("a", new Scalar(Primitive.INTEGER), 1, false, false, null)));

        assertThat(decode("3003810105", tagged)).hasToString("{\"a\":5}");
        for (String other : List.of("3003410105", "3003C10105")) {
            assertThatThrownBy(() -> decode(other, tagged)).as(other).isInstanceOf(ValidationException.class);
        }
    }
}
