package com.otilm.core.extension;

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
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Asn1ModuleReaderTest {

    private static ExtensionType read(String body) {
        return Asn1ModuleReader.read("M DEFINITIONS IMPLICIT TAGS ::= BEGIN\n" + body + "\nEND");
    }

    private static String encode(String json, ExtensionType type) throws Exception {
        return HexFormat
                .of()
                .formatHex(JerCodec.encode(new com.fasterxml.jackson.databind.ObjectMapper().readTree(json), type))
                .toUpperCase();
    }

    @Nested
    class ShippedExtensions {

        @Test
        void subjectKeyIdentifierIsABareOctetString() {
            ExtensionType type = read("""
                    SubjectKeyIdentifier ::= KeyIdentifier
                    KeyIdentifier ::= OCTET STRING""");

            assertThat(type).isEqualTo(new Scalar(Primitive.OCTET_STRING));
        }

        @Test
        void basicConstraintsCarriesItsDefaultAndItsLowerBound() throws Exception {
            ExtensionType type = read("""
                    BasicConstraints ::= SEQUENCE {
                         cA                      BOOLEAN DEFAULT FALSE,
                         pathLenConstraint       INTEGER (0..MAX) OPTIONAL }""");

            Structure structure = (Structure) type;
            assertThat(structure.members()).hasSize(2);
            assertThat(structure.members().get(0).defaultValue()).isEqualTo(Boolean.FALSE);
            assertThat(structure.members().get(1).optional()).isTrue();
            assertThat(((Scalar) structure.members().get(1).type()).valueRanges().get(0).min())
                    .isEqualTo(BigInteger.ZERO);
            assertThat(encode("{\"cA\":true,\"pathLenConstraint\":0}", type)).isEqualTo("30060101FF020100");
        }

        @Test
        void privateKeyUsagePeriodTagsBothMembersImplicitly() throws Exception {
            ExtensionType type = read("""
                    PrivateKeyUsagePeriod ::= SEQUENCE {
                         notBefore       [0]     GeneralizedTime OPTIONAL,
                         notAfter        [1]     GeneralizedTime OPTIONAL }""");

            Member notBefore = ((Structure) type).members().get(0);
            assertThat(notBefore.tag()).isZero();
            assertThat(notBefore.explicit()).isFalse();
            assertThat(encode("{\"notAfter\":\"20271231235959Z\"}", type))
                    .isEqualTo("3011810F32303237313233313233353935395A");
        }

        @Test
        void tlsFeatureIsASequenceOfIntegers() throws Exception {
            ExtensionType type = read("Features ::= SEQUENCE OF INTEGER");

            assertThat(type).isInstanceOf(Repeated.class);
            assertThat(encode("[5]", type)).isEqualTo("3003020105");
        }

        @Test
        void subjectDirectoryAttributesCarriesAnOpaqueValue() {
            ExtensionType type = read("""
                    SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF AttributeSet
                    AttributeSet ::= SEQUENCE {
                         type       OBJECT IDENTIFIER,
                         values     SET SIZE (1..MAX) OF ANY }""");

            Structure attribute = (Structure) ((Repeated) type).element();
            Repeated values = (Repeated) attribute.members().get(1).type();
            assertThat(values.set()).isTrue();
            assertThat(values.element()).isInstanceOf(Opaque.class);
        }
    }

    @Nested
    class Tagging {

        @Test
        void aTagOnAChoiceIsExplicitEvenInAnImplicitModule() {
            // X.680 31.2.7: the tag is what selects a CHOICE alternative, so replacing it would destroy it.
            ExtensionType type = read("""
                    GeneralSubtree ::= SEQUENCE { base [4] Name }
                    Name ::= CHOICE { rdnSequence RDNSequence }
                    RDNSequence ::= SEQUENCE OF ANY""");

            Member base = ((Structure) type).members().get(0);
            assertThat(base.type()).isInstanceOf(Choice.class);
            assertThat(base.explicit()).isTrue();
        }

        @Test
        void aModuleWithNoTaggingClauseIsExplicit() throws Exception {
            // X.680 13.3: an absent TagDefault means EXPLICIT TAGS. Read as implicit, the same member would encode
            // as 80 0F ... instead of A0 11 18 0F ..., and nothing would say so.
            ExtensionType type = Asn1ModuleReader.read("""
                    M DEFINITIONS ::= BEGIN
                    P ::= SEQUENCE { notBefore [0] GeneralizedTime OPTIONAL }
                    END""");

            assertThat(((Structure) type).members().get(0).explicit()).isTrue();
            assertThat(encode("{\"notBefore\":\"20260101000000Z\"}", type))
                    .isEqualTo("3013A011180F32303236303130313030303030305A");
        }

        @Test
        void anExplicitTagsClauseIsExplicit() {
            ExtensionType type = Asn1ModuleReader.read("""
                    M DEFINITIONS EXPLICIT TAGS ::= BEGIN
                    P ::= SEQUENCE { a [0] INTEGER }
                    END""");

            assertThat(((Structure) type).members().get(0).explicit()).isTrue();
        }

        @Test
        void automaticTagsIsRefusedByName() {
            assertThatThrownBy(() -> Asn1ModuleReader.read("""
                    M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
                    P ::= SEQUENCE { a INTEGER, b INTEGER }
                    END""")).isInstanceOf(ValidationException.class).hasMessageContaining("AUTOMATIC TAGS");
        }

        @Test
        void aTagOnAnOrdinaryTypeStaysImplicit() {
            ExtensionType type = read("Probe ::= SEQUENCE { dNSName [2] IA5String }");

            assertThat(((Structure) type).members().get(0).explicit()).isFalse();
        }

        @Test
        void aTaggedReferenceToAnUndefinedTypeIsRefusedRatherThanGuessed() {
            // Whether the tag wraps or replaces depends on whether ORAddress is a CHOICE, which is not here.
            assertThatThrownBy(() -> read("GeneralName ::= SEQUENCE { x400Address [3] ORAddress }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("ORAddress")
                    .hasMessageContaining("tagging cannot be determined");
        }

        @Test
        void anUndefinedTypeThatIsSaidToBeImplicitIsAccepted() {
            ExtensionType type = read("GeneralName ::= SEQUENCE { x400Address [3] IMPLICIT ORAddress }");

            Member member = ((Structure) type).members().get(0);
            assertThat(member.type()).isInstanceOf(Opaque.class);
            assertThat(member.explicit()).isFalse();
        }

        @Test
        void anUntaggedUndefinedTypeIsSimplyOpaque() {
            ExtensionType type = read("Probe ::= SEQUENCE { thing SomethingElse }");

            assertThat(((Structure) type).members().get(0).type()).isEqualTo(new Opaque("SomethingElse"));
        }
    }

    @Nested
    class Decodability {

        @Test
        void anOptionalFollowedBySameTagIsRefused() {
            // X.680 26.3. Encoded, {"b":5} would read back as {"a":5}: the optional member absorbs the component.
            assertThatThrownBy(() -> read("P ::= SEQUENCE { a INTEGER OPTIONAL, b INTEGER }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'a'")
                    .hasMessageContaining("'b'")
                    .hasMessageContaining("same tag");
        }

        @Test
        void aDefaultFollowedBySameTagIsRefused() {
            assertThatThrownBy(() -> read("P ::= SEQUENCE { a BOOLEAN DEFAULT FALSE, b BOOLEAN }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("same tag");
        }

        @Test
        void theRunEndsAtTheFirstMandatoryMember() {
            // c shares a's tag, but b is mandatory and sits between them, so an encoding is unambiguous.
            assertThat(read("P ::= SEQUENCE { a INTEGER OPTIONAL, b UTF8String, c INTEGER }")).isNotNull();
        }

        @Test
        void differentStringTypesAreDistinct() {
            assertThat(read("P ::= SEQUENCE { a UTF8String OPTIONAL, b IA5String }")).isNotNull();
        }

        @Test
        void tagsMakeAnOptionalRunDecodable() {
            assertThat(read("P ::= SEQUENCE { a [0] INTEGER OPTIONAL, b [1] INTEGER }")).isNotNull();
        }

        @Test
        void anOptionalOpaqueCollidesWithEverything() {
            // ANY can carry any tag, so nothing after it in the run can be told from it.
            assertThatThrownBy(() -> read("P ::= SEQUENCE { a ANY OPTIONAL, b INTEGER }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("same tag");
        }

        @Test
        void choiceAlternativesMustCarryDistinctTags() {
            assertThatThrownBy(() -> read("C ::= CHOICE { a IA5String, b IA5String }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("alternative 'b'");
            assertThat(read("C ::= CHOICE { a IA5String, b UTF8String }")).isNotNull();
            assertThat(read("C ::= CHOICE { a [0] IA5String, b [1] IA5String }")).isNotNull();
        }

        @Test
        void aChoiceInsideAnOptionalRunContributesAllItsTags() {
            assertThatThrownBy(() -> read("""
                    P ::= SEQUENCE { a Alt OPTIONAL, b INTEGER }
                    Alt ::= CHOICE { x IA5String, y INTEGER }"""))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("same tag");
        }
    }

    @Nested
    class ComponentConstraints {

        @Test
        void atLeastOneOfTwoOptionals() throws Exception {
            // The X.680 way to say what OPTIONAL alone cannot: {} is a legal SEQUENCE but not a legal value here.
            ExtensionType type = read("""
                    P ::= SEQUENCE { a [0] INTEGER OPTIONAL, b [1] INTEGER OPTIONAL }
                      (WITH COMPONENTS { ..., a PRESENT } | WITH COMPONENTS { ..., b PRESENT })""");

            assertThat(((Structure) type).componentAlternatives()).hasSize(2);
            assertThat(encode("{\"a\":1}", type)).isEqualTo("3003800101");
            assertThatThrownBy(() -> encode("{}", type))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("have a, or have b");
        }

        @Test
        void aFullSpecificationMakesUnnamedOptionalsAbsent() throws Exception {
            // X.680 51.8.7: without "...", a WITH COMPONENTS constrains every member, so b must be absent.
            ExtensionType full = read("""
                    P ::= SEQUENCE { a [0] INTEGER OPTIONAL, b [1] INTEGER OPTIONAL }
                      (WITH COMPONENTS { a PRESENT })""");
            ExtensionType partial = read("""
                    P ::= SEQUENCE { a [0] INTEGER OPTIONAL, b [1] INTEGER OPTIONAL }
                      (WITH COMPONENTS { ..., a PRESENT })""");

            assertThat(encode("{\"a\":1}", full)).isEqualTo("3003800101");
            assertThatThrownBy(() -> encode("{\"a\":1,\"b\":2}", full))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("omit b");
            assertThat(encode("{\"a\":1,\"b\":2}", partial)).isEqualTo("3006800101810102");
        }

        @Test
        void aMemberOnlyWhenAnotherHoldsAValue() throws Exception {
            ExtensionType type = read("""
                    P ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL }
                      (WITH COMPONENTS { ..., pathLen ABSENT } | WITH COMPONENTS { ..., cA (TRUE) })""");

            assertThat(encode("{}", type)).isEqualTo("3000");
            assertThat(encode("{\"cA\":true,\"pathLen\":0}", type)).isEqualTo("30060101FF020100");
            // pathLen without cA asserted, and with cA written as its default, both fail the same way.
            for (String value : List.of("{\"pathLen\":0}", "{\"cA\":false,\"pathLen\":0}")) {
                assertThatThrownBy(() -> encode(value, type))
                        .as(value)
                        .isInstanceOf(ValidationException.class)
                        .hasMessageContaining("omit pathLen, or have cA = true");
            }
        }

        @Test
        void aConstraintOnAnUndeclaredComponentIsRefused() {
            assertThatThrownBy(() -> read("P ::= SEQUENCE { a INTEGER } (WITH COMPONENTS { ..., b PRESENT })"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'b'");
        }

        @Test
        void aConstraintOnANonStructureIsRefused() {
            assertThatThrownBy(() -> read("P ::= INTEGER (WITH COMPONENTS { ..., a PRESENT })"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("WITH COMPONENTS");
        }

        @Test
        void setMembersMustCarryDistinctTags() {
            // DER sorts a SET by tag, so two members with the same tag could never be told apart when read back.
            assertThatThrownBy(() -> read("S ::= SET { a INTEGER, b INTEGER }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("a SET");
            assertThat(read("S ::= SET { a INTEGER, b BOOLEAN }")).isNotNull();
        }
    }

    @Nested
    class Constraints {

        @Test
        void aSizeUnionOnASequenceOfIsKept() throws Exception {
            ExtensionType type = read("F ::= SEQUENCE SIZE (1 | 3) OF INTEGER");

            assertThat(((Repeated) type).sizes()).hasSize(2);
            assertThat(encode("[1]", type)).isEqualTo("3003020101");
            assertThatThrownBy(() -> encode("[1,2]", type))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("2 elements");
        }

        @Test
        void aConstraintOnAReferenceNarrowsTheTypeItNames() throws Exception {
            // Ext ::= Count (1..3) with Count ::= INTEGER: the constraint narrows the type the reference names.
            ExtensionType type = read("Ext ::= Count (1..3)\nCount ::= INTEGER");

            assertThat(encode("2", type)).isEqualTo("020102");
            assertThatThrownBy(() -> encode("4", type))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("permitted range");
        }

        @Test
        void constraintsOnBothSidesIntersect() throws Exception {
            ExtensionType type = read("Ext ::= Count (5..20)\nCount ::= INTEGER (0..10)");

            assertThat(((Scalar) type).valueRanges()).containsExactly(Range.of(5, 10));
            assertThat(encode("7", type)).isEqualTo("020107");
            for (String outside : List.of("3", "12")) {
                assertThatThrownBy(() -> encode(outside, type)).as(outside).isInstanceOf(ValidationException.class);
            }
        }

        @Test
        void anEmptyIntersectionIsRefusedAtRegistration() {
            assertThatThrownBy(() -> read("Ext ::= Count (11..20)\nCount ::= INTEGER (0..10)"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("admits no value");
        }

        @Test
        void aComponentConstraintMayBeWrittenOnAReferenceToAStructure() throws Exception {
            ExtensionType type = read("""
                    Ext ::= Base (WITH COMPONENTS { ..., a PRESENT })
                    Base ::= SEQUENCE { a [0] INTEGER OPTIONAL, b [1] INTEGER OPTIONAL }""");

            assertThat(encode("{\"a\":1}", type)).isEqualTo("3003800101");
            assertThatThrownBy(() -> encode("{\"b\":1}", type)).isInstanceOf(ValidationException.class);
        }

        @Test
        void aConstraintTheNamedTypeCannotCarryIsRefused() {
            assertThatThrownBy(() -> read("Ext ::= Alt (1..3)\nAlt ::= CHOICE { x IA5String, y INTEGER }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'Alt'");
            assertThatThrownBy(() -> read("Ext ::= Base (SIZE (1..2))\nBase ::= SEQUENCE { a INTEGER }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'Base'");
        }

        @Test
        void aValueUnionOnAnIntegerIsKept() throws Exception {
            ExtensionType type = read("T ::= INTEGER (1 | 3)");

            assertThat(((Scalar) type).valueRanges()).hasSize(2);
            assertThat(encode("3", type)).isEqualTo("020103");
            assertThatThrownBy(() -> encode("2", type)).isInstanceOf(ValidationException.class);
        }

        @Test
        void aSizeUnionIsKeptAsAUnion() throws Exception {
            // RFC 5280 states an iPAddress as SIZE (8 | 32); one range cannot say it.
            ExtensionType type = read("Addr ::= OCTET STRING (SIZE (4 | 16))");

            assertThat(((Scalar) type).sizes()).hasSize(2);
            assertThat(encode("\"C0000200\"", type)).isEqualTo("0404C0000200");
            assertThatThrownBy(() -> encode("\"C00002\"", type)).isInstanceOf(ValidationException.class);
        }

        @Test
        void aValueRangeReachesTheEncoder() {
            ExtensionType type = read("Tier ::= INTEGER (1..3)");

            assertThatThrownBy(() -> encode("4", type))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("permitted range");
        }
    }

    @Nested
    class Refusals {

        @Test
        void anEmptyModule() {
            assertThatThrownBy(() -> Asn1ModuleReader.read("  "))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("empty");
        }

        @Test
        void aConstructOutsideTheSupportedSubset() {
            assertThatThrownBy(() -> read("Probe ::= SEQUENCE { thing INTEGER (SIZE (1..2)) } (WITH COMPONENTS { x })"))
                    .isInstanceOf(ValidationException.class);
        }

        @Test
        void aModuleNestedBeyondTheBudget() {
            String open = "SEQUENCE { m ".repeat(40);
            String close = " }".repeat(40);
            assertThatThrownBy(() -> read("P ::= " + open + "INTEGER" + close))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("nests types more than");
        }

        @Test
        void aModuleThatResolvesToTooManyMembers() {
            // Each level names the next twice, so resolving the chain doubles at every step.
            StringBuilder module = new StringBuilder("T0 ::= SEQUENCE { a T1, b T1 }\n");
            for (int i = 1; i < 20; i++) {
                int next = i + 1;
                module.append("T" + i + " ::= SEQUENCE { a [0] T" + next + ", b [1] T" + next + " }\n");
            }
            module.append("T20 ::= INTEGER");
            String text = module.toString();
            assertThatThrownBy(() -> read(text))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("more than");
        }

        @Test
        void aModuleWithoutEnd() {
            assertThatThrownBy(() -> Asn1ModuleReader.read("M DEFINITIONS ::= BEGIN P ::= INTEGER"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("END");
        }

        @Test
        void contentAfterEnd() {
            assertThatThrownBy(() -> Asn1ModuleReader.read("M DEFINITIONS ::= BEGIN P ::= INTEGER END Q ::= BOOLEAN"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("after END");
        }

        @Test
        void aTypeDefinedTwice() {
            // The second definition would otherwise replace the first, constraints and all.
            assertThatThrownBy(() -> read("P ::= INTEGER (1..3)\nP ::= INTEGER"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'P' twice");
        }

        @Test
        void aMemberNamedTwice() {
            assertThatThrownBy(() -> read("P ::= SEQUENCE { a INTEGER, a BOOLEAN }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'a' twice");
        }

        @Test
        void extensibilityImpliedIsRefusedByName() {
            // Every SEQUENCE, SET and CHOICE would be open to members the module does not name; values are held
            // to exactly the members it does, so the clause would mean something the encoding never honours.
            assertThatThrownBy(() -> Asn1ModuleReader.read("""
                    M DEFINITIONS IMPLICIT TAGS EXTENSIBILITY IMPLIED ::= BEGIN
                    P ::= SEQUENCE { a INTEGER }
                    END""")).isInstanceOf(ValidationException.class).hasMessageContaining("EXTENSIBILITY IMPLIED");
        }

        @Test
        void anUnknownHeaderClauseIsRefusedByName() {
            assertThatThrownBy(() -> Asn1ModuleReader.read("M DEFINITIONS INSTRUCTIONS ::= BEGIN P ::= INTEGER END"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'INSTRUCTIONS'");
        }

        @Test
        void aHeaderWithoutDefinitionsIsRefused() {
            assertThatThrownBy(() -> Asn1ModuleReader.read("M ::= BEGIN P ::= INTEGER END"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("DEFINITIONS");
        }

        @Test
        void aDefinitiveOidInTheHeaderIsAccepted() {
            assertThat(Asn1ModuleReader.read("""
                    M { iso(1) identified-organization(3) 6 } DEFINITIONS IMPLICIT TAGS ::= BEGIN
                    P ::= INTEGER
                    END""")).isNotNull();
        }

        @Test
        void aTruncatedModule() {
            assertThatThrownBy(() -> Asn1ModuleReader.read("M DEFINITIONS ::= BEGIN Probe ::= SEQUENCE {"))
                    .isInstanceOf(ValidationException.class);
        }
    }

    @Nested
    class RefusedByName {

        @Test
        void aBuiltInTypeOutsideTheSubset() {
            for (String type : List
                    .of("UTCTime", "BMPString", "VisibleString", "TeletexString", "NumericString", "REAL",
                            "ENUMERATED")) {
                assertThatThrownBy(() -> read("P ::= SEQUENCE { a " + type + " }"))
                        .as(type)
                        .isInstanceOf(ValidationException.class)
                        .hasMessageContaining("'" + type + "'")
                        .hasMessageContaining("does not support");
            }
        }

        @Test
        void imports() {
            assertThatThrownBy(() -> Asn1ModuleReader.read("""
                    M DEFINITIONS IMPLICIT TAGS ::= BEGIN
                    IMPORTS Name FROM PKIX1Explicit88;
                    P ::= SEQUENCE { a Name }
                    END""")).isInstanceOf(ValidationException.class).hasMessageContaining("IMPORTS");
        }

        @Test
        void aValueAssignment() {
            assertThatThrownBy(() -> read("P ::= INTEGER\nlimit INTEGER ::= 5"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("assigns a value to 'limit'");
        }

        @Test
        void namedNumbers() {
            assertThatThrownBy(() -> read("P ::= INTEGER { low(0), high(1) }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("named numbers or bits");
        }

        @Test
        void anExtensionMarker() {
            assertThatThrownBy(() -> read("P ::= SEQUENCE { a INTEGER, ... }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("extension marker");
        }

        @Test
        void aNegativeTag() {
            assertThatThrownBy(() -> read("P ::= SEQUENCE { a [-1] INTEGER }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("[-1]");
        }

        @Test
        void aConstraintTheTypeCannotCarry() {
            for (String module : List
                    .of("P ::= INTEGER (SIZE (1))", "P ::= SEQUENCE { a BOOLEAN (1..2) }",
                            "P ::= SEQUENCE (1..3) OF INTEGER", "P ::= UTF8String (1..3)",
                            "P ::= Count (SIZE (1))\nCount ::= INTEGER")) {
                assertThatThrownBy(() -> read(module))
                        .as(module)
                        .isInstanceOf(ValidationException.class)
                        .hasMessageContaining("cannot carry");
            }
        }

        @Test
        void aDefaultOutsideTheMembersRange() {
            assertThatThrownBy(() -> read("P ::= SEQUENCE { tier INTEGER (1..3) DEFAULT 5 }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("DEFAULT of 5");
            assertThat(read("P ::= SEQUENCE { tier INTEGER (1..3) DEFAULT 2 }")).isNotNull();
        }

        @Test
        void aDefaultOfAnotherType() {
            assertThatThrownBy(() -> read("P ::= SEQUENCE { a BOOLEAN DEFAULT 7 }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("DEFAULT of 7");
            assertThatThrownBy(() -> read("P ::= SEQUENCE { a UTF8String DEFAULT none }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("DEFAULT of none");
        }
    }

    @Nested
    class OpenTypeTagging {

        @Test
        void aTagOnAnOpenTypeIsExplicitInAnImplicitModule() throws Exception {
            // X.680 31.2.7: ANY has no tag of its own to replace, so [0] wraps the value it carries.
            ExtensionType holder = read("P ::= SEQUENCE { v [0] ANY }");
            assertThat(encode("{\"v\":\"020105\"}", holder)).isEqualTo("3005A003020105");
            assertThat(JerDecoder.decode(HexFormat.of().parseHex("3005A003020105"), holder))
                    .hasToString("{\"v\":\"020105\"}");
        }

        @Test
        void aTagOnAReferenceToAChoiceIsExplicit() throws Exception {
            ExtensionType tree = read("""
                    Tree ::= SEQUENCE { child [0] Node OPTIONAL }
                    Node ::= CHOICE { leaf [1] INTEGER, sub [2] SEQUENCE { count INTEGER } }""");
            assertThat(encode("{\"child\":{\"leaf\":5}}", tree)).isEqualTo("3005A003810105");
        }

        @Test
        void aRecursiveTypeIsRefusedByName() {
            // Cutting the recursion to bytes would make the inner values take hex where the module promises members.
            assertThatThrownBy(() -> read("""
                    Tree ::= SEQUENCE { child [0] Node OPTIONAL }
                    Node ::= CHOICE { leaf [1] INTEGER, sub [2] SEQUENCE { child [0] Node OPTIONAL } }"""))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'Node' in terms of itself");
        }

        @Test
        void aUnionOfRangesIsKeptDisjoint() throws Exception {
            // (1..3 | 2..5 | 7) is 1..5 and 7; the encoder sees two ranges, not three.
            ExtensionType type = read("P ::= INTEGER (1..3 | 2..5 | 7)");
            assertThat(encode("4", type)).isEqualTo("020104");
            assertThat(encode("7", type)).isEqualTo("020107");
            assertThatThrownBy(() -> encode("6", type)).isInstanceOf(ValidationException.class);
            assertThat(((Scalar) type).valueRanges()).hasSize(2);
        }

        @Test
        void aChainOfConstrainedReferencesDoesNotMultiplyRanges() {
            // Thirty aliases each adding (0..MAX | 0..MAX) would be 2^30 overlaps if unions were kept as written.
            StringBuilder module = new StringBuilder("P ::= A0 (0..MAX | 0..MAX)\n");
            for (int i = 0; i < 30; i++) {
                module.append("A%d ::= A%d (0..MAX | 0..MAX)".formatted(i, i + 1)).append('\n');
            }
            module.append("A30 ::= INTEGER\n");
            assertThat(((Scalar) read(module.toString())).valueRanges()).hasSize(1);
        }

        @Test
        void tooManyRangesInOneConstraintAreRefused() {
            String union = IntStream
                    .range(0, 65)
                    .mapToObj(i -> String.valueOf(i * 2))
                    .collect(Collectors.joining(" | "));
            assertThatThrownBy(() -> read("P ::= INTEGER (" + union + ")"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("more than 64 ranges");
        }

        @Test
        void aComponentLiteralOfAnotherType() {
            assertThatThrownBy(() -> read("P ::= SEQUENCE { enabled BOOLEAN } (WITH COMPONENTS { ..., enabled (7) })"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'enabled' to be 7");
            assertThatThrownBy(() -> read("P ::= SEQUENCE { tier INTEGER (1..3) } (WITH COMPONENTS { ..., tier (9) })"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'tier' to be 9");
        }

        @Test
        void aNegativeSize() {
            assertThatThrownBy(() -> read("P ::= OCTET STRING (SIZE (-1))"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("cannot be negative");
            assertThatThrownBy(() -> read("P ::= SEQUENCE SIZE (-2..4) OF INTEGER"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("cannot be negative");
        }

        @Test
        void aCommentEndsAtTheNextDelimiterOrTheLine() throws Exception {
            // X.680 12.6.3; the range after a closed comment is part of the type, the rest of an open one is not.
            for (String module : List
                    .of("P ::= INTEGER -- note -- (1..3)", "P ::= INTEGER -- a -- (1..3) -- tail (5..9)",
                            "P ::= INTEGER -- note\n  (1..3)")) {
                ExtensionType type = read(module);
                assertThat(encode("2", type)).as(module).isEqualTo("020102");
                assertThatThrownBy(() -> encode("4", type)).as(module).isInstanceOf(ValidationException.class);
            }
            assertThat(encode("4", read("P ::= INTEGER -- (1..3)"))).isEqualTo("020104");
        }

        @Test
        void aConstraintOnAnUndefinedReferenceIsRefused() {
            assertThatThrownBy(() -> read("P ::= SEQUENCE { a [0] EXPLICIT Foo (SIZE (1)) }"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'Foo'")
                    .hasMessageContaining("not defined here");
        }

        @Test
        void implicitWrittenOnAChoiceOrOpenTypeIsRefused() {
            for (String module : List
                    .of("P ::= SEQUENCE { g [0] IMPLICIT G }\nG ::= CHOICE { x [1] INTEGER }",
                            "P ::= SEQUENCE { v [0] IMPLICIT ANY }")) {
                assertThatThrownBy(() -> read(module))
                        .as(module)
                        .isInstanceOf(ValidationException.class)
                        .hasMessageContaining("IMPLICIT")
                        .hasMessageContaining("tag it EXPLICIT");
            }
        }

        @Test
        void implicitOnAnUndefinedReferenceIsStillHonoured() throws Exception {
            // ORAddress in the shipped Name Constraints is exactly this: a SEQUENCE the module does not spell out.
            ExtensionType holder = read("P ::= SEQUENCE { a [3] IMPLICIT ORAddress }");
            assertThat(encode("{\"a\":\"3000\"}", holder)).isEqualTo("3002A300");
        }
    }
}
