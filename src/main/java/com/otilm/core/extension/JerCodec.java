package com.otilm.core.extension;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectReader;
import com.otilm.api.exception.ValidationException;
import com.otilm.core.extension.ExtensionType.Choice;
import com.otilm.core.extension.ExtensionType.ComponentRule;
import com.otilm.core.extension.ExtensionType.Member;
import com.otilm.core.extension.ExtensionType.Opaque;
import com.otilm.core.extension.ExtensionType.Range;
import com.otilm.core.extension.ExtensionType.Repeated;
import com.otilm.core.extension.ExtensionType.Scalar;
import com.otilm.core.extension.ExtensionType.Structure;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.io.IOException;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encodes a JSON value of a known {@link ExtensionType} into DER, in the JSON Encoding Rules of ITU-T X.697.
 *
 * <p>
 * The type supplies everything the JSON cannot: which ASN.1 type each member has, what tag it carries and whether that
 * tag wraps or replaces. A value therefore names its members and nothing else - the same text encodes differently under
 * a different type, which is exactly why one must be registered before a value can be written at all.
 *
 * <p>
 * The type is also the only authority consulted. Where it does not determine something this refuses rather than
 * choosing, because a choice made here would encode something its author did not write.
 */
public final class JerCodec {

    private static final Logger logger = LoggerFactory.getLogger(JerCodec.class);
    private static final String VALUE = "value";
    private static final String LENGTH = "length";

    /**
     * Trailing text and duplicate keys are both silent losses otherwise: text after the first complete value is
     * discarded, and a repeated key collapses to the last, so a value would encode something other than what was
     * written.
     */
    private static final ObjectReader STRICT_READER = ObjectMapperFactory
            .wire()
            .reader()
            .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

    private JerCodec() {
    }

    /** The characters a written value can begin with that base64 never contains. */
    private static final Pattern GENERALIZED_TIME = Pattern.compile("\\d{14}(\\.\\d*[1-9])?Z");
    private static final DateTimeFormatter STRICT_TIME = DateTimeFormatter
            .ofPattern("uuuuMMddHHmmss")
            .withResolverStyle(ResolverStyle.STRICT);

    private static final String WRITTEN_STARTS = "{[\"-";

    /**
     * The value as JSON when it was written out, or empty when it was handed over as base64 DER.
     *
     * <p>
     * A value beginning with a brace, a bracket, a quote or a minus was written - base64 has none of them - and if it
     * then fails to parse, that is a fault to report rather than a reason to read it as bytes. The two grammars overlap
     * in exactly one place: a string of digits is a JSON number and may also be base64. Almost always it is base64 of
     * nothing - the second byte would be a DER length longer than the blob - but a long enough run can decode to a
     * complete DER value under a private-class tag. So the rule is DER-first where both readings exist: a number that
     * is also complete DER when read as base64 is bytes. Everything else that parses as JSON is written; base64 of any
     * length otherwise contains characters JSON cannot follow a digit with, and never parses.
     *
     * @throws ValidationException when the value begins as written JSON but is not well-formed
     */
    public static Optional<JsonNode> tryParse(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        String text = value.strip();
        boolean written = WRITTEN_STARTS.indexOf(text.charAt(0)) >= 0;
        JsonNode parsed;
        try {
            parsed = STRICT_READER.readTree(text);
        } catch (JsonProcessingException e) {
            if (written) {
                throw new ValidationException("Extension value is not well-formed JSON: " + e.getOriginalMessage());
            }
            return Optional.empty();
        }
        if (parsed == null || !written && parsed.isNumber() && isCompleteDer(text)) {
            return Optional.empty();
        }
        return Optional.of(parsed);
    }

    /** Whether {@code candidate} is base64 of exactly one complete DER value, with nothing after it. */
    private static boolean isCompleteDer(String candidate) {
        try {
            return ASN1Primitive.fromByteArray(java.util.Base64.getDecoder().decode(candidate)) != null;
        } catch (IllegalArgumentException | IOException e) {
            return false;
        }
    }

    public static byte[] encode(JsonNode value, ExtensionType type) {
        try {
            return encodable(value, type, "$").toASN1Primitive().getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new ValidationException("Extension value could not be encoded to DER");
        } catch (ValidationException e) {
            throw e;
        } catch (RuntimeException e) {
            // BouncyCastle rejects some values with its own unchecked exceptions, whose messages name library
            // internals and would otherwise reach a request client as a 500. Logged because arriving here means
            // either a shape this should have named or a defect.
            logger.warn("Encoding an extension value failed outside this codec's own checks", e);
            throw new ValidationException("Extension value could not be encoded to DER");
        }
    }

    private static ASN1Encodable encodable(JsonNode value, ExtensionType type, String path) {
        return switch (type) {
            case Scalar scalar -> scalar(value, scalar, path);
            case Structure structure -> structure(value, structure, path);
            case Repeated repeated -> repeated(value, repeated, path);
            case Choice choice -> choice(value, choice, path);
            case Opaque opaque -> opaque(value, opaque, path);
        };
    }

    /**
     * A member's tag is applied here rather than by the member's own type, which knows nothing about it. An implicit
     * tag replaces the value's own, and for an undescribed value nothing records what that was. A SEQUENCE is the one
     * shape that can be read back regardless, so anything else is refused rather than written as bytes that decode to a
     * different value.
     */
    private static ASN1Encodable tagged(ASN1Encodable encoded, Member member, String path) {
        if (member.tag() == null) {
            return encoded;
        }
        if (!member.explicit() && member.type() instanceof Opaque(var asn1Name) && !(encoded instanceof ASN1Sequence)) {
            throw refusal(path, ("must be a SEQUENCE: an implicit tag replaces the type of anything else, and %s "
                    + "does not say what it was").formatted(asn1Name));
        }
        return new DERTaggedObject(member.explicit(), member.tag(), encoded);
    }

    private static ASN1Encodable structure(JsonNode value, Structure type, String path) {
        if (!value.isObject()) {
            throw refusal(path, "must be an object naming the members");
        }
        // Before anything else: an unwritten member is usually one that was misspelt, and naming the
        // spelling points at the mistake where "the member it should have been is required" would not.
        rejectUndeclared(value, type.members(), path);
        ASN1EncodableVector members = new ASN1EncodableVector();
        for (Member member : type.members()) {
            JsonNode written = value.get(member.name());
            if (written == null) {
                // Absent means absent. A written null is not: it is the JER value of ASN.1 NULL, and for any
                // other type it is a wrong value the type's own check names.
                requirePresent(member, path);
            } else if (!isDefault(written, member)) {
                // A member written as its DEFAULT is left out, as DER requires; accepting it and omitting it is
                // kinder than refusing, since the author said what they meant.
                String memberPath = path + "." + member.name();
                members.add(tagged(encodable(written, member.type(), memberPath), member, memberPath));
            }
        }
        requireComponentAlternatives(value, type, path);
        return type.set() ? new DERSet(members) : new DERSequence(members);
    }

    /**
     * A value must satisfy at least one alternative of the type's {@code WITH COMPONENTS} constraint. A member written
     * as its DEFAULT counts as absent for PRESENT and ABSENT, since that is what it encodes to, but as holding that
     * value for an EQUALS rule, since that is what it means.
     */
    private static void requireComponentAlternatives(JsonNode value, Structure type, String path) {
        if (type.componentAlternatives().isEmpty()) {
            return;
        }
        for (List<ComponentRule> alternative : type.componentAlternatives()) {
            if (alternative.stream().allMatch(rule -> holds(rule, value, type))) {
                return;
            }
        }
        throw refusal(path, "must " + type
                .componentAlternatives()
                .stream()
                .map(alternative -> alternative.stream().map(JerCodec::describe).collect(Collectors.joining(" and ")))
                .collect(Collectors.joining(", or ")));
    }

    private static boolean holds(ComponentRule rule, JsonNode value, Structure type) {
        Member member = type.members().stream().filter(m -> m.name().equals(rule.member())).findFirst().orElse(null);
        JsonNode written = value.get(rule.member());
        boolean present = written != null && !(member != null && isDefault(written, member));
        return switch (rule.presence()) {
            case PRESENT -> present;
            case ABSENT -> !present;
            case EQUALS -> written != null
                    ? literalEquals(written, rule.value())
                    : member != null && member.defaultValue() != null
                            && Objects.equals(normalise(member.defaultValue()), normalise(rule.value()));
        };
    }

    private static String describe(ComponentRule rule) {
        return switch (rule.presence()) {
            case PRESENT -> "have " + rule.member();
            case ABSENT -> "omit " + rule.member();
            case EQUALS -> "have " + rule.member() + " = " + rule.value();
        };
    }

    private static void requirePresent(Member member, String path) {
        if (!member.optional() && member.defaultValue() == null) {
            throw refusal(path + "." + member.name(), "is required");
        }
    }

    private static boolean isDefault(JsonNode written, Member member) {
        return member.defaultValue() != null && literalEquals(written, member.defaultValue());
    }

    /** Whether a written JSON value is the ASN.1 literal a module wrote: TRUE, FALSE, a number, or a bare word. */
    private static boolean literalEquals(JsonNode written, Object literal) {
        if (literal instanceof Boolean flag) {
            return written.isBoolean() && written.booleanValue() == flag;
        }
        if (literal instanceof Number number) {
            return written.isIntegralNumber() && written.bigIntegerValue().equals(normalise(number));
        }
        return written.isTextual() && literal.toString().equals(written.textValue());
    }

    private static Object normalise(Object literal) {
        return literal instanceof Number number && !(number instanceof BigInteger)
                ? BigInteger.valueOf(number.longValue())
                : literal;
    }

    /**
     * An object leaf has a fixed vocabulary; a key outside it is a misspelling, and naming it points at the mistake.
     */
    private static void rejectUnknownMembers(JsonNode object, String path, String... allowed) {
        List<String> permitted = List.of(allowed);
        for (Iterator<String> names = object.fieldNames(); names.hasNext();) {
            String written = names.next();
            if (!permitted.contains(written)) {
                throw refusal(path + "." + written,
                        "is not a member here; the members are " + String.join(" and ", permitted));
            }
        }
    }

    private static void rejectUndeclared(JsonNode value, List<Member> declared, String path) {
        for (Iterator<String> names = value.fieldNames(); names.hasNext();) {
            String written = names.next();
            if (declared.stream().noneMatch(member -> member.name().equals(written))) {
                throw refusal(path + "." + written, "is not a member of this extension");
            }
        }
    }

    private static ASN1Encodable repeated(JsonNode value, Repeated type, String path) {
        if (!value.isArray()) {
            throw refusal(path, "must be an array");
        }
        requireSize(value.size(), type.sizes(), path, "elements");
        ASN1EncodableVector elements = new ASN1EncodableVector();
        int index = 0;
        for (JsonNode element : value) {
            elements.add(encodable(element, type.element(), "%s[%d]".formatted(path, index++)));
        }
        return type.set() ? new DERSet(elements) : new DERSequence(elements);
    }

    /** A CHOICE value names its alternative, which is the only thing that can select one. */
    private static ASN1Encodable choice(JsonNode value, Choice type, String path) {
        if (!value.isObject() || value.size() != 1) {
            throw refusal(path, "must name exactly one alternative");
        }
        String name = value.fieldNames().next();
        for (Member alternative : type.alternatives()) {
            if (alternative.name().equals(name)) {
                String alternativePath = path + "." + name;
                return tagged(encodable(value.get(name), alternative.type(), alternativePath), alternative,
                        alternativePath);
            }
        }
        throw refusal(path + "." + name, "is not an alternative of this choice");
    }

    private static ASN1Encodable opaque(JsonNode value, Opaque type, String path) {
        byte[] der = hex(value, path);
        if (der.length == 0) {
            throw refusal(path, "carries no DER; %s cannot be empty".formatted(type.asn1Name()));
        }
        try {
            return ASN1Primitive.fromByteArray(der);
        } catch (IOException e) {
            throw refusal(path, "is not valid DER, which is the only form %s can take here".formatted(type.asn1Name()));
        }
    }

    private static ASN1Encodable scalar(JsonNode value, Scalar type, String path) {
        return switch (type.primitive()) {
            case BOOLEAN -> ASN1Boolean.getInstance(bool(value, path));
            case INTEGER -> new ASN1Integer(integer(value, type.valueRanges(), path));
            case OID -> checked(value, type, path, "an OBJECT IDENTIFIER", ASN1ObjectIdentifier::new);
            case UTF8_STRING -> new DERUTF8String(text(value, type, path));
            case IA5_STRING -> checked(value, type, path, "an IA5String", written -> new DERIA5String(written, true));
            case PRINTABLE_STRING ->
                checked(value, type, path, "a PrintableString", written -> new DERPrintableString(written, true));
            case GENERALIZED_TIME -> generalizedTime(value, type, path);
            case OCTET_STRING -> octetString(value, type, path);
            case BIT_STRING -> bitString(value, type, path);
            case NULL -> derNull(value, path);
        };
    }

    /**
     * BouncyCastle refuses text outside a type's alphabet with a message naming its internals; this names the member.
     */
    private static ASN1Encodable checked(JsonNode value, Scalar type, String path, String asn1Type,
            Function<String, ASN1Encodable> constructor) {
        String written = text(value, type, path);
        try {
            return constructor.apply(written);
        } catch (IllegalArgumentException e) {
            throw refusal(path, "is not " + asn1Type);
        }
    }

    /**
     * X.690 11.7 fixes the DER form of a GeneralizedTime: UTC with a Z, seconds always present, and a fraction only
     * when it is not zero, with no trailing zeros. Anything else would go into the certificate as written.
     */
    private static ASN1Encodable generalizedTime(JsonNode value, Scalar type, String path) {
        String written = text(value, type, path);
        if (!GENERALIZED_TIME.matcher(written).matches()) {
            throw refusal(path, "must be a GeneralizedTime in DER form, YYYYMMDDHHMMSS[.fraction]Z with no trailing "
                    + "zeros in the fraction");
        }
        try {
            LocalDateTime.parse(written.substring(0, 14), STRICT_TIME);
        } catch (DateTimeParseException e) {
            throw refusal(path, "is not a calendar date and time");
        }
        return new DERGeneralizedTime(written);
    }

    private static ASN1Encodable octetString(JsonNode value, Scalar type, String path) {
        byte[] octets = hex(value, path);
        requireSize(octets.length, type.sizes(), path, "octets");
        return new DEROctetString(octets);
    }

    /**
     * X.697 gives a variable-length bit string as a value and a count of the bits that matter. The count is checked as
     * strictly as a member name: a misspelt {@code length} would otherwise fall back to every bit of the octets and
     * encode a different value than was written, and a non-integer count would be coerced rather than refused.
     */
    private static ASN1Encodable bitString(JsonNode value, Scalar type, String path) {
        OptionalInt fixed = Range.single(type.sizes());
        if (value.isTextual()) {
            // X.697 24.2: a bit string of fixed size is written as its octets alone, padded to a whole number of
            // them; the size says how many of the bits count.
            if (fixed.isEmpty()) {
                throw refusal(path, "must carry a hexadecimal value and a length in bits; only a bit string of "
                        + "fixed size is written as a bare string");
            }
            byte[] octets = hex(value, path);
            int expected = (fixed.getAsInt() + 7) / 8;
            if (octets.length != expected) {
                throw refusal(path, "must be %d bits, which is %d octets".formatted(fixed.getAsInt(), expected));
            }
            return new DERBitString(octets, octets.length * 8 - fixed.getAsInt());
        }
        if (!value.isObject()) {
            throw refusal(path, "must carry a hexadecimal value and a length in bits");
        }
        rejectUnknownMembers(value, path, VALUE, LENGTH);
        if (!value.has(VALUE) || !value.has(LENGTH)) {
            throw refusal(path, "must carry a hexadecimal value and a length in bits");
        }
        byte[] octets = hex(value.get(VALUE), path + "." + VALUE);
        JsonNode length = value.get(LENGTH);
        if (!length.isIntegralNumber() || !length.canConvertToInt()) {
            throw refusal(path + "." + LENGTH, "must be a whole number of bits");
        }
        int bits = length.intValue();
        if (bits < 0 || bits > octets.length * 8 || bits <= (octets.length - 1) * 8) {
            throw refusal(path + "." + LENGTH, "does not match the %d octets written".formatted(octets.length));
        }
        requireSize(bits, type.sizes(), path, "bits");
        return new DERBitString(octets, octets.length * 8 - bits);
    }

    private static ASN1Encodable derNull(JsonNode value, String path) {
        if (!value.isNull()) {
            throw refusal(path, "must be null; ASN.1 NULL carries no value");
        }
        return DERNull.INSTANCE;
    }

    private static boolean bool(JsonNode value, String path) {
        if (!value.isBoolean()) {
            throw refusal(path, "must be true or false");
        }
        return value.booleanValue();
    }

    private static BigInteger integer(JsonNode value, List<Range> ranges, String path) {
        if (!value.isIntegralNumber()) {
            throw refusal(path, "must be a whole number");
        }
        BigInteger written = value.bigIntegerValue();
        if (!ranges.isEmpty() && ranges.stream().noneMatch(range -> range.admits(written))) {
            throw refusal(path, "is outside the permitted range");
        }
        return written;
    }

    private static String text(JsonNode value, Scalar type, String path) {
        if (!value.isTextual()) {
            throw refusal(path, "must be a string");
        }
        String written = value.textValue();
        // SIZE on a character string counts characters, and a character outside the basic plane is two UTF-16
        // units - String.length would refuse a five-character value as six.
        requireSize(written.codePointCount(0, written.length()), type.sizes(), path, "characters");
        return written;
    }

    private static byte[] hex(JsonNode value, String path) {
        if (!value.isTextual()) {
            throw refusal(path, "must be a string of hexadecimal digits");
        }
        try {
            return HexFormat.of().parseHex(value.textValue());
        } catch (IllegalArgumentException e) {
            throw refusal(path, "is not an even-length string of hexadecimal digits");
        }
    }

    private static void requireSize(int actual, List<Range> permitted, String path, String unit) {
        if (!Range.anyAdmits(permitted, actual)) {
            throw refusal(path, "carries %d %s, which the extension does not permit".formatted(actual, unit));
        }
    }

    private static ValidationException refusal(String path, String reason) {
        return new ValidationException("Extension value at %s %s".formatted(path, reason));
    }
}
