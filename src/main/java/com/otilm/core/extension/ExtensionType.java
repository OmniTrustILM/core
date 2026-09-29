package com.otilm.core.extension;

import java.math.BigInteger;
import java.util.List;
import java.util.OptionalInt;

/**
 * The ASN.1 type of a certificate extension's value, as much of it as the platform needs to encode a value and check
 * it.
 *
 * <p>
 * This is the resolved form: type references are already inlined, so nothing here refers outward. It is an internal
 * model rather than a wire format - what an operator registers is the extension's ASN.1 module, and how that text
 * becomes this is the reader's business, not this model's.
 */
public sealed interface ExtensionType {

    /** The ASN.1 types whose values the platform can build from JSON. */
    enum Primitive {
        BOOLEAN,
        INTEGER,
        OID,
        UTF8_STRING,
        IA5_STRING,
        PRINTABLE_STRING,
        OCTET_STRING,
        BIT_STRING,
        GENERALIZED_TIME,
        NULL
    }

    /**
     * A member of a SEQUENCE, or an alternative of a CHOICE.
     *
     * @param tag the context tag number, or {@code null} when the member is untagged
     * @param explicit whether that tag wraps the member's own encoding rather than replacing its tag
     * @param defaultValue the DEFAULT, which DER forbids encoding, so writing it means omitting the member
     */
    record Member(String name, ExtensionType type, Integer tag, boolean explicit, boolean optional,
            Object defaultValue) {

        public Member(String name, ExtensionType type) {
            this(name, type, null, false, false, null);
        }
    }

    /** An inclusive bound, either end of which may be absent. {@code SIZE} and value ranges share the shape. */
    record Range(BigInteger min, BigInteger max) {

        public static Range of(long min, long max) {
            return new Range(BigInteger.valueOf(min), BigInteger.valueOf(max));
        }

        public boolean admits(BigInteger value) {
            return (min == null || value.compareTo(min) >= 0) && (max == null || value.compareTo(max) <= 0);
        }

        /**
         * The single length a SIZE union pins, if it pins exactly one. X.697 writes a fixed-size bit string as a bare
         * hexadecimal string and a variable-size one as an object, so the encoder and decoder both need this answer.
         */
        public static OptionalInt single(List<Range> ranges) {
            if (ranges.size() != 1) {
                return OptionalInt.empty();
            }
            Range only = ranges.get(0);
            boolean pinned = only.min() != null && only.min().equals(only.max()) && only.min().bitLength() < 31;
            return pinned ? OptionalInt.of(only.min().intValue()) : OptionalInt.empty();
        }

        /** Whether {@code value} falls in any of {@code ranges}; an empty list constrains nothing. */
        public static boolean anyAdmits(List<Range> ranges, long value) {
            BigInteger candidate = BigInteger.valueOf(value);
            return ranges.isEmpty() || ranges.stream().anyMatch(range -> range.admits(candidate));
        }
    }

    /**
     * A built-in type, optionally constrained. Both constraints are unions, because {@code SIZE (8 | 32)} is how RFC
     * 5280 states an iPAddress and {@code INTEGER (1 | 3)} is legal, and a single range cannot say either.
     */
    record Scalar(Primitive primitive, List<Range> valueRanges, List<Range> sizes) implements ExtensionType {

        public Scalar(Primitive primitive) {
            this(primitive, List.of(), List.of());
        }
    }

    /** What a component constraint says about one member: that it is present, absent, or holds a given value. */
    enum Presence {
        PRESENT,
        ABSENT,
        EQUALS
    }

    /** One clause of a {@code WITH COMPONENTS} constraint. {@code value} is set only for {@link Presence#EQUALS}. */
    record ComponentRule(String member, Presence presence, Object value) {
    }

    /**
     * A SEQUENCE or SET of declared members, addressed by name.
     *
     * @param componentAlternatives the {@code WITH COMPONENTS} constraint, as alternatives of which a value must
     * satisfy at least one; each alternative is a conjunction of rules. Empty means unconstrained. This is how a module
     * says "at least one of these", or "this member only when that one holds", which the members' own OPTIONAL and
     * DEFAULT cannot.
     */
    record Structure(List<Member> members, boolean set,
            List<List<ComponentRule>> componentAlternatives) implements ExtensionType {

        public Structure(List<Member> members) {
            this(members, false, List.of());
        }

        public Structure(List<Member> members, boolean set) {
            this(members, set, List.of());
        }
    }

    /** A SEQUENCE OF or SET OF: every element takes the same type, and the count is bounded by a SIZE union. */
    record Repeated(ExtensionType element, boolean set, List<Range> sizes) implements ExtensionType {

        public Repeated(ExtensionType element) {
            this(element, false, List.of());
        }
    }

    /** A CHOICE: the value names the alternative it takes. */
    record Choice(List<Member> alternatives) implements ExtensionType {
    }

    /**
     * A member the module does not describe - an ANY, or a type imported from a module the platform was not given. Its
     * value is written as DER and passed through, because nothing here can build it.
     */
    record Opaque(String asn1Name) implements ExtensionType {
    }
}
