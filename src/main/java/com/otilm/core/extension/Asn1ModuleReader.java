package com.otilm.core.extension;

import com.otilm.api.exception.ValidationException;
import com.otilm.core.extension.ExtensionType.Choice;
import com.otilm.core.extension.ExtensionType.ComponentRule;
import com.otilm.core.extension.ExtensionType.Member;
import com.otilm.core.extension.ExtensionType.Opaque;
import com.otilm.core.extension.ExtensionType.Presence;
import com.otilm.core.extension.ExtensionType.Primitive;
import com.otilm.core.extension.ExtensionType.Range;
import com.otilm.core.extension.ExtensionType.Repeated;
import com.otilm.core.extension.ExtensionType.Scalar;
import com.otilm.core.extension.ExtensionType.Structure;
import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.BinaryOperator;

/**
 * Reads the ASN.1 module an operator registers for an extension into the type the platform encodes against.
 *
 * <p>
 * The subset is the one certificate extensions are written in: SEQUENCE, SET, their OF forms, CHOICE, context tags, the
 * built-in types X.509 uses, and SIZE and value-range constraints. Anything else is refused by name, so an operator
 * learns their module needs narrowing rather than discovering later that a construct was quietly dropped.
 *
 * <p>
 * The X.680 rules the decoder depends on are enforced. A module with no tagging clause is EXPLICIT TAGS (13.3). A tag
 * on an untagged CHOICE or open type is explicit whatever the clause says, and IMPLICIT cannot be written on one
 * (31.2.7, 31.2.9). Where a member is OPTIONAL or DEFAULT, its tag must differ from every member that could follow it
 * in the same run, and a CHOICE's alternatives and a SET's members must all carry distinct tags (26.3, 27.3, 29.3) -
 * without that, an encoding cannot be read back to the members it came from, so such a module is refused rather than
 * registered undecodable.
 */
public final class Asn1ModuleReader {

    private static final Map<String, Primitive> BUILT_IN = Map
            .ofEntries(Map.entry("BOOLEAN", Primitive.BOOLEAN), Map.entry("INTEGER", Primitive.INTEGER),
                    Map.entry("NULL", Primitive.NULL), Map.entry("UTF8String", Primitive.UTF8_STRING),
                    Map.entry("IA5String", Primitive.IA5_STRING),
                    Map.entry("PrintableString", Primitive.PRINTABLE_STRING),
                    Map.entry("GeneralizedTime", Primitive.GENERALIZED_TIME));

    /** Deep enough for any extension anyone has written; a module that needs more is not one to register. */
    private static final int MAX_NESTING = 32;
    private static final int MAX_RANGES = 64;
    /** Inlining references can multiply a small module into a very large type; this caps what one may become. */
    private static final int MAX_RESOLVED_MEMBERS = 10_000;

    private final List<String> tokens = new ArrayList<>();
    private int at;
    private int nesting;
    private int resolvedMembers;
    private boolean implicitTags;
    private final Map<String, Node> assignments = new LinkedHashMap<>();
    private String rootName;

    private enum Kind {
        SCALAR,
        OPAQUE,
        REFERENCE,
        REPEATED,
        CHOICE,
        STRUCTURE
    }

    /**
     * One {@code WITH COMPONENTS} alternative as written. Without {@code ...} it is a full specification, and X.680
     * 51.8.7 reads every optional member it does not name as ABSENT; with {@code ...} it constrains only what it names.
     * The difference is resolved into rules once the members are known.
     */
    private record Spec(List<ComponentRule> rules, boolean full) {
    }

    /** The parse tree, before type references are resolved. */
    private static final class Node {

        private Kind kind;
        private Primitive primitive;
        private String reference;
        private List<Node> members;
        private Node element;
        private boolean set;
        private List<Range> valueRanges = List.of();
        private List<Range> sizes = List.of();
        private List<Spec> componentSpecs = List.of();
        private String name;
        private Integer tag;
        private Boolean explicit;
        private boolean optional;
        private Object defaultValue;
    }

    private Asn1ModuleReader(String module) {
        tokenise(module);
    }

    /** The type of the module's first assignment, which is the extension's own. */
    public static ExtensionType read(String module) {
        if (module == null || module.isBlank()) {
            throw new ValidationException("The extension's ASN.1 module is empty");
        }
        Asn1ModuleReader reader = new Asn1ModuleReader(module);
        reader.module();
        if (reader.rootName == null) {
            throw new ValidationException("The extension's ASN.1 module assigns no type");
        }
        return reader
                .resolve(reader.assignments.get(reader.rootName), null, new ArrayDeque<>(List.of(reader.rootName)));
    }

    // ---------- lexing ----------

    private void tokenise(String module) {
        StringBuilder word = new StringBuilder();
        for (String line : module.split("\n")) {
            String text = withoutComments(line);
            int i = 0;
            while (i < text.length()) {
                char ch = text.charAt(i);
                if (Character.isLetterOrDigit(ch) || ch == '-' || ch == '_') {
                    word.append(ch);
                    i++;
                } else {
                    flush(word);
                    String symbol = symbolAt(text, i);
                    if (symbol != null) {
                        tokens.add(symbol);
                    }
                    i += symbol == null ? 1 : symbol.length();
                }
            }
            flush(word);
        }
    }

    /**
     * X.680 12.6.3: a comment runs from {@code --} to the next {@code --} on the line, or to its end. Stopping at the
     * first delimiter would drop {@code (1..3)} from {@code INTEGER -- note -- (1..3)} without a word.
     */
    private static String withoutComments(String line) {
        StringBuilder out = new StringBuilder();
        int i = 0;
        while (i < line.length()) {
            int start = line.indexOf("--", i);
            if (start < 0) {
                out.append(line, i, line.length());
                break;
            }
            out.append(line, i, start).append(' ');
            int end = line.indexOf("--", start + 2);
            if (end < 0) {
                break;
            }
            i = end + 2;
        }
        return out.toString();
    }

    /**
     * The punctuation token starting at {@code i}: one of the multi-character symbols, a single character, or nothing
     * for whitespace.
     */
    private static String symbolAt(String text, int i) {
        for (String multi : List.of("...", "..", "::=")) {
            if (text.startsWith(multi, i)) {
                return multi;
            }
        }
        char ch = text.charAt(i);
        return Character.isWhitespace(ch) ? null : String.valueOf(ch);
    }

    private void flush(StringBuilder word) {
        if (!word.isEmpty()) {
            tokens.add(word.toString());
            word.setLength(0);
        }
    }

    private String peek() {
        return at < tokens.size() ? tokens.get(at) : "";
    }

    private String take() {
        if (at >= tokens.size()) {
            throw new ValidationException("The extension's ASN.1 module ends unexpectedly");
        }
        return tokens.get(at++);
    }

    private boolean accept(String token) {
        if (peek().equals(token)) {
            at++;
            return true;
        }
        return false;
    }

    private void require(String token) {
        if (!accept(token)) {
            throw new ValidationException(
                    "The extension's ASN.1 module has '%s' where '%s' belongs".formatted(peek(), token));
        }
    }

    // ---------- parsing ----------

    /**
     * {@code Name [{ definitive OID }] DEFINITIONS [IMPLICIT|EXPLICIT|AUTOMATIC TAGS] [EXTENSIBILITY IMPLIED] ::= BEGIN}.
     * Every clause is read, because a clause that is skipped is one whose meaning the encoding silently lacks.
     */
    private void module() {
        take();
        if (accept("{")) {
            while (!accept("}")) {
                take();
            }
        }
        require("DEFINITIONS");
        String tagging = null;
        boolean extensibility = false;
        while (!peek().equals("::=")) {
            String token = take();
            switch (token) {
                case IMPLICIT, EXPLICIT, AUTOMATIC -> {
                    require("TAGS");
                    tagging = token;
                }
                case "EXTENSIBILITY" -> {
                    require("IMPLIED");
                    extensibility = true;
                }
                default -> throw new ValidationException(
                        "The extension's ASN.1 module has '%s' in its header, which this platform does not support"
                                .formatted(token));
            }
        }
        require("::=");
        require("BEGIN");
        if (AUTOMATIC.equals(tagging)) {
            // AUTOMATIC TAGS assigns [0], [1], ... to every member, which this reader does not do; reading the
            // module as if the clause were absent would encode every member with the wrong tag.
            throw new ValidationException(
                    "The extension's ASN.1 module uses AUTOMATIC TAGS, which this platform does not support; "
                            + "write the tags out and declare IMPLICIT or EXPLICIT TAGS");
        }
        if (extensibility) {
            // Implied extensibility makes every SEQUENCE, SET and CHOICE open to members the module does not
            // name. Values are held to exactly the members it does, so the clause would mean something the
            // encoding does not honour.
            throw new ValidationException(
                    "The extension's ASN.1 module declares EXTENSIBILITY IMPLIED, which this platform does not "
                            + "support; its types are closed to the members they name");
        }
        implicitTags = IMPLICIT.equals(tagging);
        if (peek().equals("EXPORTS") || peek().equals("IMPORTS")) {
            throw new ValidationException(
                    (UNSUPPORTED_USE + "; a module must define every type it names").formatted(peek()));
        }
        while (!peek().equals("END") && at < tokens.size()) {
            String name = take();
            if (Character.isLowerCase(name.charAt(0))) {
                throw new ValidationException(("The extension's ASN.1 module assigns a value to '%s', which this "
                        + "platform does not support; only type assignments are read").formatted(name));
            }
            require("::=");
            if (assignments.containsKey(name)) {
                // A second assignment would silently replace the first, constraints and all.
                throw new ValidationException("The extension's ASN.1 module defines '%s' twice".formatted(name));
            }
            assignments.put(name, type());
            if (rootName == null) {
                rootName = name;
            }
        }
        require("END");
        if (at < tokens.size()) {
            // Text after END is either a second module or a mistake; either way it is not what was registered.
            throw new ValidationException(
                    "The extension's ASN.1 module has content after END, beginning '%s'".formatted(peek()));
        }
    }

    private Node type() {
        if (++nesting > MAX_NESTING) {
            throw new ValidationException(
                    "The extension's ASN.1 module nests types more than %d deep".formatted(MAX_NESTING));
        }
        try {
            return typeBody();
        } finally {
            nesting--;
        }
    }

    private Node typeBody() {
        Node node = new Node();
        String token = take();
        switch (token) {
            case "SEQUENCE", "SET" -> collection(node, token.equals("SET"));
            case "CHOICE" -> {
                node.kind = Kind.CHOICE;
                node.members = members();
            }
            case "OCTET" -> {
                require("STRING");
                node.kind = Kind.SCALAR;
                node.primitive = Primitive.OCTET_STRING;
            }
            case "BIT" -> {
                require("STRING");
                node.kind = Kind.SCALAR;
                node.primitive = Primitive.BIT_STRING;
            }
            case "OBJECT" -> {
                require("IDENTIFIER");
                node.kind = Kind.SCALAR;
                node.primitive = Primitive.OID;
            }
            case OPEN_TYPE -> {
                if (accept("DEFINED")) {
                    require("BY");
                    take();
                }
                node.kind = Kind.OPAQUE;
                node.reference = OPEN_TYPE;
            }
            default -> named(node, token);
        }
        if (node.kind == Kind.SCALAR && peek().equals("{")) {
            throw new ValidationException((UNSUPPORTED_USE + " on " + token).formatted("named numbers or bits"));
        }
        if (peek().equals("(")) {
            if (at + 1 < tokens.size() && tokens.get(at + 1).equals("WITH")) {
                componentConstraint(node);
            } else {
                constraint(node);
            }
        }
        return node;
    }

    /**
     * {@code (WITH COMPONENTS { ..., a PRESENT } | WITH COMPONENTS { ..., b (TRUE) })}: alternatives, each a
     * conjunction of PRESENT, ABSENT or a single value. This is the X.680 way to say what OPTIONAL and DEFAULT alone
     * cannot - "at least one of these", or "this member only when that one is asserted" - and the shipped modules need
     * exactly that to keep the rules RFC 5280 states in prose.
     */
    private void componentConstraint(Node node) {
        if (node.kind != Kind.STRUCTURE && node.kind != Kind.REFERENCE) {
            throw new ValidationException(
                    "The extension's ASN.1 module applies WITH COMPONENTS to something other than a SEQUENCE or SET");
        }
        require("(");
        List<Spec> specs = new ArrayList<>();
        do {
            require("WITH");
            require("COMPONENTS");
            require("{");
            List<ComponentRule> rules = new ArrayList<>();
            boolean full = true;
            do {
                if (accept("...")) {
                    full = false;
                } else {
                    componentRule(rules);
                }
            } while (accept(","));
            require("}");
            if (rules.isEmpty()) {
                throw new ValidationException(
                        "The extension's ASN.1 module has a WITH COMPONENTS that constrains nothing");
            }
            specs.add(new Spec(List.copyOf(rules), full));
        } while (accept("|"));
        require(")");
        node.componentSpecs = List.copyOf(specs);
    }

    private void componentRule(List<ComponentRule> rules) {
        String member = take();
        if (accept("PRESENT")) {
            rules.add(new ComponentRule(member, Presence.PRESENT, null));
        } else if (accept("ABSENT")) {
            rules.add(new ComponentRule(member, Presence.ABSENT, null));
        } else if (accept("(")) {
            rules.add(new ComponentRule(member, Presence.EQUALS, literal(take())));
            require(")");
        } else {
            throw new ValidationException(("The extension's ASN.1 module constrains component '%s' with "
                    + "'%s'; only PRESENT, ABSENT or a single value in parentheses are supported")
                    .formatted(member, peek()));
        }
    }

    /** Full specifications gain an ABSENT rule for every optional member they leave unnamed. */
    private static List<List<ComponentRule>> expand(List<Spec> specs, List<Member> members) {
        List<List<ComponentRule>> out = new ArrayList<>();
        for (Spec spec : specs) {
            List<ComponentRule> rules = new ArrayList<>(spec.rules());
            if (spec.full()) {
                Set<String> named = new HashSet<>();
                spec.rules().forEach(rule -> named.add(rule.member()));
                for (Member member : members) {
                    boolean omittable = member.optional() || member.defaultValue() != null;
                    if (omittable && !named.contains(member.name())) {
                        rules.add(new ComponentRule(member.name(), Presence.ABSENT, null));
                    }
                }
            }
            out.add(List.copyOf(rules));
        }
        return List.copyOf(out);
    }

    private void named(Node node, String token) {
        Primitive builtIn = BUILT_IN.get(token);
        if (builtIn != null) {
            node.kind = Kind.SCALAR;
            node.primitive = builtIn;
            return;
        }
        if (UNSUPPORTED_TYPES.contains(token) || !Character.isUpperCase(token.charAt(0))) {
            throw new ValidationException(UNSUPPORTED_USE.formatted("'" + token + "'"));
        }
        node.kind = Kind.REFERENCE;
        node.reference = token;
    }

    private void collection(Node node, boolean set) {
        node.set = set;
        if (peek().equals("SIZE") || peek().equals("(")) {
            constraint(node);
        }
        if (accept("OF")) {
            node.kind = Kind.REPEATED;
            node.element = type();
            return;
        }
        node.kind = Kind.STRUCTURE;
        node.members = members();
    }

    private List<Node> members() {
        List<Node> out = new ArrayList<>();
        Set<String> names = new HashSet<>();
        require("{");
        do {
            String name = take();
            if (name.equals("...")) {
                throw new ValidationException((UNSUPPORTED_USE + "; its types are closed to the members they name")
                        .formatted("an extension marker"));
            }
            if (!names.add(name)) {
                // A JSON object cannot carry the same key twice, so a value could never name both.
                throw new ValidationException(
                        "The extension's ASN.1 module names member '%s' twice in one type".formatted(name));
            }
            Integer tag = null;
            Boolean explicit = null;
            if (accept("[")) {
                tag = number(take());
                if (tag < 0) {
                    throw new ValidationException(
                            "The extension's ASN.1 module tags '%s' with [%d]; a tag number cannot be negative"
                                    .formatted(name, tag));
                }
                require("]");
                if (accept(EXPLICIT)) {
                    explicit = true;
                } else if (accept(IMPLICIT)) {
                    explicit = false;
                }
            }
            Node member = type();
            member.name = name;
            member.tag = tag;
            member.explicit = explicit;
            if (accept("OPTIONAL")) {
                member.optional = true;
            } else if (accept("DEFAULT")) {
                member.defaultValue = literal(take());
            }
            out.add(member);
        } while (accept(","));
        require("}");
        return out;
    }

    private static int number(String token) {
        try {
            return Integer.parseInt(token);
        } catch (NumberFormatException e) {
            throw new ValidationException(
                    "The extension's ASN.1 module has '%s' where a number belongs".formatted(token));
        }
    }

    private static Object literal(String token) {
        if (token.equals("TRUE")) {
            return Boolean.TRUE;
        }
        if (token.equals("FALSE")) {
            return Boolean.FALSE;
        }
        try {
            return new BigInteger(token);
        } catch (NumberFormatException e) {
            return token;
        }
    }

    /** {@code (SIZE (1..8))} and the bare {@code SIZE (1..8)} of a SEQUENCE OF, or a plain value range. */
    private void constraint(Node node) {
        boolean bare = peek().equals("SIZE");
        boolean size = bare;
        if (bare) {
            require("SIZE");
            require("(");
        } else {
            require("(");
            size = accept("SIZE");
            if (size) {
                require("(");
            }
        }
        List<Range> ranges = new ArrayList<>();
        do {
            BigInteger low = bound(take());
            BigInteger high = accept("..") ? bound(take()) : low;
            if (size && low != null && low.signum() < 0) {
                throw new ValidationException(
                        "The extension's ASN.1 module writes SIZE (%s); a size cannot be negative".formatted(low));
            }
            if (high != null && low != null && low.compareTo(high) > 0) {
                throw new ValidationException(
                        "The extension's ASN.1 module writes the range %s..%s backwards".formatted(low, high));
            }
            ranges.add(new Range(low, high));
            if (ranges.size() > MAX_RANGES) {
                throw new ValidationException(
                        "The extension's ASN.1 module unites more than %d ranges in one constraint"
                                .formatted(MAX_RANGES));
            }
        } while (accept("|"));
        require(")");
        if (!bare && size) {
            require(")");
        }
        if (size) {
            node.sizes = disjoint(ranges);
        } else {
            node.valueRanges = disjoint(ranges);
        }
    }

    private static BigInteger bound(String token) {
        if (token.equals("MAX") || token.equals("MIN")) {
            return null;
        }
        try {
            return new BigInteger(token);
        } catch (NumberFormatException e) {
            throw new ValidationException(
                    "The extension's ASN.1 module constrains a type with '%s', which is not a number".formatted(token));
        }
    }

    // ---------- resolution ----------

    private ExtensionType resolve(Node node, Node memberContext, Deque<String> inProgress) {
        return switch (node.kind) {
            case REFERENCE -> resolveReference(node, memberContext, inProgress);
            case SCALAR -> scalar(node.primitive, node.valueRanges, node.sizes, describe(node));
            case OPAQUE -> new Opaque(node.reference);
            case REPEATED -> {
                refuseIf(!node.valueRanges.isEmpty(), describe(node), "a value range");
                yield new Repeated(resolve(node.element, null, inProgress), node.set, node.sizes);
            }
            case CHOICE -> {
                List<Member> alternatives = memberList(node, inProgress);
                requireDistinctAlternatives(alternatives);
                yield new Choice(alternatives);
            }
            case STRUCTURE -> {
                List<Member> members = memberList(node, inProgress);
                if (node.set) {
                    // X.680 27.3: every member of a SET must carry a distinct tag - DER sorts them by tag, so the
                    // tag is the only thing that says which member a component is.
                    requireDistinctTags(members, "member", "a SET");
                } else {
                    requireDecodableOptionals(members);
                }
                List<List<ComponentRule>> alternatives = expand(node.componentSpecs, members);
                requireKnownComponents(alternatives, members);
                yield new Structure(members, node.set, alternatives);
            }
        };
    }

    /**
     * A reference the module does not define cannot be built, so it becomes opaque - except when it is tagged. A
     * reference to a type still being resolved is recursion, which the model does not represent and is refused. X.680
     * 31.2.7 makes a tag on an untagged CHOICE explicit even in an IMPLICIT module, so whether the tag wraps or
     * replaces depends on a type that is not here. Guessing would emit different bytes without saying so, which is
     * worse than refusing.
     */
    private ExtensionType resolveReference(Node node, Node memberContext, Deque<String> inProgress) {
        Node target = assignments.get(node.reference);
        boolean tagged = memberContext != null && memberContext.tag != null && memberContext.explicit == null;
        if (target == null && tagged) {
            throw new ValidationException(("The extension's ASN.1 module tags '%s' but does not define it, so "
                    + "its tagging cannot be determined; define it in the module, or tag it EXPLICIT or IMPLICIT")
                    .formatted(node.reference));
        }
        if (target == null) {
            // Still constrained, so a SIZE or range on a type the module does not define is refused, not dropped.
            return constrain(new Opaque(node.reference), node);
        }
        if (inProgress.contains(node.reference)) {
            // The resolved model is a finite tree; cutting the recursion to bytes would make the inner values take
            // hex where the module promises members, without saying so.
            throw new ValidationException(("The extension's ASN.1 module defines '%s' in terms of itself, which "
                    + "this platform does not support").formatted(node.reference));
        }
        inProgress.push(node.reference);
        try {
            return constrain(resolve(target, memberContext, inProgress), node);
        } finally {
            inProgress.pop();
        }
    }

    /**
     * A constraint written on a reference narrows the type it names: {@code Count (1..3)} with {@code Count ::=
     * INTEGER} admits 1 to 3. Where both the reference and the definition constrain the same thing, the value must
     * satisfy both, which for ranges is their intersection. A constraint the named type cannot carry is refused rather
     * than dropped.
     */
    private static ExtensionType constrain(ExtensionType resolved, Node reference) {
        boolean ranges = !reference.valueRanges.isEmpty();
        boolean sizes = !reference.sizes.isEmpty();
        boolean components = !reference.componentSpecs.isEmpty();
        if (!ranges && !sizes && !components) {
            return resolved;
        }
        String name = reference.reference;
        return switch (resolved) {
            case Scalar(var primitive, var definedRanges, var definedSizes) -> {
                refuseIf(components, name, "WITH COMPONENTS");
                yield scalar(primitive, intersect(definedRanges, reference.valueRanges, name),
                        intersect(definedSizes, reference.sizes, name), "'" + name + "'");
            }
            case Repeated(var element, var set, var definedSizes) -> {
                refuseIf(ranges || components, name, "a value range or WITH COMPONENTS");
                yield new Repeated(element, set, intersect(definedSizes, reference.sizes, name));
            }
            case Structure(var members, var set, var definedAlternatives) -> {
                refuseIf(ranges || sizes, name, "a value range or SIZE");
                if (!definedAlternatives.isEmpty()) {
                    throw new ValidationException(("The extension's ASN.1 module constrains '%s' with WITH COMPONENTS "
                            + "on both its definition and a reference to it; state the constraint once")
                            .formatted(name));
                }
                List<List<ComponentRule>> alternatives = expand(reference.componentSpecs, members);
                requireKnownComponents(alternatives, members);
                yield new Structure(members, set, alternatives);
            }
            case Choice ignored -> throw constraintRefusal(name, "a constraint; constrain its alternatives instead");
            case Opaque ignored -> throw constraintRefusal(name, "a constraint; it is not defined here");
        };
    }

    /**
     * A value range belongs to INTEGER and SIZE to the string types; on anything else the encoder would never consult
     * it, and a module registered with one would promise a rule that no value is held to.
     */
    private static Scalar scalar(Primitive primitive, List<Range> ranges, List<Range> sizes, String name) {
        boolean sized = switch (primitive) {
            case UTF8_STRING, IA5_STRING, PRINTABLE_STRING, OCTET_STRING, BIT_STRING -> true;
            default -> false;
        };
        refuseIf(!ranges.isEmpty() && primitive != Primitive.INTEGER, name, "a value range");
        refuseIf(!sizes.isEmpty() && !sized, name, "SIZE");
        return new Scalar(primitive, ranges, sizes);
    }

    private static String describe(Node node) {
        if (node.name != null) {
            return "'" + node.name + "'";
        }
        return node.kind == Kind.SCALAR ? node.primitive.name() : "a SEQUENCE OF";
    }

    private static void refuseIf(boolean condition, String name, String what) {
        if (condition) {
            throw constraintRefusal(name, what);
        }
    }

    private static ValidationException constraintRefusal(String name, String what) {
        return new ValidationException(
                "The extension's ASN.1 module applies %s to '%s', which that type cannot carry".formatted(what, name));
    }

    /**
     * Both constraints must hold, so the admitted values are those in some range of each: the pairwise overlaps. Both
     * sides are disjoint unions, so the result has fewer ranges than the two together, and a chain of constrained
     * references cannot grow it.
     */
    private static List<Range> intersect(List<Range> definition, List<Range> reference, String name) {
        if (definition.isEmpty()) {
            return reference;
        }
        if (reference.isEmpty()) {
            return definition;
        }
        List<Range> out = new ArrayList<>();
        for (Range a : definition) {
            for (Range b : reference) {
                overlap(a, b).ifPresent(out::add);
            }
        }
        if (out.isEmpty()) {
            throw new ValidationException(
                    "The extension's ASN.1 module constrains '%s' to a range that admits no value".formatted(name));
        }
        return disjoint(out);
    }

    /**
     * The same set of values as the fewest ranges: sorted, with overlapping and adjacent ones merged. A union written
     * as {@code (0..MAX | 0..MAX)} is one range, so repeating it through references costs nothing.
     */
    private static List<Range> disjoint(List<Range> ranges) {
        List<Range> sorted = new ArrayList<>(ranges);
        // An absent lower bound is MIN, so it sorts first.
        sorted.sort(Comparator.comparing(Range::min, Comparator.nullsFirst(Comparator.naturalOrder())));
        List<Range> out = new ArrayList<>();
        for (Range next : sorted) {
            Range last = out.isEmpty() ? null : out.getLast();
            boolean touches = last != null && (last.max() == null || next.min() == null
                    || last.max().add(BigInteger.ONE).compareTo(next.min()) >= 0);
            if (touches) {
                BigInteger max = last.max() == null || next.max() == null ? null : last.max().max(next.max());
                out.set(out.size() - 1, new Range(last.min(), max));
            } else {
                out.add(next);
            }
        }
        return List.copyOf(out);
    }

    /** The values both ranges admit, or empty when there are none. An absent bound admits everything on its side. */
    private static Optional<Range> overlap(Range a, Range b) {
        BigInteger min = tighter(a.min(), b.min(), BigInteger::max);
        BigInteger max = tighter(a.max(), b.max(), BigInteger::min);
        boolean admitsSomething = min == null || max == null || min.compareTo(max) <= 0;
        return admitsSomething ? Optional.of(new Range(min, max)) : Optional.empty();
    }

    private static BigInteger tighter(BigInteger a, BigInteger b, BinaryOperator<BigInteger> pick) {
        if (a == null) {
            return b;
        }
        return b == null ? a : pick.apply(a, b);
    }

    private List<Member> memberList(Node node, Deque<String> inProgress) {
        List<Member> out = new ArrayList<>();
        for (Node member : node.members) {
            if (++resolvedMembers > MAX_RESOLVED_MEMBERS) {
                throw new ValidationException("The extension's ASN.1 module resolves to more than %d members"
                        .formatted(MAX_RESOLVED_MEMBERS));
            }
            ExtensionType type = resolve(member, member, inProgress);
            boolean open = member.tag != null && choiceOrOpenType(member, new HashSet<>());
            if (open && Boolean.FALSE.equals(member.explicit)) {
                throw new ValidationException(("The extension's ASN.1 module tags '%s' IMPLICIT, but a CHOICE or "
                        + "open type has no tag of its own to replace; tag it EXPLICIT").formatted(member.name));
            }
            boolean explicit = member.explicit != null ? member.explicit : open || !implicitTags;
            if (member.defaultValue != null) {
                requireDefaultOfItsType(member, type);
            }
            out.add(new Member(member.name, type, member.tag, explicit, member.optional, member.defaultValue));
        }
        return out;
    }

    /**
     * X.680 31.2.7: a tag on an untagged CHOICE or open type is explicit even in an IMPLICIT module, because such a
     * type has no tag of its own for an implicit one to replace. Followed through references, since a member's type is
     * often a name.
     */
    private boolean choiceOrOpenType(Node node, Set<String> seen) {
        return switch (node.kind) {
            case CHOICE -> true;
            case OPAQUE -> OPEN_TYPE.equals(node.reference);
            case REFERENCE -> {
                Node target = assignments.get(node.reference);
                yield target != null && seen.add(node.reference) && choiceOrOpenType(target, seen);
            }
            default -> false;
        };
    }

    /** A DEFAULT is compared to written values, so a literal of another type would match nothing or the wrong thing. */
    private static void requireDefaultOfItsType(Node member, ExtensionType type) {
        if (!literalFits(member.defaultValue, type)) {
            throw new ValidationException(("The extension's ASN.1 module gives '%s' a DEFAULT of %s, which is not a "
                    + "value of its type; only BOOLEAN and INTEGER defaults within the member's range are supported")
                    .formatted(member.name, member.defaultValue));
        }
    }

    /** Whether a literal the module wrote - TRUE, FALSE or a number - is a value of the type it is compared with. */
    private static boolean literalFits(Object literal, ExtensionType type) {
        return type instanceof Scalar(var primitive, var ranges, var sizes) && switch (primitive) {
            case BOOLEAN -> literal instanceof Boolean;
            case INTEGER -> literal instanceof BigInteger value
                    && (ranges.isEmpty() || ranges.stream().anyMatch(range -> range.admits(value)));
            default -> false;
        };
    }

    /**
     * X.680 26.3: an OPTIONAL or DEFAULT member's tag must differ from the tags of every member that could follow it -
     * each later member up to and including the first mandatory one. Otherwise an encoding with the optional member
     * absent is indistinguishable from one with it present, and nothing could read it back.
     */
    private static void requireDecodableOptionals(List<Member> members) {
        for (int i = 0; i < members.size(); i++) {
            Member member = members.get(i);
            if (!member.optional() && member.defaultValue() == null) {
                continue;
            }
            Set<String> mine = leadingTags(member);
            for (int j = i + 1; j < members.size(); j++) {
                Member later = members.get(j);
                if (collide(mine, leadingTags(later))) {
                    throw new ValidationException(("The extension's ASN.1 module cannot be decoded: '%s' is "
                            + "optional and '%s' can follow it with the same tag, so an encoding could not tell "
                            + "them apart; tag one of them").formatted(member.name(), later.name()));
                }
                if (!later.optional() && later.defaultValue() == null) {
                    break;
                }
            }
        }
    }

    /** X.680 29.3: a CHOICE's alternatives must carry distinct tags, since the tag is all that selects one. */
    private static void requireDistinctAlternatives(List<Member> alternatives) {
        requireDistinctTags(alternatives, "alternative", "a CHOICE");
    }

    private static void requireDistinctTags(List<Member> members, String role, String of) {
        Set<String> seen = new HashSet<>();
        for (Member member : members) {
            Set<String> tags = leadingTags(member);
            if (tags.contains(ANY_TAG) && members.size() > 1 || tags.stream().anyMatch(seen::contains)) {
                throw new ValidationException(("The extension's ASN.1 module cannot be decoded: %s '%s' of %s "
                        + "shares its tag with another; tag them apart").formatted(role, member.name(), of));
            }
            seen.addAll(tags);
        }
    }

    /** A component constraint naming a member the structure does not have would hold or fail for no reason. */
    private static void requireKnownComponents(List<List<ComponentRule>> alternatives, List<Member> members) {
        Map<String, Member> byName = new LinkedHashMap<>();
        members.forEach(member -> byName.put(member.name(), member));
        for (List<ComponentRule> alternative : alternatives) {
            for (ComponentRule rule : alternative) {
                Member member = byName.get(rule.member());
                if (member == null) {
                    throw new ValidationException(
                            "The extension's ASN.1 module constrains component '%s', which the type does not declare"
                                    .formatted(rule.member()));
                }
                if (rule.presence() == Presence.EQUALS && !literalFits(rule.value(), member.type())) {
                    throw new ValidationException(("The extension's ASN.1 module requires '%s' to be %s, which is not "
                            + "a value of its type, so no value could satisfy it")
                            .formatted(rule.member(), rule.value()));
                }
            }
        }
    }

    /** A tag that matches anything: an undescribed member's, which could carry any type at all. */
    private static final String ANY_TAG = "*";
    private static final String OPEN_TYPE = "ANY";
    private static final String UNSUPPORTED_USE = "The extension's ASN.1 module uses %s, which this platform does not support";

    /**
     * X.680 built-in types outside the subset. Named here so that a module using one is refused by that name; as
     * unknown capitalised words they would otherwise read as references to types the module never defines.
     */
    private static final Set<String> UNSUPPORTED_TYPES = Set
            .of("UTCTime", "BMPString", "VisibleString", "ISO646String", "TeletexString", "T61String", "NumericString",
                    "UniversalString", "GeneralString", "GraphicString", "VideotexString", "ObjectDescriptor", "REAL",
                    "ENUMERATED", "EMBEDDED", "EXTERNAL", "CHARACTER", "RELATIVE-OID", "OID-IRI", "RELATIVE-OID-IRI",
                    "TIME", "DATE", "TIME-OF-DAY", "DATE-TIME", "DURATION", "INSTANCE", "CLASS", "TYPE-IDENTIFIER",
                    "ABSTRACT-SYNTAX");
    private static final String IMPLICIT = "IMPLICIT";
    private static final String EXPLICIT = "EXPLICIT";
    private static final String AUTOMATIC = "AUTOMATIC";

    /** The tags an encoding of {@code member} can begin with, as strings so classes cannot be confused. */
    private static Set<String> leadingTags(Member member) {
        if (member.tag() != null) {
            return Set.of("context:" + member.tag());
        }
        return leadingTags(member.type());
    }

    private static Set<String> leadingTags(ExtensionType type) {
        return switch (type) {
            case Opaque ignored -> Set.of(ANY_TAG);
            case Structure(var members, var set, var alternatives) -> Set.of(set ? "universal:17" : "universal:16");
            case Repeated(var element, var set, var sizes) -> Set.of(set ? "universal:17" : "universal:16");
            case Choice(var alternatives) -> {
                Set<String> all = new HashSet<>();
                alternatives.forEach(alternative -> all.addAll(leadingTags(alternative)));
                yield all;
            }
            case Scalar(var primitive, var ranges, var sizes) -> Set.of("universal:" + switch (primitive) {
                case BOOLEAN -> 1;
                case INTEGER -> 2;
                case BIT_STRING -> 3;
                case OCTET_STRING -> 4;
                case NULL -> 5;
                case OID -> 6;
                case UTF8_STRING -> 12;
                case PRINTABLE_STRING -> 19;
                case IA5_STRING -> 22;
                case GENERALIZED_TIME -> 24;
            });
        };
    }

    private static boolean collide(Set<String> a, Set<String> b) {
        return a.contains(ANY_TAG) || b.contains(ANY_TAG) || a.stream().anyMatch(b::contains);
    }
}
