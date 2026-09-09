package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.IntNode;
import com.fasterxml.jackson.databind.node.TextNode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The text primitives every keyed value passes through, and the places where Java's defaults are the wrong answer.
 *
 * <p>
 * Most of what is pinned here was caught by differential testing rather than by reading, and the cases share one shape:
 * a hashed value whose behaviour was inherited from a language primitive rather than decided. That is the failure class
 * this suite exists to freeze.
 *
 * <p>
 * Exotic code points are built with {@link Character#toString(int)} rather than written as literals. {@code U+0085 NEXT
 * LINE} reads as a line terminator to more than one Java source tool -- a file containing one literally cannot be
 * parsed by the formatter this project gates on, even though javac accepts it -- and a unicode escape does not help,
 * because escapes are resolved before the lexer runs.
 */
class TextNormalizationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // ---------------------------------------------------------------- ASCII folding

    /**
     * Folding is ASCII-only, so a non-ASCII character can never alias onto a registry token.
     *
     * <p>
     * {@code U+212A KELVIN SIGN} case-folds to ASCII {@code k} under Unicode rules, which would let a crafted name
     * claim a family it does not have. Under this fold it stays itself.
     */
    @Test
    void aUnicodeLookalikeCannotAliasOntoARegistryToken() {
        String kelvinSign = Character.toString(0x212A);

        assertThat(AsciiText.fold(kelvinSign)).isEqualTo(kelvinSign);
        assertThat(AsciiText.fold("KEM")).isEqualTo("kem");
    }

    /** Upper-casing is ASCII-only too, because a Unicode upper-case is length-changing on non-ASCII input. */
    @Test
    void upperCasingIsLengthPreserving() {
        String sharpS = Character.toString(0x00DF);

        assertThat(AsciiText.upper(sharpS))
                .describedAs("sharp s upper-cases to SS under Unicode rules")
                .isEqualTo(sharpS);
        assertThat(AsciiText.upper("gcm")).isEqualTo("GCM");
    }

    /** A Turkish-locale JVM must not key differently from any other node in the cluster. */
    @Test
    void foldingDoesNotDependOnThePlatformLocale() {
        assertThat(AsciiText.fold("KYBER-I")).isEqualTo("kyber-i");
        assertThat(AsciiText.upper("kyber-i")).isEqualTo("KYBER-I");
    }

    @ParameterizedTest
    @CsvSource({"'A-E-S', aes", "'a e s', aes", "'A_E_S', aes", "'AES', aes", "'p-256', p256"})
    void lookupKeysDropSeparatorsAndCase(String input, String expected) {
        assertThat(AsciiText.lookupKey(input)).isEqualTo(expected);
    }

    @Test
    void lookupKeysUseTheReferenceWhitespaceSet() {
        assertThat(AsciiText.lookupKey("A\u0085E\u00A0S\u2007G\u202FC\u200BM")).isEqualTo("aesgc\u200Bm");
    }

    // ---------------------------------------------------------------- whitespace

    /**
     * The whitespace stripped is the reference's, not the JDK's. These are the code points the two disagree on, and
     * {@code AsciiText.PYTHON_WHITESPACE} carries the measurement and the reason.
     */
    @ParameterizedTest
    @ValueSource(ints = {0x0085, 0x00A0, 0x2007, 0x202F})
    void theFourCodePointsJavaMissesAreStripped(int codePoint) {
        String character = Character.toString(codePoint);

        assertThat(Character.isWhitespace(codePoint))
                .describedAs("if this becomes true, the JDK changed and this rule can be simplified")
                .isFalse();
        assertThat(AsciiText.strip("RSA" + character)).isEqualTo("RSA");
        assertThat(AsciiText.isBlank(character)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(ints = {
            0x0020,
            0x0009,
            0x000A,
            0x000D,
            0x000B,
            0x000C,
            0x001C,
            0x1680,
            0x2000,
            0x200A,
            0x2028,
            0x2029,
            0x205F,
            0x3000})
    void theWhitespaceBothLanguagesAgreeOnIsStripped(int codePoint) {
        assertThat(AsciiText.strip("RSA" + Character.toString(codePoint))).isEqualTo("RSA");
    }

    /**
     * A zero-width space is whitespace to neither language, so it is <em>not</em> stripped.
     *
     * <p>
     * Pinned as a known limitation rather than as a desired behaviour. {@code "RSA"} followed by {@code U+200B} keys
     * apart from {@code "RSA"} in both implementations, which makes it a shared blind spot invisible to any
     * cross-implementation diff, not a divergence -- and a shared blind spot is the class that took reading a rule
     * against its own output to find, not a diff.
     *
     * <p>
     * <b>Measured, not assumed:</b> a sweep of all 200 validation-corpus documents -- wild, hold-out and local -- for
     * U+200B, U+200C, U+200D, U+2060, U+FEFF and U+00AD, raw and JSON-escaped, found <b>zero</b> occurrences. That
     * removes the urgency and answers nothing: a corpus is not production, and a zero-width character arrives by
     * copy-paste out of a browser or a word processor. Whether the ratified rule should STRIP such characters or REJECT
     * the document carrying them is open either way, and both choices re-key rows, which makes it a person's ruling and
     * a rule-set bump rather than either implementation's call. This test records the current answer and should change
     * only when that ruling exists.
     */
    @Test
    void aZeroWidthSpaceSurvivesInBothImplementations() {
        String zeroWidthSpace = Character.toString(0x200B);

        assertThat(AsciiText.strip("RSA" + zeroWidthSpace)).isEqualTo("RSA" + zeroWidthSpace);
        assertThat(AsciiText.isBlank(zeroWidthSpace)).isFalse();
    }

    @Test
    void runsOfWhitespaceCollapseToOneSpace() {
        assertThat(AsciiText.collapseWhitespace("a \t\n b")).isEqualTo("a b");
    }

    /**
     * Every text primitive treats an absent value as absent rather than throwing.
     *
     * <p>
     * A reducer reads a slot straight out of a producer's document, so every one of these is called with {@code null}
     * on ordinary input. A guard that is only exercised through a caller is a guard that moves when the caller does.
     */
    @Test
    void everyTextPrimitivePassesAbsenceThrough() {
        assertThat(AsciiText.fold(null)).isNull();
        assertThat(AsciiText.upper(null)).isNull();
        assertThat(AsciiText.lookupKey(null)).isNull();
        assertThat(AsciiText.strip(null)).isNull();
        assertThat(AsciiText.collapseWhitespace(null)).isNull();
        assertThat(AsciiText.isBlank(null)).isTrue();
    }

    /** The printable test is the ASCII range exactly: the control characters below it and everything above it fail. */
    @Test
    void printabilityIsTheAsciiRangeAndNothingElse() {
        assertThat(AsciiText.isAsciiPrintable("AES-256/GCM")).isTrue();
        assertThat(AsciiText.isAsciiPrintable("")).isTrue();
        assertThat(AsciiText.isAsciiPrintable("a\tb")).isFalse();
        assertThat(AsciiText.isAsciiPrintable("a" + Character.toString(0x7F) + "b")).isFalse();
        assertThat(AsciiText.isAsciiPrintable("caf\u00e9")).isFalse();
    }

    /**
     * The OID shape is digit groups separated by single dots, and nothing else.
     *
     * <p>
     * The grammar is scanned rather than matched because {@code \d+(\.\d+)*} recurses inside Java's matcher and
     * overflows the stack on a long enough input. These cases pin the grammar the scan implements, so a later move back
     * to a regex has something to answer to.
     */
    @Test
    void theDottedDigitShapeIsDigitGroupsSeparatedBySingleDots() {
        assertThat(AsciiText.isDottedDigits("1.2.840.113549", 3)).isTrue();
        assertThat(AsciiText.isDottedDigits("1.2", 1)).isTrue();

        assertThat(AsciiText.isDottedDigits("1.2", 3)).describedAs("too few arcs").isFalse();
        assertThat(AsciiText.isDottedDigits("1..2", 1)).describedAs("empty arc").isFalse();
        assertThat(AsciiText.isDottedDigits(".1.2", 1)).describedAs("leading dot").isFalse();
        assertThat(AsciiText.isDottedDigits("1.2.", 1)).describedAs("trailing dot").isFalse();
        assertThat(AsciiText.isDottedDigits("1.2a", 1)).describedAs("non-digit").isFalse();
        assertThat(AsciiText.isDottedDigits("", 0)).isFalse();
        assertThat(AsciiText.isDottedDigits(null, 0)).isFalse();
    }

    /** A digit is an ASCII digit, exactly as {@code \d} is by default -- so no keyed value moves with the locale. */
    @Test
    void anArabicIndicDigitIsNotADigitHere() {
        assertThat(AsciiText.isDottedDigits("1." + Character.toString(0x0661), 1)).isFalse();
    }

    // ---------------------------------------------------------------- slot escaping

    /**
     * A producer-controlled value cannot forge a slot boundary and impersonate another tier.
     *
     * <p>
     * A material id of {@code abc|F|x} otherwise renders {@code MAT|secret-key|I|abc|F|x}, which is exactly the shape a
     * fingerprint-tier asset emits.
     */
    @Test
    void aCraftedValueCannotForgeATierBoundary() {
        assertThat(PreImageSlot.of("abc|F|x")).isEqualTo("abc%7CF%7Cx");
    }

    @ParameterizedTest
    @CsvSource({"'a b', 'a%20b'", "'100%', '100%25'"})
    void theDelimiterSetIsEscaped(String input, String expected) {
        assertThat(PreImageSlot.of(input)).isEqualTo(expected);
    }

    @Test
    void controlDelimitersAreEscapedToo() {
        assertThat(PreImageSlot.of("a\tb")).isEqualTo("a%09b");
        assertThat(PreImageSlot.of("a\rb")).isEqualTo("a%0Db");
        assertThat(PreImageSlot.of("a\nb")).isEqualTo("a%0Ab");
    }

    /** Escaping is lossless, so no two distinct values are ever conflated by it. */
    @Test
    void escapingNeverConflatesTwoDistinctValues() {
        assertThat(PreImageSlot.of("a|b")).isNotEqualTo(PreImageSlot.of("a%7Cb"));
    }

    /** An absent value renders as the empty slot, which is distinct from every present value. */
    @Test
    void anAbsentValueIsDistinctFromEveryPresentOne() {
        assertThat(PreImageSlot.of((String) null)).isEmpty();
        assertThat(PreImageSlot.of("")).isEmpty();
        assertThat(PreImageSlot.of((Integer) null)).isEmpty();
        assertThat(PreImageSlot.of(Integer.valueOf(2048))).isEqualTo("2048");
    }

    // ---------------------------------------------------------------- timestamps

    /**
     * A spelling must not split a certificate, and parsing is case-insensitive because the reference's is.
     *
     * <p>
     * RFC 3339 permits a lowercase {@code t} separator and {@code z} zone and producers emit both. A case-sensitive
     * Java formatter left that spelling unparsed, keying the certificate on its <em>spelling</em> rather than on its
     * instant, and splitting it from every producer writing uppercase.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "2025-01-01T00:00:00Z",
            "2025-01-01T00:00:00.000Z",
            "2025-01-01t00:00:00z",
            "2025-01-01T00:00:00+00:00",
            "2025-01-01T02:00:00+02:00",
            "2025-01-01T02:00:00+0200",
            "2024-12-31T19:00:00-05:00",
            "20250101000000Z",
            "2025-01-01T00:00:00.123456789Z"})
    void everySpellingOfOneInstantFoldsToOneValue(String spelling) {
        assertThat(ValidityTimestamps.normalize(spelling)).isEqualTo("1735689600");
    }

    @Test
    void aSpaceSeparatedOffsetIsKeptRatherThanFolded() {
        assertThat(ValidityTimestamps.normalize("2025-01-01 02:00:00+02:00")).isEqualTo("2025-01-01 02:00:00+02:00");
    }

    /**
     * An unparseable value is returned cleaned rather than discarded: it is still a fact the producer stated, and two
     * certificates differing only there must not merge.
     */
    @Test
    void anUnparseableTimestampIsKeptRatherThanDropped() {
        assertThat(ValidityTimestamps.normalize("not-a-date")).isEqualTo("not-a-date");
        assertThat(ValidityTimestamps.normalize("release.1")).isEqualTo("release.1");
        assertThat(ValidityTimestamps.normalize("v1.2.3")).isEqualTo("v1.2.3");
        assertThat(ValidityTimestamps.normalize("")).isEmpty();
        assertThat(ValidityTimestamps.normalize(null)).isEmpty();
    }

    /**
     * A fraction is stripped from both accepted spellings, not only the extended one.
     *
     * <p>
     * {@code uuuuMMddHHmmss'Z'} is GeneralizedTime, where a fractional second is legal, so anchoring the fraction
     * pattern to the extended form alone left {@code 20250101000000.123Z} unparsed and keyed on its spelling -- the
     * split this class exists to prevent, reintroduced for the one format the corpus does not yet witness.
     */
    @Test
    void aFractionIsStrippedFromTheBasicSpellingToo() {
        assertThat(ValidityTimestamps.normalize("20250101000000.123Z")).isEqualTo("1735689600");
        assertThat(ValidityTimestamps.normalize("20250101000000Z")).isEqualTo("1735689600");
        assertThat(ValidityTimestamps.normalize("2025-01-01T00:00:00.123Z")).isEqualTo("1735689600");
    }

    @Test
    void calendarInvalidTimestampsStayLiteral() {
        assertThat(ValidityTimestamps.normalize("2025-02-28T00:00:00Z")).isEqualTo("1740700800");
        assertThat(ValidityTimestamps.normalize("2025-02-29T00:00:00Z")).isEqualTo("2025-02-29T00:00:00Z");
        assertThat(ValidityTimestamps.normalize("2025-02-30T00:00:00Z")).isEqualTo("2025-02-30T00:00:00Z");
        assertThat(ValidityTimestamps.normalize("2025-02-28T24:00:00Z")).isEqualTo("2025-02-28T24:00:00Z");
        assertThat(ValidityTimestamps.normalize("20250229000000Z")).isEqualTo("20250229000000Z");
    }

    @Test
    void anInstantIsAvailableWhereOneIsWantedRatherThanAKeyedString() {
        assertThat(ValidityTimestamps.instant("2025-01-01T00:00:00Z").getEpochSecond()).isEqualTo(1735689600L);
        assertThat(ValidityTimestamps.instant("not-a-date")).isNull();
        assertThat(ValidityTimestamps.instant(null)).isNull();
    }

    // ---------------------------------------------------------------- component names

    /**
     * A producer-generated identifier must not enter identity, or every row is rewritten on every scan.
     *
     * <p>
     * One producer names every secret-key asset {@code key@<random UUIDv4>}; all 33 reduce to one token, which is
     * exactly the desired behaviour.
     */
    @Test
    void generatedIdentifiersContributeNothing() {
        assertThat(ComponentNames.stableToken("key@ff11be02-d1ac-4887-9c11-000000000000"))
                .isEqualTo(ComponentNames.stableToken("key@0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"));
    }

    /** Thirty-two, not sixteen: a 16-hex-digit run is a plausible meaningful identifier. */
    @Test
    void aShortHexRunIsMeaningfulAndSurvives() {
        assertThat(ComponentNames.stableToken("key-0123456789abcdef"))
                .isNotEqualTo(ComponentNames.stableToken("key-fedcba9876543210"));
    }

    /** A separator survives only between two digits, the one place it carries meaning. */
    @Test
    void punctuationIsDroppedExceptBetweenDigits() {
        assertThat(ComponentNames.stableToken("key-12")).isNotEqualTo(ComponentNames.stableToken("key1-2"));
        assertThat(ComponentNames.stableToken("PrivateKey"))
                .isEqualTo(ComponentNames.stableToken("Private-Key"))
                .isEqualTo(ComponentNames.stableToken("Private_Key"));
    }

    @Test
    void anEmptyNameYieldsAnEmptyToken() {
        assertThat(ComponentNames.stableToken(null)).isEmpty();
        assertThat(ComponentNames.stableToken("   ")).isEmpty();
    }

    /** Address-shaped runs go before any digit is read as a size, IPv4 before port so host:port loses both halves. */
    @Test
    void addressShapedRunsAreRemovedBeforeAnyDigitIsRead() {
        assertThat(ComponentNames.stripOpaqueTokens("cert 192.168.56.10:636"))
                .doesNotContain("192")
                .doesNotContain("636");
        assertThat(ComponentNames.stripOpaqueTokens("protocol:tls:localhost:13443")).doesNotContain("13443");
    }

    // ---------------------------------------------------------------- occurrence locations

    /**
     * A location feeds the identity key for version-less protocols and identity-less material, so a credential in one
     * would be hashed into the key and stored in the evidence payload.
     */
    @Test
    void credentialsAndVolatilePartsNeverReachAKey() {
        assertThat(sanitize("tcp://user:pass@host:443/path")).isEqualTo("tcp://host:443/path");
        assertThat(sanitize("https://user:p@ss@host/path")).isEqualTo("https://host/path");
        assertThat(sanitize("https://user@a@b@host/path")).isEqualTo("https://host/path");
        assertThat(sanitize("https://host/path?token=secret")).isEqualTo("https://host/path");
        assertThat(sanitize("file:///a/b#fragment")).isEqualTo("file:///a/b");
    }

    @Test
    void anAbsentLocationIsTheEmptyString() {
        assertThat(Occurrences.sanitizeLocation((JsonNode) null)).isEmpty();
        assertThat(sanitize("   ")).isEmpty();
        assertThat(Occurrences.sanitizeLocation(new IntNode(7)))
                .describedAs("a location that is not a string states no location")
                .isEmpty();
    }

    /**
     * The cap counts code points rather than UTF-16 units.
     *
     * <p>
     * The reference counts characters, so an astral-heavy location was capped at 512 characters here and at 1024 there
     * -- one location, two keys. A location of 1024 astral characters is the shortest input that shows it.
     */
    @Test
    void theLocationLengthCapCountsCodePoints() {
        String astral = Character.toString(0x1F5DD);

        assertThat(sanitize("a".repeat(1023) + astral + "b")).isEqualTo("a".repeat(1023) + astral);
        assertThat(sanitize(astral.repeat(1024) + "b")).isEqualTo(astral.repeat(1024));
        assertThat(sanitize("a".repeat(2000))).hasSize(1024);
    }

    /** The cap is the last step, so no length of location can leave a credential behind it. */
    @Test
    void userInfoIsStrippedWhateverTheCapCounts() {
        String astral = Character.toString(0x1F5DD);
        String location = "tcp://" + astral.repeat(611) + ":SuperSecretPassword123@host:443/path";

        assertThat(sanitize(location)).doesNotContain("SuperSecret").isEqualTo("tcp://host:443/path");
    }

    /**
     * Every user-info goes, not only the first.
     *
     * <p>
     * One location can hold more than one URI, and {@code [^/?#]*} cannot cross a {@code /}, so a single replacement
     * left every credential after the first standing. This is the live path to the served {@code evidence} column, so
     * what survives is a stored, queryable secret.
     */
    @Test
    void everyUserInfoIsStrippedNotOnlyTheFirst() {
        assertThat(sanitize("jar:file://u1:p1@h1/a.jar!/https://u2:SECRET2@h2/b"))
                .isEqualTo("jar:file://h1/a.jar!/https://h2/b");
        assertThat(sanitize("kafka://u1:p1@b1:9092,kafka://u2:p2@b2:9092"))
                .isEqualTo("kafka://b1:9092,kafka://b2:9092");
        assertThat(sanitize("ldap://a:b@h1 ldap://c:d@h2")).isEqualTo("ldap://h1 ldap://h2");
        assertThat(sanitize("tcp://a@h/" + Character.toString(0x1F5DD).repeat(497) + "/https://user:PASSWORD123@e"))
                .describedAs("a larger cap must not preserve a credential the smaller one removed")
                .doesNotContain("PASSWORD123");
    }

    /**
     * A fragment-only location keeps its own text, because the empty string means absent.
     *
     * <p>
     * A CycloneDX occurrence inside an OpenAPI or JSON document carries a JSON pointer. Cutting at position zero made
     * every pointer the empty location, so they shared one discriminator with each other and with a component that
     * stated no location at all.
     */
    @Test
    void aFragmentOnlyLocationIsNotTheEmptyLocation() {
        assertThat(sanitize("#/components/schemas/PrivateKey")).isEqualTo("/components/schemas/PrivateKey");
        assertThat(sanitize("#/components/schemas/PrivateKey"))
                .isNotEqualTo(sanitize("#/components/schemas/PublicKey"));
        assertThat(sanitize("#L42")).isEqualTo("L42");
        assertThat(sanitize("a.py#L42")).describedAs("a trailing fragment on a real path still goes").isEqualTo("a.py");
    }

    /**
     * The kept pointer is a fragment, not a licence to keep a query.
     *
     * <p>
     * A location beginning with {@code ?} is a bare query string naming no place, so keeping it verbatim stored the
     * session token the query rule exists to drop -- and a pointer with a query of its own kept that token too.
     */
    @Test
    void aLeadingDelimiterNeverKeepsAQueryString() {
        assertThat(sanitize("?session=SECRETTOKEN&sig=HMACSECRET")).isEmpty();
        assertThat(sanitize("#/components/schemas/PrivateKey?session=SECRETTOKEN"))
                .isEqualTo("/components/schemas/PrivateKey");
        assertThat(sanitize("#frag?session=SECRETTOKEN")).isEqualTo("frag");
    }

    /**
     * A location made only of lone surrogates is refused, not fatal.
     *
     * <p>
     * {@link AsciiText#isBlank} does not treat a surrogate as whitespace, so such a location passed the entry guard;
     * the scrub then emptied it and the fragment rule read its first character, throwing
     * {@code StringIndexOutOfBoundsException} out of the ingest path with no {@code catch} between it and the source
     * upsert. On {@code main} the same input reached the digest guard and became a reported skip, so the step order
     * turned a diagnosable skip into an index error.
     */
    @ParameterizedTest
    @ValueSource(strings = {"\uD800", "\uDFFF", "\uD800\uD800", " \uD800 ", "\uDFFF\uD800"})
    void anAllSurrogateLocationIsRefusedRatherThanFatal(String location) {
        assertThat(sanitize(location)).isEmpty();
    }

    /**
     * The whole leading delimiter run comes off, so a doubled marker is not absence.
     *
     * <p>
     * Removing exactly one {@code #} left {@code ##a} cutting at position zero again and rendering as the empty
     * location -- the defect the retention exists to close, one character further along. What the rule does not restore
     * is the count: {@code #a} and {@code ##a} both render {@code a}, because the delimiter cannot come back into an
     * unescaped slot.
     */
    @Test
    void aLeadingDelimiterRunComesOffWhole() {
        assertThat(sanitize("##a")).isEqualTo("a");
        assertThat(sanitize("###/x")).isEqualTo("/x");
        assertThat(sanitize("##a")).isNotEqualTo(sanitize(""));
        assertThat(sanitize("#")).isEmpty();
        assertThat(sanitize("##")).isEmpty();
    }

    /**
     * A delimiter inside the authority does not hide the credential behind it.
     *
     * <p>
     * The user-info class excluded {@code ?} and {@code #}, so a password containing one put the {@code @} beyond the
     * pattern's reach and the cut then kept everything before the delimiter -- {@code //user:sec?ret@host/x} stored
     * {@code //user:sec}, and a password ending in {@code ?} stored whole. No step order repairs that: the class cannot
     * span a character it excludes.
     */
    @Test
    void aDelimiterInsideTheAuthorityDoesNotHideTheCredential() {
        assertThat(sanitize("//user:sec?ret@host/x")).isEqualTo("//host/x");
        assertThat(sanitize("https://user:sec?ret@host/x")).isEqualTo("https://host/x");
        assertThat(sanitize("//u:secret?@h")).isEqualTo("//h");
        assertThat(sanitize("//user:sec#ret@host/x")).isEqualTo("//host/x");
    }

    /**
     * A location nested past the pass bound names nothing, rather than costing unbounded CPU or keeping a credential.
     *
     * <p>
     * Stripping user-info once, or twice, is not stripping it. The replacement can create the shape it matches:
     * consuming {@code //u1:p1@} from {@code //u1:p1@/u2:p2@/u3:p3@host} leaves {@code ///u2:p2@…}, where the scan
     * resumes past the slash and finds only one before the next credential. Each pass peels one layer, so the two-pass
     * version left the third password in the key and in the served evidence column. Found by an exhaustive sweep the
     * hand-built cases missed.
     *
     * <p>
     * Each pass rescans the whole string and the cap is the last step, so {@code n} nested authorities cost {@code n}
     * passes over an uncapped location. Capping first is not available -- that is the truncation defect core#2165 item
     * 3 closed -- so the passes are bounded and what still matches afterwards is refused.
     */
    @Test
    void aLocationNestedPastTheBoundIsRefused() {
        String pathological = "//" + "u:p@/".repeat(64) + "host";

        assertThat(sanitize(pathological)).describedAs("refused, not partly stripped").isEmpty();
        assertThat(sanitize("//" + "u:p@/".repeat(8) + "host"))
                .describedAs("real depth still sanitizes")
                .doesNotContain("@")
                .endsWith("host");
    }

    @Test
    void userInfoIsStrippedToAFixpointRatherThanOnce() {
        assertThat(sanitize("//u1:p1@/u2:p2@/u3:p3@host")).isEqualTo("////host");
        assertThat(sanitize("#//u1:p1@/u2:p2@/u3:p3@host")).doesNotContain("p3").doesNotContain("@");
        assertThat(sanitize("file://user@/mnt@/root:toor@nas/x")).doesNotContain("toor").doesNotContain("@");
        assertThat(sanitize("//@/@/@")).isEqualTo("////");
    }

    /**
     * Keeping a pointer's text does not uncover a credential the anchored pattern could no longer see.
     *
     * <p>
     * Cutting the {@code #} off {@code #/api/v1//admin:hunter2@db.internal/x} moves the {@code //} into the middle of a
     * path, where a pattern anchored at the string start or after a colon does not match -- so the retention re-exposed
     * a credential {@code main} dropped, in the key and in the served evidence column alike.
     */
    @Test
    void aKeptPointerDoesNotUncoverACredential() {
        assertThat(sanitize("#/api/v1//admin:hunter2@db.internal:5432/x")).doesNotContain("hunter2");
        assertThat(sanitize("#x//user:secret@host")).isEqualTo("x//host");
        assertThat(sanitize("#//user:secret@host")).isEqualTo("//host");
    }

    /**
     * No sanitized location carries the triple's own separator.
     *
     * <p>
     * The location slot is the one slot {@link PreImageSlot} does not escape, so a location holding a {@code #} and a
     * newline renders as two triple lines and one occurrence impersonates two. Keeping a leading fragment's delimiter
     * re-opened this; keeping only its text closes it, because a {@code #} can then never reach the slot at all.
     */
    @Test
    void noSanitizedLocationCarriesTheTripleSeparator() {
        assertThat(sanitize("##\na")).doesNotContain("#").doesNotContain("\n");
        assertThat(sanitize("a\nb")).describedAs("the joiner is a newline and this slot is unescaped").isEqualTo("ab");
        assertThat(sanitize("#a##\nb#1#2")).doesNotContain("#");
        assertThat(Occurrences.triples(occurrences("[{\"location\": \"##\\na\"}]")))
                .describedAs("one occurrence cannot render as two triples")
                .isNotEqualTo(Occurrences.triples(occurrences("[{},{\"location\": \"a\"}]")));
    }

    /**
     * A network-path reference carries user-info too.
     *
     * <p>
     * {@code //user:secret@host/x} is a well-formed URI reference that {@code java.net.URI} parses with
     * {@code userInfo=user:secret}, and it is what a scanner emits for a protocol-relative URL. Anchoring the pattern
     * on a literal {@code ://} let it through.
     */
    @Test
    void aNetworkPathReferenceLosesItsCredentialToo() {
        assertThat(sanitize("//user:secret@host/x")).isEqualTo("//host/x");
        assertThat(sanitize("x://user:secret@host/x")).isEqualTo("x://host/x");
        assertThat(sanitize("kafka://u1:p1@b1:9092,kafka://u2:p2@b2:9092"))
                .describedAs("every credential, not the first")
                .isEqualTo("kafka://b1:9092,kafka://b2:9092");
    }

    /**
     * The surrogate scrub runs before the credential strip, because removal can create what the strip looks for.
     *
     * <p>
     * {@code x:\uD800//user:pass@host} does not match the user-info pattern. Scrubbing after the strip rendered
     * {@code x://user:pass@host} -- a well-formed location carrying the credential into the digest and the evidence
     * column, where the retained surrogate had previously made the whole string unhashable.
     */
    @Test
    void aSurrogateCannotSmuggleACredentialPastTheStrip() {
        assertThat(sanitize("x:\uD800//user:pass@host")).isEqualTo("x://host");
        assertThat(sanitize(":/\uD800/user:pass@host")).isEqualTo("://host");
        assertThat(sanitize("x://user:pass@host")).isEqualTo("x://host");
    }

    /** An unpaired surrogate has no UTF-8 encoding, so it reaches neither the digest nor the jsonb column. */
    @Test
    void anUnpairedSurrogateIsScrubbedWhereverItSits() {
        assertThat(sanitize("a\uD83Db")).isEqualTo("ab");
        assertThat(sanitize("a\uDE00b")).isEqualTo("ab");
        assertThat(sanitize("a".repeat(1023) + "\uD83D" + "b")).isEqualTo("a".repeat(1023) + "b");
        assertThat(sanitize("a" + Character.toString(0x1F5DD) + "b"))
                .describedAs("a well-formed pair is untouched")
                .isEqualTo("a" + Character.toString(0x1F5DD) + "b");
    }

    // ---------------------------------------------------------------- occurrence discriminator

    /**
     * Location alone under-discriminates, so the triple carries line and offset too.
     *
     * <p>
     * Measured on one producer's scan, 33 distinct secret keys occupied only 21 distinct location sets -- one source
     * file held five of them -- so a location-only discriminator silently merged twelve different secrets.
     */
    @Test
    void twoSecretsInOneFileAreNotMerged() {
        String first = Occurrences.triples(occurrences("[{\"location\": \"a.py\", \"line\": 1, \"offset\": 0}]"));
        String second = Occurrences.triples(occurrences("[{\"location\": \"a.py\", \"line\": 9, \"offset\": 0}]"));

        assertThat(first).isNotEqualTo(second);
    }

    /** The hashed string is exposed by name because a digest tells an implementer nothing about why it differs. */
    @Test
    void theDiscriminatorIsTheDigestOfTheExposedString() {
        JsonNode component = occurrences("[{\"location\": \"a.py\", \"line\": 1, \"offset\": 2}]");

        assertThat(Occurrences.triples(component)).isEqualTo("a.py#1#2");
        assertThat(Occurrences.discriminator(component)).isEqualTo(IdentityDigests.sha256Hex("a.py#1#2"));
    }

    /** Triples are sorted, but repeated sightings are kept because multiplicity is a stated fact. */
    @Test
    void arrayOrderDoesNotReachTheKeyButRepetitionDoes() {
        String ascending = Occurrences
                .triples(occurrences("[{\"location\": \"a.py\", \"line\": 1}, {\"location\": \"b.py\", \"line\": 2}]"));
        String descendingWithARepeat = Occurrences
                .triples(occurrences("[{\"location\": \"b.py\", \"line\": 2}, {\"location\": \"a.py\", \"line\": 1},"
                        + " {\"location\": \"b.py\", \"line\": 2}]"));

        assertThat(ascending).isEqualTo("a.py#1#\nb.py#2#");
        assertThat(descendingWithARepeat).isEqualTo("a.py#1#\nb.py#2#\nb.py#2#");
    }

    /**
     * An integral line renders through its exact integer value, never through a float's rendering of it.
     *
     * <p>
     * {@code JsonNode.asText()} on a large integral node can yield exponent notation, which would key the same line two
     * ways depending on how the producer serialized it. A non-integral line has no exact integer to render.
     */
    @Test
    void anIntegralLineRendersThroughItsExactValue() {
        assertThat(Occurrences.triples(occurrences("[{\"location\": \"a\", \"line\": 10000000000}]")))
                .isEqualTo("a#10000000000#");
        assertThat(Occurrences.triples(occurrences("[{\"location\": \"a\", \"line\": 1.5}]")))
                .describedAs("no exact integer exists, so the numeric value is refused")
                .isEqualTo("a#%3F#");
    }

    /**
     * A refused position is not an absent one.
     *
     * <p>
     * Rendering both as the empty slot would key an occurrence that stated an unusable line identically to one that
     * stated no line at all, and the empty slot means absent everywhere else in the chain. The sentinel cannot collide
     * with a producer value because {@link PreImageSlot} escapes a literal {@code %} before anything else.
     */
    @Test
    void aRefusedPositionKeysApartFromAnAbsentOne() {
        assertThat(Occurrences.triples(occurrences("[{\"location\": \"a\", \"line\": 1.5}]")))
                .isNotEqualTo(Occurrences.triples(occurrences("[{\"location\": \"a\"}]")));
        assertThat(Occurrences.triples(occurrences("[{\"location\": \"a\"}]"))).isEqualTo("a##");
        assertThat(Occurrences.triples(occurrences("[{\"location\": \"a\", \"line\": \"%3F\"}]")))
                .describedAs("a producer spelling the sentinel is escaped, so it cannot impersonate a refusal")
                .isEqualTo("a#%253F#");
    }

    /**
     * A position is rendered through its exact value, not through Jackson's node type.
     *
     * <p>
     * {@code isIntegralNumber} asks how the producer serialized the number, so every double-spelled line collapsed onto
     * one refusal: {@code 1.0} and {@code 2.0} keyed identically, and {@code 1e3} -- the line 1000 -- was refused for
     * its spelling. A producer whose JSON writer emits {@code 1.0} for an integer had its discriminator degraded to
     * location-only, which merges twelve of thirty-three distinct secret keys.
     */
    @Test
    void aPositionRendersThroughItsValueNotItsSpelling() {
        assertThat(Occurrences.triples(occurrences("[{\"location\": \"a\", \"line\": 1.0}]"))).isEqualTo("a#1#");
        assertThat(Occurrences.triples(occurrences("[{\"location\": \"a\", \"line\": 2.0}]"))).isEqualTo("a#2#");
        assertThat(Occurrences.triples(occurrences("[{\"location\": \"a\", \"line\": 1e3}]"))).isEqualTo("a#1000#");
        assertThat(Occurrences.triples(occurrences("[{\"location\": \"a\", \"line\": 0.0}]"))).isEqualTo("a#0#");
        assertThat(Occurrences.triples(occurrences("[{\"location\": \"a\", \"line\": 1.0}]")))
                .describedAs("two different lines must not key alike")
                .isNotEqualTo(Occurrences.triples(occurrences("[{\"location\": \"a\", \"line\": 2.0}]")));
        assertThat(Occurrences.triples(occurrences("[{\"location\": \"a\", \"line\": -1.5}]")))
                .describedAs("only a genuinely fractional position names no line")
                .isEqualTo("a#%3F#");
    }

    /**
     * An overflowing position is refused, not fatal.
     *
     * <p>
     * A JSON {@code 1e999} parses to {@code Infinity}, and {@code BigDecimal.valueOf(Infinity)} throws -- so rendering
     * the exact value threw {@code NumberFormatException} out of the reducer on a producer-controlled number. The
     * sentinel exists precisely so an unusable position cannot key as absent; it has to catch this one too.
     */
    @Test
    void anOverflowingPositionReachesTheSentinelRatherThanThrowing() {
        assertThat(Occurrences.triples(occurrences("[{\"location\": \"a\", \"line\": 1e999}]"))).isEqualTo("a#%3F#");
        assertThat(Occurrences.triples(occurrences("[{\"location\": \"a\", \"line\": -1e999}]"))).isEqualTo("a#%3F#");
    }

    @Test
    void triplesSortByCodePointNotUtf16StorageUnits() {
        String supplementary = Character.toString(0x10000);
        String privateUse = Character.toString(0xE000);

        assertThat(Occurrences
                .triples(occurrences(
                        "[{\"location\": \"" + supplementary + "\"}," + "{\"location\": \"" + privateUse + "\"}]")))
                .isEqualTo(privateUse + "##\n" + supplementary + "##");
    }

    /**
     * A producer-controlled line cannot forge a triple boundary.
     *
     * <p>
     * Triples are joined with a newline, so a line of {@code "1\nb#9#9"} would otherwise render as two triples and
     * claim an occurrence the producer never reported. The newline is escaped in the slot; {@code #} is left literal
     * because it separates fields <em>within</em> one triple, which the producer already controls all three of.
     */
    @Test
    void aCraftedLineCannotForgeATripleBoundary() {
        assertThat(Occurrences.triples(occurrences("[{\"location\": \"a\", \"line\": \"1\\nb\"}]")))
                .isEqualTo("a#1%0Ab#");
    }

    /** No occurrences at all is absence, not an empty digest -- an assetless discriminator must not key anything. */
    @Test
    void aComponentWithNoOccurrencesHasNoDiscriminator() {
        assertThat(Occurrences.triples(null)).isNull();
        assertThat(Occurrences.discriminator(null)).isNull();
        assertThat(Occurrences.triples(read("{}"))).isNull();
        assertThat(Occurrences.triples(read("{\"evidence\": {}}"))).isNull();
        assertThat(Occurrences.triples(read("{\"evidence\": {\"occurrences\": \"a.py\"}}"))).isNull();
        assertThat(Occurrences.triples(occurrences("[]"))).isNull();
        assertThat(Occurrences.triples(occurrences("[\"a.py\", 7]")))
                .describedAs("entries that are not objects carry no triple at all")
                .isNull();
    }

    /**
     * A location past the input bound is refused rather than sanitized.
     *
     * <p>
     * The cap on the result is deliberately the last step, so every pass above it scans the producer's string at the
     * producer's length -- and the location is the one producer string that never passes {@code boundedText}. Refusing
     * bounds that work without capping first, which is the defect core#2165 item 3 closed by leaving
     * {@code //user:passwo} standing. The longest corpus location is 194 characters.
     */
    @Test
    void aLocationPastTheInputBoundIsRefused() {
        assertThat(sanitize("a".repeat(64 * 1024)))
                .describedAs("at the bound it is still sanitized, and capped to the result length")
                .hasSize(1024);
        assertThat(sanitize("a".repeat(64 * 1024 + 1))).isEmpty();
    }

    /**
     * Sanitizing a sanitized location changes nothing.
     *
     * <p>
     * The location is sanitized twice on two paths -- once for the key, once for the stored evidence -- so the served
     * string must be the string the key hashed. The cap can land on interior whitespace, and the leading-fragment
     * retention can uncover a leading space, so a second application used to remove a character the first had kept.
     */
    @ParameterizedTest
    @ValueSource(strings = {"aaa  bbb", "# /path/to/key", "# pointer"})
    void sanitizingASanitizedLocationChangesNothing(String tail) {
        String location = "a".repeat(1020) + tail;
        String once = sanitize(location);

        assertThat(sanitize(once)).isEqualTo(once);
        assertThat(sanitize(tail)).isEqualTo(sanitize(sanitize(tail)));
    }

    /**
     * A stated location that renders as nothing is recorded by mechanism, and the record never quotes the location.
     *
     * <p>
     * Four classes empty a stated location -- a non-string value, the input-length refusal, the user-info pass-cap
     * refusal, and a string the sanitizer leaves nothing of -- and each renders the triple an absent location renders.
     * The one-argument {@code triples} is the reference operation the kernel mirrors and stays byte-identical to the
     * recording overload; the record is the only thing that separates the four from absence.
     */
    @Test
    void aStatedLocationThatRendersAsNothingIsRecordedByMechanismAndNeverQuoted() {
        Map<String, String> emptiedBy = new LinkedHashMap<>();
        emptiedBy.put("42", "is not a string");
        emptiedBy.put("\"" + "a".repeat(64 * 1024 + 1) + "\"", "is longer than 65536 characters");
        emptiedBy.put("\"//u:secret@" + "/u:secret@".repeat(39) + "host\"", "nests user-info deeper than 16");
        emptiedBy.put("\"?sig=secret\"", "names no place");
        emptiedBy.put("\"#?tok=secret\"", "names no place");
        emptiedBy.put("\"##\"", "names no place");
        emptiedBy.put("\"\\ud800\"", "names no place");
        emptiedBy.put("\"\\ud800 ?a\"", "names no place");

        emptiedBy.forEach((location, mechanism) -> {
            List<String> findings = new ArrayList<>();
            JsonNode component = occurrences("[{\"location\": " + location + ", \"line\": 7}]");
            assertThat(Occurrences.triples(component, findings)).describedAs(location).isEqualTo("#7#");
            assertThat(Occurrences.triples(component)).describedAs(location).isEqualTo("#7#");
            assertThat(findings)
                    .describedAs(location)
                    .singleElement()
                    .asString()
                    .startsWith("occurrence 0: the stated location ")
                    .contains(mechanism)
                    .doesNotContain("secret");
        });
        for (String absent : List.of("null", "\"   \"", "\"\\u00a0\"", "\"\\r\\n\"")) {
            List<String> findings = new ArrayList<>();
            assertThat(Occurrences.triples(occurrences("[{\"location\": " + absent + ", \"line\": 7}]"), findings))
                    .isEqualTo("#7#");
            assertThat(findings).describedAs("%s states nothing and is not a refusal", absent).isEmpty();
        }
        List<String> findings = new ArrayList<>();
        assertThat(
                Occurrences.triples(occurrences("[{\"line\": 7}, {\"location\": \"a\"}, {\"location\": 1}]"), findings))
                .isEqualTo("##\n#7#\na##");
        assertThat(findings)
                .describedAs("the index is the producer's, counted over the whole array")
                .singleElement()
                .asString()
                .startsWith("occurrence 2:");
    }

    private static String sanitize(String location) {
        return Occurrences.sanitizeLocation(new TextNode(location));
    }

    private static JsonNode occurrences(String occurrencesArrayJson) {
        return read("{\"evidence\": {\"occurrences\": " + occurrencesArrayJson + "}}");
    }

    private static JsonNode read(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(json, e);
        }
    }
}
