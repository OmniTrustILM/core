package com.otilm.core.cbom.asset.identity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/** Pins the distinguished-name form the certificate tiers key on. */
class DistinguishedNamesTest {

    private static final IdentityTables TABLES = IdentityTables.load();

    /**
     * Attribute types become dotted OIDs, never short names, and the long spellings map too.
     *
     * <p>
     * Both implementations of this specification once carried an abbreviation-only map, so a producer writing
     * {@code commonName=} got a lower-cased short name in the slot where the rule says a dotted OID always goes.
     * Because both sides reproduced the wart together, no cross-implementation agreement measurement could ever have
     * found it: it took reading the rule against its own output. The mapping is read from the ratified tables for that
     * reason.
     */
    @ParameterizedTest
    @CsvSource({
            "'CN=x', '2.5.4.3=x'",
            "'commonName=x', '2.5.4.3=x'",
            "'O=x', '2.5.4.10=x'",
            "'organizationName=x', '2.5.4.10=x'",
            "'DC=x', '0.9.2342.19200300.100.1.25=x'",
            "'domainComponent=x', '0.9.2342.19200300.100.1.25=x'",
            "'UID=x', '0.9.2342.19200300.100.1.1=x'"})
    void attributeTypesBecomeDottedOids(String input, String expected) {
        assertThat(DistinguishedNames.normalize(input, TABLES)).isEqualTo(expected);
    }

    /**
     * RDNs sort on the rendered {@code oid=value} string, so {@code 2.5.4.10} precedes {@code 2.5.4.3}.
     *
     * <p>
     * Not on the value, which the specification's own prose claimed for months. Sorting at all is an availability fact
     * rather than a preference: the producer's renderer has already rebuilt the RDNs in a hardcoded field order and
     * discarded true DER order, so preserving source order would make one certificate reported by two producers never
     * agree.
     */
    @Test
    void rdnsSortOnTheRenderedStringNotOnTheValue() {
        assertThat(DistinguishedNames.normalize("CN=zebra,O=alpha", TABLES)).isEqualTo("2.5.4.10=alpha,2.5.4.3=zebra");
        assertThat(DistinguishedNames.normalize("O=alpha,CN=zebra", TABLES))
                .describedAs("source order must not survive")
                .isEqualTo("2.5.4.10=alpha,2.5.4.3=zebra");
    }

    /**
     * A value carrying no {@code =} at all is a bare common name, not a malformed DN.
     *
     * <p>
     * Refusing it made the composite unconstructible and dropped two <em>different</em> root CAs -- same subject,
     * different validity windows -- onto one identity.
     */
    @Test
    void aBareNameBecomesACommonName() {
        assertThat(DistinguishedNames.normalize("EJBCA-Root-CA", TABLES)).isEqualTo("2.5.4.3=ejbca-root-ca");
    }

    /** A plain split would break a real corpus value into two RDNs. */
    @Test
    void anEscapedSeparatorDoesNotSplitAnRdn() {
        assertThat(DistinguishedNames.normalize("O=Qualys\\, Inc.", TABLES)).isEqualTo("2.5.4.10=qualys\\, inc.");
    }

    /** Folding is ASCII-only and applies only where the attribute's syntax allows it. Default-deny. */
    @Test
    void onlyCaseInsensitiveAttributesFold() {
        assertThat(DistinguishedNames.normalize("CN=MixedCase", TABLES)).isEqualTo("2.5.4.3=mixedcase");
        assertThat(DistinguishedNames.normalize("serialNumber=ABCdef", TABLES))
                .describedAs("a serial number is compared verbatim")
                .isEqualTo("2.5.4.5=ABCdef");
        assertThat(DistinguishedNames.normalize("emailAddress=Foo@Bar.com", TABLES))
                .describedAs("RFC 5321 local-parts are case-sensitive")
                .isEqualTo("1.2.840.113549.1.9.1=Foo@Bar.com");
    }

    /**
     * The pipe is escaped because the identity pre-image is pipe-delimited: an unescaped one inside a crafted common
     * name could shift every later field boundary and forge a collision with a different tier.
     */
    @Test
    void theDelimiterCannotBeSmuggledThroughAValue() {
        assertThat(DistinguishedNames.normalize("CN=a|b", TABLES)).isEqualTo("2.5.4.3=a\\|b");
    }

    /** Whitespace collapses and NFKC applies, so a fullwidth or padded spelling cannot split a row. */
    @Test
    void spacingAndCompatibilitySpellingsDoNotSplitARow() {
        assertThat(DistinguishedNames.normalize("cn=  Spaced   Out  ", TABLES)).isEqualTo("2.5.4.3=spaced out");
        assertThat(DistinguishedNames.normalize("CN=ＲＳＡ", TABLES)).isEqualTo("2.5.4.3=rsa");
    }

    /**
     * A trailing no-break space is stripped, which {@link String#strip()} would not do.
     *
     * <p>
     * NFKC turns a surviving one into an ordinary trailing space, keying {@code "x "} apart from {@code "x"}.
     */
    @Test
    void aTrailingNoBreakSpaceIsStripped() {
        assertThat(DistinguishedNames.normalize("CN=x ", TABLES)).isEqualTo("2.5.4.3=x");
        assertThat(DistinguishedNames.normalize("CN=x ", TABLES)).isEqualTo("2.5.4.3=x");
    }

    /**
     * An RFC 4514 hex pair is the octet it names, and consecutive pairs are one UTF-8 run. Dropping the backslash and
     * keeping the digits made {@code CN=a\\2Cb} the same name as {@code CN=a2Cb}, and rendered the NetLock and E-Tugra
     * roots in the corpus -- seven DN values -- as {@code TanC3BAs...}.
     */
    @Test
    void aHexPairIsTheOctetItNames() {
        assertThat(DistinguishedNames.normalize("CN=a\\2Cb", TABLES))
                .isEqualTo(DistinguishedNames.normalize("CN=a\\,b", TABLES))
                .isNotEqualTo(DistinguishedNames.normalize("CN=a2Cb", TABLES));
        assertThat(DistinguishedNames.normalize("O=Tan\\C3\\BAs", TABLES))
                .isEqualTo(DistinguishedNames.normalize("O=Tan\u00FAs", TABLES));
        assertThat(DistinguishedNames.normalize("CN=e\\CC\\81", TABLES))
                .describedAs("the decoded run joins the surrounding text before NFKC, so a combining mark composes")
                .isEqualTo(DistinguishedNames.normalize("CN=\u00E9", TABLES));
    }

    /** A pair that is not UTF-8 renders as the reserved bare byte, so it cannot alias a producer's literal escape. */
    @Test
    void anUndecodableHexPairRendersAsTheReservedBareByte() {
        assertThat(DistinguishedNames.normalize("CN=\\FF", TABLES))
                .isEqualTo("2.5.4.3=%ff")
                .isNotEqualTo(DistinguishedNames.normalize("CN=%FF", TABLES));
    }

    /**
     * An RFC 2253 quoted value is one value. 84 of the 1 595 corpus DN values are OpenSSL's {@code O = "Entrust, Inc."}
     * rendering; split on the inner comma, {@code "Entrust, Inc."} and {@code "Entrust, Ltd."} rendered one AVA with
     * the rest silently dropped, and the quote itself was kept as text.
     */
    @Test
    void aQuotedValueIsOneValue() {
        assertThat(DistinguishedNames.normalize("O=\"Entrust, Inc.\",C=US", TABLES))
                .isEqualTo("2.5.4.10=entrust\\, inc.,2.5.4.6=us")
                .isEqualTo(DistinguishedNames.normalize("O=Entrust\\, Inc.,C=US", TABLES))
                .isEqualTo(DistinguishedNames.normalize("C = US, O = \"Entrust, Inc.\"", TABLES))
                .isNotEqualTo(DistinguishedNames.normalize("O=\"Entrust, Ltd.\",C=US", TABLES));
        assertThat(DistinguishedNames.normalize("CN=\"#414243\"", TABLES))
                .describedAs("quoted content is text whatever it opens with")
                .isEqualTo("2.5.4.3=\\#414243");
        assertThat(DistinguishedNames.normalize("CN=say \"hi\"", TABLES))
                .describedAs("a quote that does not enclose the whole value is a character in it")
                .isEqualTo("2.5.4.3=say \\\"hi\\\"");
    }

    /** RFC 2253 §4 requires {@code ;} to be read as an RDN separator; RFC 4514 gives an unescaped one no meaning. */
    @Test
    void aSemicolonSeparatesRdns() {
        assertThat(DistinguishedNames.normalize("CN=a;O=b", TABLES))
                .isEqualTo(DistinguishedNames.normalize("CN=a,O=b", TABLES));
    }

    /**
     * RDNs sort by code point, as the reference and every other ordered sequence here do. {@code sort(null)} compared
     * UTF-16 units, which put an astral character below one at or above U+E000.
     */
    @Test
    void rdnsSortByCodePointNotByUtf16Unit() {
        assertThat(DistinguishedNames.normalize("CN=\uD83D\uDE00,CN=\uE000", TABLES)).startsWith("2.5.4.3=\uE000,");
    }

    /**
     * Go emits every attribute type it does not know this way, and decoding is mandatory or two producers never match.
     */
    @Test
    void theHexDerFormIsDecodedBeforeComparison() {
        assertThat(DistinguishedNames.normalize("CN=#414243", TABLES)).isEqualTo("2.5.4.3=abc");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   "})
    void anEmptyInputYieldsNoName(String input) {
        assertThat(DistinguishedNames.normalize(input, TABLES)).isNull();
    }

    /**
     * A malformed attribute is kept as itself rather than discarded, which is what the reference does.
     *
     * <p>
     * Keeping it is the safer direction: an attribute nobody can parse is still a fact the producer stated, and two
     * certificates differing only there must not merge. Verified against the reference rather than assumed -- the first
     * draft of this test asserted these were dropped, and the reference disagreed.
     */
    @ParameterizedTest
    @CsvSource({"'=', '='", "'a=', 'a='", "'=b', '=b'"})
    void anUnparseableAttributeSurvivesAsItself(String input, String expected) {
        assertThat(DistinguishedNames.normalize(input, TABLES)).isEqualTo(expected);
    }

    @Test
    void aNullInputYieldsNoName() {
        assertThat(DistinguishedNames.normalize(null, TABLES)).isNull();
    }

    /**
     * A CN-only observation is never merged into a full-DN row.
     *
     * <p>
     * {@code CN=localhost} is issued endlessly by internal CAs. Merging would fuse two certificates into one row that
     * inherits one certificate's key size and expiry and both certificates' occurrences, so an operator asking "where
     * is weak crypto deployed" gets CLEAN for a vulnerable host.
     */
    @Test
    void aCommonNameOnlySubjectIsRecognized() {
        assertThat(DistinguishedNames.isCommonNameOnly(DistinguishedNames.normalize("CN=localhost", TABLES))).isTrue();
        assertThat(DistinguishedNames.isCommonNameOnly(DistinguishedNames.normalize("CN=x,O=y", TABLES))).isFalse();
        assertThat(DistinguishedNames.isCommonNameOnly(null)).isFalse();
    }

    /** Multi-valued RDNs sort within themselves, so a producer's ordering of a {@code +} pair cannot split a row. */
    @Test
    void multiValuedRdnsSortWithinThemselves() {
        assertThat(DistinguishedNames.normalize("CN=b+O=a", TABLES))
                .isEqualTo(DistinguishedNames.normalize("O=a+CN=b", TABLES));
    }

    /**
     * A DER value that is not UTF-8 keys apart from one that spells its escape.
     *
     * <p>
     * Escaping only the malformed path moved item 17's merge rather than closing it: {@code #FF} is not UTF-8 and
     * renders {@code %FF}, while {@code #254646} decodes cleanly to the three ASCII characters {@code %FF}. Two
     * distinct DER attribute values, one AVA -- the same "two issuers on one row" failure, different inputs.
     */
    @org.junit.jupiter.api.Test
    void aMalformedDerValueDoesNotKeyAsItsOwnEscape() {
        assertThat(DistinguishedNames.normalize("CN=#FF", TABLES))
                .isNotEqualTo(DistinguishedNames.normalize("CN=#254646", TABLES));
        assertThat(DistinguishedNames.normalize("CN=#1401E9", TABLES))
                .isNotEqualTo(DistinguishedNames.normalize("CN=#1401EA", TABLES));
        assertThat(DistinguishedNames.normalize("CN=#FF", TABLES))
                .describedAs("a refused byte and a producer spelling its escape are different values")
                .isNotEqualTo(DistinguishedNames.normalize("CN=%FF", TABLES));
        assertThat(DistinguishedNames.normalize("CN=%25FF", TABLES))
                .describedAs("and the escape of the escape is a third")
                .isNotEqualTo(DistinguishedNames.normalize("CN=%FF", TABLES));
    }

    /**
     * A compatibility spelling of the escape character cannot forge a refused byte.
     *
     * <p>
     * NFKC maps U+FF05 FULLWIDTH PERCENT SIGN onto {@code %}, so escaping before normalizing left {@code CN=\uFF05FF}
     * rendering the bare {@code %FF} that the malformed-bytes fallback reserves for {@code CN=#FF} -- the same
     * two-issuers-on-one-row merge the escape namespace exists to prevent, reached through the normalizer rather than
     * through a hex path.
     *
     * <p>
     * Its mirror is not closed by the same reordering but by the opposite one. Testing for the {@code #} marker
     * <em>after</em> NFKC let U+FF03 FULLWIDTH NUMBER SIGN manufacture a marker: {@code CN=\uFF03FF} was decoded as
     * DER, failed UTF-8, and rendered the same bare {@code %FF} as {@code CN=#FF}, so three issuers became one row. RFC
     * 4514 defines the marker over ASCII {@code #} alone; a compatibility number sign is text.
     */
    @Test
    void aFullwidthEscapeCharacterCannotForgeARefusedByte() {
        assertThat(DistinguishedNames.normalize("CN=\uFF05FF", TABLES))
                .describedAs("the normalizer's percent is a producer's percent, so it is escaped like one")
                .isEqualTo(DistinguishedNames.normalize("CN=%FF", TABLES))
                .isNotEqualTo(DistinguishedNames.normalize("CN=#FF", TABLES));
        assertThat(DistinguishedNames.normalize("CN=\uFF03FF", TABLES))
                .describedAs("a compatibility number sign is text, never the hex-DER marker")
                .isEqualTo(DistinguishedNames.normalize("CN=\\#FF", TABLES))
                .isNotEqualTo(DistinguishedNames.normalize("CN=#FF", TABLES));
        assertThat(DistinguishedNames.normalize("CN=\uFE5F414243", TABLES))
                .describedAs("so a readable payload behind one is not decoded either")
                .isNotEqualTo(DistinguishedNames.normalize("CN=#414243", TABLES));
        assertThat(DistinguishedNames.normalize("CN=#%FF", TABLES))
                .describedAs("an unreadable hex spelling is text, and text has its percents escaped")
                .isNotEqualTo(DistinguishedNames.normalize("CN=#FF", TABLES));
    }

    /**
     * The bare-common-name path reserves the escape namespace exactly as the attribute path does.
     *
     * <p>
     * A DN with no {@code =} is keyed as a common name, and its percents were escaped by a different line of code than
     * {@code CN=}'s. Dropping that escape leaves every other test green while {@code %FF} and {@code CN=#FF} -- a
     * producer spelling an escape and a byte no decoder could read -- merge onto one issuer, which is the invariant
     * {@link #aMalformedDerValueDoesNotKeyAsItsOwnEscape} pins for the prefixed spelling.
     */
    @Test
    void theBareNamePathReservesTheEscapeNamespaceToo() {
        assertThat(DistinguishedNames.normalize("%FF", TABLES))
                .isNotEqualTo(DistinguishedNames.normalize("CN=#FF", TABLES));
        assertThat(DistinguishedNames.normalize("\uFF05FF", TABLES))
                .describedAs("and normalizes before it escapes, as the attribute path does")
                .isEqualTo(DistinguishedNames.normalize("%FF", TABLES));
    }
}
