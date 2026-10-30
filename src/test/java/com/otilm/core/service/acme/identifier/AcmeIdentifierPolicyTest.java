package com.otilm.core.service.acme.identifier;

import com.otilm.api.model.core.acme.AcmeIdentifierMatchType;
import com.otilm.api.model.core.acme.AcmeIdentifierType;
import com.otilm.api.model.core.acme.AcmePreauthorizedIdentifierDto;
import com.otilm.api.model.core.acme.Identifier;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AcmeIdentifierPolicyTest {

    private static final AcmePreauthorizedIdentifierDto EXACT_SERVER = entry("server01.example.com",
            AcmeIdentifierMatchType.EXACT, false);
    private static final AcmePreauthorizedIdentifierDto SUBDOMAIN_APPS = entry("apps.example.com",
            AcmeIdentifierMatchType.SUBDOMAIN, false);
    private static final AcmePreauthorizedIdentifierDto SUBDOMAIN_APPS_WILDCARD = entry("apps.example.com",
            AcmeIdentifierMatchType.SUBDOMAIN, true);

    /**
     * What each match type covers, asserted row by row so the behaviour a profile's editor sees and the matcher cannot
     * drift apart.
     */
    @ParameterizedTest(name = "{0}: exact={1} subdomain={2} subdomain+wildcard={3}")
    @CsvSource({
            "server01.example.com,    true,  false, false",
            "SERVER01.example.com,    true,  false, false",
            "apps.example.com,        false, false, false",
            "web.apps.example.com,    false, true,  true",
            "db.eu.apps.example.com,  false, true,  true",
            "other.example.com,       false, false, false",
            "*.apps.example.com,      false, false, true"})
    void theWorkedExample(String ordered, boolean byExact, boolean bySubdomain, boolean bySubdomainWildcard) {
        assertEquals(byExact, AcmeIdentifierPolicy.covers(List.of(EXACT_SERVER), dns(ordered)));
        assertEquals(bySubdomain, AcmeIdentifierPolicy.covers(List.of(SUBDOMAIN_APPS), dns(ordered)));
        assertEquals(bySubdomainWildcard, AcmeIdentifierPolicy.covers(List.of(SUBDOMAIN_APPS_WILDCARD), dns(ordered)));
    }

    @Test
    void subdomainDoesNotCoverTheNameItself() {
        assertFalse(AcmeIdentifierPolicy.covers(List.of(SUBDOMAIN_APPS), dns("apps.example.com")),
                "covering the name and its descendants takes an exact entry alongside the subdomain one");
        assertTrue(AcmeIdentifierPolicy
                .covers(List.of(SUBDOMAIN_APPS, entry("apps.example.com", AcmeIdentifierMatchType.EXACT, false)),
                        dns("apps.example.com")));
    }

    @Test
    void aSuffixThatIsNotALabelBoundaryIsNotADescendant() {
        assertFalse(AcmeIdentifierPolicy.covers(List.of(SUBDOMAIN_APPS), dns("evilapps.example.com")));
        assertFalse(AcmeIdentifierPolicy.covers(List.of(SUBDOMAIN_APPS), dns("notapps.example.com")));
    }

    @Test
    void aTrailingRootDotNamesTheSameHost() {
        assertTrue(AcmeIdentifierPolicy.covers(List.of(EXACT_SERVER), dns("server01.example.com.")));
        assertTrue(AcmeIdentifierPolicy
                .covers(List.of(entry("apps.example.com.", AcmeIdentifierMatchType.SUBDOMAIN, false)),
                        dns("web.apps.example.com")));
    }

    @Test
    void anExactEntryNeverCoversAWildcard() {
        AcmePreauthorizedIdentifierDto exactWithFlag = entry("apps.example.com", AcmeIdentifierMatchType.EXACT, true);

        assertFalse(AcmeIdentifierPolicy.covers(List.of(exactWithFlag), dns("*.apps.example.com")),
                "a wildcard stands for many names; an exact entry covers one, so the flag cannot help it");
    }

    @Test
    void aWildcardIsCoveredWhenItsParentSitsInsideTheEntry() {
        assertTrue(AcmeIdentifierPolicy.covers(List.of(SUBDOMAIN_APPS_WILDCARD), dns("*.eu.apps.example.com")),
                "every name the wildcard stands for is a descendant of the entry");
        assertFalse(AcmeIdentifierPolicy.covers(List.of(SUBDOMAIN_APPS_WILDCARD), dns("*.example.com")),
                "the wildcard would stand for names outside the entry, so it is not covered");
    }

    @Test
    void ipAddressesMatchByOctetsRegardlessOfRendering() {
        AcmePreauthorizedIdentifierDto entry = ipEntry("192.0.2.1", AcmeIdentifierMatchType.EXACT);

        assertTrue(AcmeIdentifierPolicy.covers(List.of(entry), ip("192.0.2.1")));
        assertFalse(AcmeIdentifierPolicy.covers(List.of(entry), ip("192.0.2.2")));
        assertTrue(AcmeIdentifierPolicy
                .covers(List.of(ipEntry("2001:db8::1", AcmeIdentifierMatchType.EXACT)), ip("2001:0db8:0:0:0:0:0:1")),
                "the same address written two ways is the same address");
    }

    /**
     * A value alone does not say which kind of identifier it is, and several read as both. The entry's own type is what
     * decides, so an operator who listed an address has not also listed the name spelled the same way.
     */
    @ParameterizedTest
    @CsvSource({"192.0.2.1", "1.2.3.4", "0.0.0.0"})
    void anEntryCoversItsOwnTypeAndNoOther(String value) {
        assertTrue(AcmeIdentifierPolicy.covers(List.of(ipEntry(value, AcmeIdentifierMatchType.EXACT)), ip(value)));
        assertFalse(AcmeIdentifierPolicy.covers(List.of(ipEntry(value, AcmeIdentifierMatchType.EXACT)), dns(value)),
                "an address entry must not pre-authorize the DNS name that reads the same");

        assertTrue(
                AcmeIdentifierPolicy.covers(List.of(entry(value, AcmeIdentifierMatchType.EXACT, false)), dns(value)));
        assertFalse(AcmeIdentifierPolicy.covers(List.of(entry(value, AcmeIdentifierMatchType.EXACT, false)), ip(value)),
                "and a DNS entry must not pre-authorize the address");
    }

    /**
     * An entry that cannot cover anything is refused when the profile is written, so the policy never holds one. Each
     * of these reads like cover and provides none.
     */
    @ParameterizedTest
    @CsvSource({
            "dns, *.apps.example.com,  subdomain, false, a wildcard where a name belongs",
            "dns, *.apps.example.com,  exact,     false, the same as an exact entry",
            "dns, '..apps.example.com', subdomain, false, not a well-formed name",
            "dns, 'ban\u212Ak.example.com', exact, false, not ASCII",
            "ip,  192.0.2.1,           subdomain, false, an address cannot be descended",
            "ip,  192.0.2.1,           exact,     true,  an address has no wildcard form",
            "ip,  999.0.2.1,           exact,     false, not an address literal",
            "ip,  010.0.0.1,           exact,     false, a leading zero is refused rather than interpreted",
            "ip,  localhost,           exact,     false, a name is never resolved to an address"})
    void anEntryThatCouldNeverMatchIsNotUsable(String type, String value, String matchType, boolean allowWildcard,
            String why) {
        AcmePreauthorizedIdentifierDto entry = entry(AcmeIdentifierType.findByCode(type), value,
                AcmeIdentifierMatchType.findByCode(matchType), allowWildcard);

        assertFalse(AcmeIdentifierPolicy.isUsable(entry), why);
    }

    @Test
    void anEntryThatCanMatchIsUsable() {
        assertTrue(AcmeIdentifierPolicy.isUsable(SUBDOMAIN_APPS));
        assertTrue(AcmeIdentifierPolicy.isUsable(SUBDOMAIN_APPS_WILDCARD));
        assertTrue(AcmeIdentifierPolicy.isUsable(EXACT_SERVER));
        assertTrue(AcmeIdentifierPolicy.isUsable(entry("apps.example.com.", AcmeIdentifierMatchType.SUBDOMAIN, false)),
                "a trailing root dot names the same host");
        assertTrue(AcmeIdentifierPolicy.isUsable(ipEntry("192.0.2.1", AcmeIdentifierMatchType.EXACT)));
        assertTrue(AcmeIdentifierPolicy.isUsable(ipEntry("2001:db8::1", AcmeIdentifierMatchType.EXACT)));
    }

    @Test
    void anIncompleteEntryIsNotUsable() {
        assertFalse(AcmeIdentifierPolicy.isUsable(null));
        assertFalse(
                AcmeIdentifierPolicy.isUsable(entry(null, "apps.example.com", AcmeIdentifierMatchType.EXACT, false)));
        assertFalse(AcmeIdentifierPolicy
                .isUsable(entry(AcmeIdentifierType.DNS, null, AcmeIdentifierMatchType.EXACT, false)));
        assertFalse(AcmeIdentifierPolicy.isUsable(entry(AcmeIdentifierType.DNS, "apps.example.com", null, false)));
    }

    @Test
    void anEntryWithoutATypeCoversNothing() {
        AcmePreauthorizedIdentifierDto untyped = entry(null, "server01.example.com", AcmeIdentifierMatchType.EXACT,
                false);

        assertFalse(AcmeIdentifierPolicy.covers(List.of(untyped), dns("server01.example.com")));
        assertFalse(AcmeIdentifierPolicy.covers(List.of(untyped), ip("192.0.2.1")));
    }

    @Test
    void aSubdomainEntryNeverCoversAnIpIdentifier() {
        assertFalse(
                AcmeIdentifierPolicy
                        .covers(List.of(ipEntry("192.0.2.1", AcmeIdentifierMatchType.SUBDOMAIN)), ip("192.0.2.1")),
                "an address has no hierarchy to descend");
    }

    /**
     * Resolving either side would let whoever controls DNS decide what a policy covers: an entry naming a host would
     * pre-authorize whatever address it resolves to, and an address entry would pre-authorize every name pointing at
     * it. The values start with characters that a first-character check would admit.
     */
    @ParameterizedTest
    @CsvSource({
            "example.com, 172.66.147.243",
            "api.example.com, 10.0.0.5",
            "db.internal, 192.0.2.7",
            "beef.example.com, 1.2.3.4",
            "cafe.test, 203.0.113.9"})
    void neitherSideOfAnAddressComparisonIsEverResolved(String name, String address) {
        assertFalse(
                AcmeIdentifierPolicy.covers(List.of(entry(name, AcmeIdentifierMatchType.EXACT, false)), ip(address)),
                "a name entry must not cover an address");
        assertFalse(AcmeIdentifierPolicy.covers(List.of(ipEntry(address, AcmeIdentifierMatchType.EXACT)), ip(name)),
                "an address entry must not cover a name presented as an ip identifier");
    }

    /**
     * A hostname containing a colon must never be treated as an address. These reached the resolver when the IPv6 shape
     * was expressed as a character class that admitted letters.
     */
    @ParameterizedTest
    @CsvSource({
            "victim:1.example.com",
            "zzz:1.example.com",
            "www.example.com:80",
            "guest:0.example.com",
            "abc:def.example.com",
            "_x:1.example.com",
            "-x:1.example.com",
            "foo%bar:1",
            "fe80::1%eth0"})
    void aColonDoesNotMakeAHostnameAnAddress(String value) {
        assertFalse(
                AcmeIdentifierPolicy.covers(List.of(ipEntry("192.0.2.1", AcmeIdentifierMatchType.EXACT)), ip(value)));
        assertFalse(
                AcmeIdentifierPolicy.covers(List.of(ipEntry(value, AcmeIdentifierMatchType.EXACT)), ip("192.0.2.1")));
    }

    @ParameterizedTest
    @CsvSource({
            "::1, 0:0:0:0:0:0:0:1",
            "2001:db8::1, 2001:0db8:0000:0000:0000:0000:0000:0001",
            "::, 0:0:0:0:0:0:0:0",
            "::ffff:192.0.2.1, 0:0:0:0:0:ffff:c000:0201",
            "2001:DB8::1, 2001:db8:0:0:0:0:0:1"})
    void anAddressWrittenTwoWaysIsTheSameAddress(String left, String right) {
        assertTrue(AcmeIdentifierPolicy.covers(List.of(ipEntry(left, AcmeIdentifierMatchType.EXACT)), ip(right)));
    }

    /**
     * Asserted against an entry holding the very same text, so a value the parser wrongly accepts cannot pass by merely
     * differing from some other address. A malformed value must not even match itself.
     */
    @ParameterizedTest
    @CsvSource({
            "1::2::3",
            ":::",
            "2001:db8:::1",
            "1:2:3:4:5:6:7:8:9",
            "2001:db8:0:0:0:0:0:0:1",
            "12345::1",
            "2001:db8::g",
            "::1.2.3.4.5",
            "1:2",
            "'  ::1'",
            "1.2.3.4::",
            "1.2.3.4::5",
            "0:1.2.3.4::",
            "1:2:3:4:5:1.2.3.4::",
            "1.2.3.4:5::6"})
    void aMalformedIpv6ValueIsNotAnAddress(String value) {
        assertFalse(AcmeIdentifierPolicy.covers(List.of(ipEntry(value, AcmeIdentifierMatchType.EXACT)), ip(value)));
    }

    /**
     * The dotted quad is the address-final 32 bits. Allowing one before the elision gives an entry an alias, because
     * the rewritten head parses to the same bytes.
     */
    @ParameterizedTest
    @CsvSource({
            "2001:db8::1, 32.1.13.184::1",
            "fe80::1, 254.128.0.0::1",
            "2001:db8:1:2::1, 2001:db8:0.1.0.2::1",
            "2001:db8:abcd:ef01::9, 2001:db8:171.205.239.1::9"})
    void aQuadBeforeTheElisionIsNotAnAliasForAnEntry(String entryValue, String orderedValue) {
        assertFalse(AcmeIdentifierPolicy
                .covers(List.of(ipEntry(entryValue, AcmeIdentifierMatchType.EXACT)), ip(orderedValue)));
    }

    @Test
    void anAddressValueLongerThanAnyLiteralIsRefusedBeforeParsing() {
        String oversized = "1:".repeat(5000) + "1";

        assertFalse(AcmeIdentifierPolicy.covers(List.of(ipEntry("::1", AcmeIdentifierMatchType.EXACT)), ip(oversized)));
    }

    @Test
    void aNameThatCaseFoldsOntoAnAsciiLetterIsNotThatName() {
        // U+212A KELVIN SIGN lowercases to 'k', so folding before validating would admit a name never listed.
        assertFalse(AcmeIdentifierPolicy
                .covers(List.of(entry("bank.example.com", AcmeIdentifierMatchType.EXACT, false)),
                        dns("ban\u212A.example.com")));
        assertFalse(AcmeIdentifierPolicy
                .covers(List.of(entry("example.com", AcmeIdentifierMatchType.SUBDOMAIN, false)),
                        dns("a\u212A.example.com")));
    }

    @Test
    void theNameLengthCapCountsTheWholePresentedName() {
        String longName = "a".repeat(49) + "." + "b".repeat(49) + "." + "c".repeat(49) + "." + "d".repeat(49) + "."
                + "e".repeat(53);
        assertEquals(253, longName.length());
        AcmePreauthorizedIdentifierDto suffix = entry(longName, AcmeIdentifierMatchType.SUBDOMAIN, true);

        assertFalse(AcmeIdentifierPolicy.covers(List.of(suffix), dns("*." + longName)),
                "the wildcard form is longer than a name may be, and no name it stands for could exist");
    }

    @Test
    void anIpIdentifierWhoseValueIsNotALiteralIsNotCovered() {
        assertFalse(AcmeIdentifierPolicy
                .covers(List.of(ipEntry("192.0.2.1", AcmeIdentifierMatchType.EXACT)), ip("localhost")));
        assertFalse(AcmeIdentifierPolicy
                .covers(List.of(ipEntry("192.0.2.1", AcmeIdentifierMatchType.EXACT)), ip("999.0.2.1")));
        assertFalse(
                AcmeIdentifierPolicy
                        .covers(List.of(ipEntry("192.0.2.1", AcmeIdentifierMatchType.EXACT)), ip("010.0.0.1")),
                "a leading zero reads as octal to some parsers and decimal to others");
    }

    @Test
    void aValueThatIsNotAWellFormedNameIsNotCovered() {
        AcmePreauthorizedIdentifierDto apps = entry("apps.example.com", AcmeIdentifierMatchType.SUBDOMAIN, false);

        assertFalse(AcmeIdentifierPolicy.covers(List.of(apps), dns("..apps.example.com")), "empty label");
        assertFalse(AcmeIdentifierPolicy.covers(List.of(apps), dns("x*.apps.example.com")), "asterisk mid-label");
        assertFalse(AcmeIdentifierPolicy.covers(List.of(apps), dns("web.apps.example.com\u0000")), "control character");
        assertFalse(AcmeIdentifierPolicy.covers(List.of(apps), dns("  web.apps.example.com ")), "whitespace");
        assertFalse(AcmeIdentifierPolicy.covers(List.of(apps), dns("web.apps.example.com..")), "doubled root dot");
        assertFalse(
                AcmeIdentifierPolicy
                        .covers(List.of(entry("server01.example.com", AcmeIdentifierMatchType.EXACT, false)),
                                dns("\u212Aey.example.com")),
                "a character that case-folds onto an ASCII letter is not that letter");
    }

    @Test
    void aDegenerateEntryCoversNothing() {
        assertFalse(
                AcmeIdentifierPolicy
                        .covers(List.of(entry(".", AcmeIdentifierMatchType.SUBDOMAIN, false)), dns("evil.example.net")),
                "a root-only entry must not become a policy covering everything");
        assertFalse(AcmeIdentifierPolicy
                .covers(List.of(entry("*.apps.example.com", AcmeIdentifierMatchType.SUBDOMAIN, true)),
                        dns("web.apps.example.com")),
                "an entry is a name; the match type is what widens it");
    }

    @Test
    void anIdentifierTypeThePolicyDoesNotKnowIsNeverCovered() {
        AcmePreauthorizedIdentifierDto server = entry("server01.example.com", AcmeIdentifierMatchType.EXACT, false);

        assertFalse(AcmeIdentifierPolicy.covers(List.of(server), identifier("email", "server01.example.com")));
        assertFalse(AcmeIdentifierPolicy.covers(List.of(server), identifier(null, "server01.example.com")));
    }

    @Test
    void anEmptyOrAbsentPolicyCoversNothing() {
        assertFalse(AcmeIdentifierPolicy.covers(List.of(), dns("server01.example.com")));
        assertFalse(AcmeIdentifierPolicy.covers(null, dns("server01.example.com")));
        assertFalse(AcmeIdentifierPolicy.covers(List.of(EXACT_SERVER), null));
        assertFalse(AcmeIdentifierPolicy.covers(List.of(EXACT_SERVER), dns(null)));
    }

    @Test
    void anIncompleteEntryCoversNothingRatherThanEverything() {
        assertFalse(AcmeIdentifierPolicy
                .covers(List.of(entry(null, AcmeIdentifierMatchType.EXACT, false)), dns("server01.example.com")));
        assertFalse(AcmeIdentifierPolicy
                .covers(List.of(entry("server01.example.com", null, false)), dns("server01.example.com")));
    }

    @Test
    void onlyDnsAndIpAreTypesThePolicyKnows() {
        assertTrue(AcmeIdentifierPolicy.isSupportedType(dns("server01.example.com")));
        assertTrue(AcmeIdentifierPolicy.isSupportedType(ip("192.0.2.1")));
        assertTrue(AcmeIdentifierPolicy.isSupportedType(identifier("DNS", "server01.example.com")),
                "the type is compared case-insensitively, as RFC 8555 writes it lowercase but does not require it");
        // The other types ACME registers, none of which the platform issues for.
        assertFalse(AcmeIdentifierPolicy.isSupportedType(identifier("email", "someone@example.com")));
        assertFalse(AcmeIdentifierPolicy.isSupportedType(identifier("TNAuthList", "eyJhbGciOiJF")));
        assertFalse(AcmeIdentifierPolicy.isSupportedType(identifier("permanent-identifier", "device-1")));
        assertFalse(AcmeIdentifierPolicy.isSupportedType(identifier(null, "server01.example.com")));
        assertFalse(AcmeIdentifierPolicy.isSupportedType(null));
    }

    private static Identifier dns(String value) {
        return identifier("dns", value);
    }

    private static Identifier ip(String value) {
        return identifier("ip", value);
    }

    private static Identifier identifier(String type, String value) {
        Identifier identifier = new Identifier();
        identifier.setType(type);
        identifier.setValue(value);
        return identifier;
    }

    private static AcmePreauthorizedIdentifierDto entry(String value, AcmeIdentifierMatchType matchType,
            boolean allowWildcard) {
        return entry(AcmeIdentifierType.DNS, value, matchType, allowWildcard);
    }

    private static AcmePreauthorizedIdentifierDto ipEntry(String value, AcmeIdentifierMatchType matchType) {
        return entry(AcmeIdentifierType.IP, value, matchType, false);
    }

    private static AcmePreauthorizedIdentifierDto entry(AcmeIdentifierType type, String value,
            AcmeIdentifierMatchType matchType, boolean allowWildcard) {
        AcmePreauthorizedIdentifierDto entry = new AcmePreauthorizedIdentifierDto();
        entry.setType(type);
        entry.setValue(value);
        entry.setMatchType(matchType);
        entry.setAllowWildcard(allowWildcard);
        return entry;
    }
}
