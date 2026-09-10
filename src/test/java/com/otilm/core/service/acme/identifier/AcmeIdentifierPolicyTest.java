package com.otilm.core.service.acme.identifier;

import com.otilm.api.model.core.acme.AcmeIdentifierMatchType;
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
     * The table from the issue, asserted as written so the documented behaviour and the code cannot drift.
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
        AcmePreauthorizedIdentifierDto entry = entry("192.0.2.1", AcmeIdentifierMatchType.EXACT, false);

        assertTrue(AcmeIdentifierPolicy.covers(List.of(entry), ip("192.0.2.1")));
        assertFalse(AcmeIdentifierPolicy.covers(List.of(entry), ip("192.0.2.2")));
        assertTrue(AcmeIdentifierPolicy
                .covers(List.of(entry("2001:db8::1", AcmeIdentifierMatchType.EXACT, false)),
                        ip("2001:0db8:0:0:0:0:0:1")),
                "the same address written two ways is the same address");
    }

    @Test
    void aSubdomainEntryNeverCoversAnIpIdentifier() {
        assertFalse(
                AcmeIdentifierPolicy
                        .covers(List.of(entry("192.0.2.1", AcmeIdentifierMatchType.SUBDOMAIN, false)), ip("192.0.2.1")),
                "an address has no hierarchy to descend");
    }

    @Test
    void aNameIsNeverResolvedToDecideCoverage() {
        // Were the value passed to the resolver, an entry naming a host would silently cover whatever it resolves to.
        assertFalse(AcmeIdentifierPolicy
                .covers(List.of(entry("localhost", AcmeIdentifierMatchType.EXACT, false)), ip("127.0.0.1")));
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
        assertFalse(AcmeIdentifierPolicy.isSupportedType(identifier("email", "someone@example.com")));
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
        AcmePreauthorizedIdentifierDto entry = new AcmePreauthorizedIdentifierDto();
        entry.setValue(value);
        entry.setMatchType(matchType);
        entry.setAllowWildcard(allowWildcard);
        return entry;
    }
}
