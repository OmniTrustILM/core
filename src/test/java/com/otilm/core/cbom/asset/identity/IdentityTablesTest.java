package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Guards the ratified artifact the whole identity chain keys on.
 *
 * <p>
 * These are tripwires rather than behaviour tests. The tables are data, and a data change is a re-keying event for the
 * entire inventory -- which makes an unnoticed edit strictly worse than a code change, because nothing about it looks
 * like a change to the keying rules.
 */
class IdentityTablesTest {

    /**
     * The artifact the shipped build keys on. Every published cross-implementation agreement figure predates it and was
     * measured against {@code 1331969bb507...}.
     *
     * <p>
     * An agreement percentage is worthless without the hash of the artifact it was taken against: one figure was
     * published and stale within the hour, because the same day's fixes had replaced the snapshot it was measured on.
     * If this assertion fails, the tables were edited, every stored identity key is potentially stale, and the figures
     * quoted throughout this package no longer describe the shipped build. Re-run the vectors and ratify each moved
     * expectation before changing the value here.
     *
     * <p>
     * A table edit re-keys, but it does not by itself advance {@link IdentityRuleset#VERSION}: that stamp exists to
     * make stale <em>stored</em> rows findable, and nothing in production drives {@code CryptoAssetWriter} yet, so
     * generation 2 has never keyed a row. The bump belongs to whichever change first gives that writer a production
     * caller, and that change names the rulings it is advancing past.
     */
    @Test
    void theShippedTablesAreTheRatifiedArtifact() throws IOException {
        try (InputStream stream = IdentityTablesTest.class
                .getClassLoader()
                .getResourceAsStream("cbom/identity-tables.json")) {
            assertThat(stream).isNotNull();
            assertThat(IdentityDigests.sha256HexOfBytes(stream.readAllBytes()))
                    .describedAs("the decision tables are ratified data; editing them re-keys the inventory")
                    .isEqualTo("a34c40d2f6fcfeb5aedeb58f371974e5e90e36fa225fd93ad9eb766162a153e2");
        }
    }

    /**
     * Insertion order survives loading, because the intrinsic-size lookup is first-match-wins.
     *
     * <p>
     * This is pinned because it has already broken once: {@code Map.copyOf} does not preserve order, and a name
     * carrying two intrinsic tokens then answered with whichever the hash happened to place first. The failure was
     * silent -- only names naming two curves were affected, and nothing about the code looked wrong.
     */
    @Test
    void theIntrinsicSizeTableKeepsItsOrder() {
        assertThat(new ArrayList<>(IdentityTables.load().nameIntrinsicSizes().keySet()))
                .containsExactly("ed25519", "x25519", "curve25519", "ed448", "x448", "curve448");
    }

    /**
     * The distinguished-name mapping is read from the tables and carries the long spellings.
     *
     * <p>
     * A table shipping is not a table being consumed: this exact map was once shipped, asked for, delivered, and then
     * not read, because the consumer kept a hardcoded guess beside it. The abbreviation-only version is what produced a
     * lower-cased short name where the specification says a dotted OID always goes.
     */
    @Test
    void theDistinguishedNameMappingIsConsumedFromTheTables() {
        IdentityTables tables = IdentityTables.load();

        assertThat(tables.dnAttributeOids())
                .containsEntry("cn", "2.5.4.3")
                .containsEntry("commonname", "2.5.4.3")
                .containsEntry("organizationname", "2.5.4.10")
                .containsEntry("domaincomponent", "0.9.2342.19200300.100.1.25");
    }

    /**
     * Every family a pseudo-family claims to contain must be a real registry token, or subsumption silently misfires.
     */
    @Test
    void everyPseudoFamilyMemberIsARegistryToken() {
        IdentityTables tables = IdentityTables.load();
        List<String> unknown = new ArrayList<>();
        tables
                .pseudoFamilies()
                .forEach((pseudo, members) -> members
                        .stream()
                        .filter(member -> !tables.families().contains(member))
                        .forEach(member -> unknown.add(pseudo + " -> " + member)));

        assertThat(unknown).isEmpty();
    }

    /** A family a producer can declare must resolve fold-insensitively, or the declaration is keyed verbatim. */
    @Test
    void everyFamilyTokenResolvesThroughAFoldedLookup() {
        IdentityTables tables = IdentityTables.load();
        List<String> unresolved = new ArrayList<>();
        tables.families().forEach(family -> {
            if (!family.equals(tables.familyToken(family))
                    || !family.equals(tables.familyToken(family.toLowerCase(Locale.ROOT)))) {
                unresolved.add(family);
            }
        });

        assertThat(unresolved).isEmpty();
    }

    /** Aliases must never point at a spelling outside the canonical curve vocabulary. */
    @Test
    void everyCurveAliasTargetsACanonicalCurve() {
        IdentityTables tables = IdentityTables.load();
        Set<String> canonicalCurves = new HashSet<>(tables.curveCanonical().values());

        assertThat(tables.curveAliases())
                .allSatisfy((alias, target) -> assertThat(canonicalCurves)
                        .describedAs("curve alias %s targets a canonical curve", alias)
                        .contains(target));
    }

    /**
     * OID-derived families are ratified table output, so every non-null family must resolve through the same lookup.
     */
    @Test
    void everyOidFamilyResolvesThroughAFoldedLookup() {
        IdentityTables tables = IdentityTables.load();
        List<String> unresolved = new ArrayList<>();

        tables.oidToFamily().forEach((oid, entry) -> {
            String family = entry.family();
            if (family != null && !family.equals(tables.familyToken(family))) {
                unresolved.add(oid + " -> " + family);
            }
        });

        assertThat(unresolved).isEmpty();
    }

    /** Primitive defaults must be total over concrete values that CycloneDX 1.6 can express. */
    @Test
    void everyPrimitiveDefaultUsesAnExpressiblePrimitive() throws IOException {
        JsonNode raw = rawTables();
        Set<String> expressible = textSet(raw.get("primitivesExpressibleIn16"));
        IdentityTables tables = IdentityTables.load();
        Map<String, String> defaults = tables.primitiveDefaults();

        assertThat(defaults.keySet())
                .allSatisfy(family -> assertThat(tables.familyToken(family))
                        .describedAs("primitive default key is a registered family")
                        .isEqualTo(family));
        assertThat(defaults.values())
                .allSatisfy(primitive -> assertThat(expressible)
                        .describedAs("primitive default value is expressible in CycloneDX 1.6")
                        .contains(primitive));
    }

    /**
     * Every family a grammar rule names is a legal token, so a hand-edit of the artifact cannot elect a family the
     * vocabulary does not carry. The generator refuses this on its side; a re-pinned SHA over an edited artifact would
     * have passed every Java test without this mirror.
     */
    @Test
    void everyGrammarFamilyIsALegalFamily() {
        IdentityTables tables = IdentityTables.load();

        assertThat(tables.nameGrammar())
                .allSatisfy(rule -> assertThat(tables.families())
                        .describedAs("grammar rule %s names a legal family", rule.strict())
                        .contains(rule.family()));
    }

    /** Every family the grammar or an arc can yield has a primitive default, or an omitting producer splits. */
    @Test
    void everyReachableFamilyHasAPrimitiveDefault() {
        IdentityTables tables = IdentityTables.load();
        Set<String> reachable = new HashSet<>();
        tables.nameGrammar().forEach(rule -> reachable.add(rule.family()));
        tables
                .oidToFamily()
                .values()
                .stream()
                .map(IdentityTables.OidEntry::family)
                .filter(f -> f != null)
                .forEach(reachable::add);

        assertThat(reachable)
                .allSatisfy(family -> assertThat(tables.primitiveDefaults())
                        .describedAs("family %s can be derived and needs a primitive default", family)
                        .containsKey(family));
    }

    /** The size whitelist is the one the specification names; both bounds feed the parameter-set parser. */
    @Test
    void theSizeWhitelistIsTheRatifiedRange() {
        IdentityTables tables = IdentityTables.load();

        assertThat(tables.sizeMin()).isEqualTo(64);
        assertThat(tables.sizeMax()).isEqualTo(16384);
    }

    /** A missing table is a broken build, not a runtime condition, so loading fails loudly rather than degrading. */
    @Test
    void theTablesLoadOrTheBuildIsBroken() {
        assertThat(IdentityTables.load()).isNotNull();
        assertThat(IdentityTables.load().nameGrammar()).isNotEmpty();
        assertThat(IdentityTables.load().curveCanonical()).isNotEmpty();
    }

    /**
     * A malformed artifact refuses to load, naming the table and the shape it wanted.
     *
     * <p>
     * Jackson's own traversal is fail-open -- {@code forEach} over a scalar visits nothing, {@code asInt()} of text is
     * 0 -- so a mis-typed table once loaded as an <em>empty</em> one with every vector green and only the artifact hash
     * red. The typed reader closed that, and nothing could reach its refusals: the constructor was private and
     * {@code load()} reads one fixed resource. Each shape the reader refuses is driven here through a copy of the
     * shipped artifact with one thing wrong, so the fail-open state is one red test away rather than one regression.
     */
    @ParameterizedTest
    @MethodSource("malformedArtifacts")
    void aMalformedArtifactRefusesToLoadNamingTheTable(String description, Consumer<ObjectNode> corruption,
            String refusal) throws IOException {
        ObjectNode artifact = (ObjectNode) rawTables();
        corruption.accept(artifact);

        assertThatThrownBy(() -> IdentityTables.of(artifact))
                .describedAs(description)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(refusal);
    }

    static Stream<Arguments> malformedArtifacts() {
        return Stream
                .of(malformed("a wrong container type", tables -> tables.put("oidBlockedPrefixes", "1.2.840"),
                        "table `oidBlockedPrefixes` must be an array, not STRING"),
                        malformed("a wrong element type", tables -> ((ArrayNode) tables.get("sizeStoplist")).set(0, 5),
                                "table `sizeStoplist[0]` must be a string, not NUMBER"),
                        malformed("a missing table", tables -> tables.remove("nameGrammar"),
                                "table `nameGrammar` is missing"),
                        malformed("a missing member of a rule",
                                tables -> ((ObjectNode) tables.get("nameGrammar").get(0)).remove("family"),
                                "table `nameGrammar[0].family` is missing"),
                        malformed("a null map value",
                                tables -> ((ObjectNode) tables.get("paddingAliases")).putNull("PKCS5"),
                                "table `paddingAliases.PKCS5` must be a string, not NULL"),
                        malformed("a non-integer bound",
                                tables -> ((ObjectNode) tables.get("sizeWhitelist")).put("min", "64"),
                                "table `sizeWhitelist.min` must be an integer, not STRING"),
                        malformed("an over-long marker tuple",
                                tables -> ((ArrayNode) tables.get("secondaryMarkers").get(0)).add("POLY1305"),
                                "table `secondaryMarkers[0]` must hold exactly 2 elements, not 3"),
                        malformed("two family tokens folding together",
                                tables -> ((ArrayNode) tables.get("algorithmFamilies")).add("aes"),
                                "family tokens `AES` and `aes` fold to the same lookup key `aes`"),
                        malformed("two curve aliases folding together with different targets",
                                tables -> ((ObjectNode) tables.get("curveAliases")).put("P_256", "secg/secp384r1"),
                                "`P_256` -> `secg/secp384r1` fold to the same lookup key `p256` with different targets"));
    }

    private static Arguments malformed(String description, Consumer<ObjectNode> corruption, String refusal) {
        return Arguments.of(description, corruption, refusal);
    }

    private static JsonNode rawTables() throws IOException {
        try (InputStream stream = IdentityTablesTest.class
                .getClassLoader()
                .getResourceAsStream("cbom/identity-tables.json")) {
            assertThat(stream).isNotNull();
            return ObjectMapperFactory.storage().readTree(stream);
        }
    }

    private static Set<String> textSet(JsonNode node) {
        Set<String> values = new HashSet<>();
        node.forEach(value -> values.add(value.asText()));
        return values;
    }
}
