package com.otilm.core.dao;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataIntegrityViolationException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The fence over the exception-translation sites this ticket adds.
 *
 * <p>
 * PostgreSQL reports a constraint violation with a {@code DETAIL} line that quotes the failing row -- for
 * {@code crypto_asset} that row carries the identity key, whose whole protection is that it never leaves the database.
 * Each test here builds a failure whose message carries that DETAIL and asserts the translated text carries none of it.
 */
class CryptoAssetConstraintTranslatorTest {

    /**
     * A realistic driver message. The identity key, the table names and the SQL are all things a caller must never be
     * handed.
     */
    private static final String DRIVER_MESSAGE = """
            ERROR: update or delete on table "cbom" violates foreign key constraint \
            "crypto_asset_source_to_cbom_key" on table "crypto_asset_source"
              Detail: Key (uuid)=(2f8c0f6e-0000-4000-8000-000000000001) is still referenced from table \
            "crypto_asset_source".
              Where: SQL statement "DELETE FROM core.cbom WHERE uuid = $1"
            """;

    private static DataIntegrityViolationException failure(String constraintName) {
        ConstraintViolationException hibernateFailure = new ConstraintViolationException(DRIVER_MESSAGE,
                new SQLException(DRIVER_MESSAGE, "23503"), constraintName);
        return new DataIntegrityViolationException(DRIVER_MESSAGE, hibernateFailure);
    }

    @Test
    void aRestrictedCbomDeleteIsExplainedWithoutTheDriverText() {
        String description = CryptoAssetConstraintTranslator.describe(failure("crypto_asset_source_to_cbom_key"));

        assertThat(description)
                .isEqualTo("The CBOM is still referenced by the cryptographic asset inventory. "
                        + "Its asset sources must be detached before the CBOM can be deleted.");
        assertThat(description)
                .doesNotContain("Detail")
                .doesNotContain("DETAIL")
                .doesNotContain("2f8c0f6e")
                .doesNotContain("DELETE FROM")
                .doesNotContain("$1");
    }

    /**
     * Why each of these deliberately falls through to {@link CryptoAssetConstraintTranslator#GENERIC_REJECTION}: the
     * four counters are computed by ingest code and never taken from a caller, and the source-to-asset foreign key is
     * satisfied by construction on every write path and by {@code ON DELETE CASCADE} on the delete path. A violation of
     * any of them is a platform bug rather than a caller error, so there is no sentence an operator could act on.
     */
    private static final Set<String> DELIBERATELY_GENERIC = Set
            .of("ck_crypto_asset_source_count", "ck_crypto_asset_properties_leaf_count",
                    "ck_crypto_asset_source_occurrence_count", "ck_crypto_asset_source_properties_leaf_count",
                    "crypto_asset_source_to_crypto_asset_key");

    /**
     * The list of constraints is read from the migration rather than copied here, because a copied list is what let six
     * translations ship uncovered behind a test whose name claimed all of them. Reading the declaration means a
     * constraint added without a translation fails this test, and a translation for a name the migration does not
     * declare fails it too.
     */
    @Test
    void everyConstraintTheMigrationDeclaresIsEitherExplainedOrDeliberatelyGeneric() throws IOException {
        Set<String> declared = constraintNamesTheMigrationDeclares();

        assertThat(declared)
                .describedAs("the migration is merged and therefore frozen, so the count proves the parse still parses")
                .hasSize(20)
                .containsAll(DELIBERATELY_GENERIC);

        Set<String> explained = new TreeSet<>(declared);
        explained.removeAll(DELIBERATELY_GENERIC);
        for (String constraint : explained) {
            assertThat(CryptoAssetConstraintTranslator.describe(failure(constraint)))
                    .describedAs("constraint %s must be explained in the caller's terms", constraint)
                    .isNotEqualTo(CryptoAssetConstraintTranslator.GENERIC_REJECTION)
                    .doesNotContain("Detail")
                    .doesNotContain("2f8c0f6e")
                    .doesNotContain("DELETE FROM")
                    .doesNotContain("$1");
        }

        for (String constraint : DELIBERATELY_GENERIC) {
            assertThat(CryptoAssetConstraintTranslator.describe(failure(constraint)))
                    .describedAs("constraint %s gained a translation; remove it from DELIBERATELY_GENERIC", constraint)
                    .isEqualTo(CryptoAssetConstraintTranslator.GENERIC_REJECTION);
        }

        assertThat(CryptoAssetConstraintTranslator.knownConstraintNames())
                .describedAs("a translation for a name the migration does not declare is dead or misspelled")
                .isSubsetOf(declared);
    }

    /**
     * Comments are stripped before matching, as {@code CryptoAssetInventoryMigrationITest} does, so prose naming a
     * constraint cannot be counted as declaring one. The lowercase-only character class also pins the spelling that
     * {@link CryptoAssetConstraintTranslator#constraintNameOf} folds to.
     */
    private static Set<String> constraintNamesTheMigrationDeclares() throws IOException {
        String sql = new ClassPathResource("db/migration/V202608271000__crypto_asset_inventory.sql")
                .getContentAsString(StandardCharsets.UTF_8);
        Matcher names = Pattern.compile("CONSTRAINT \"([a-z0-9_]+)\"").matcher(sql.replaceAll("(?m)--.*$", ""));

        Set<String> declared = new TreeSet<>();
        while (names.find()) {
            declared.add(names.group(1));
        }
        return declared;
    }

    @Test
    void anUnknownConstraintFallsBackToAFixedSentence() {
        assertThat(CryptoAssetConstraintTranslator.describe(failure("some_constraint_added_later")))
                .isEqualTo(CryptoAssetConstraintTranslator.GENERIC_REJECTION);
    }

    @Test
    void aFailureCarryingNoConstraintNameFallsBackToAFixedSentence() {
        assertThat(CryptoAssetConstraintTranslator
                .describe(new DataIntegrityViolationException(DRIVER_MESSAGE, new SQLException(DRIVER_MESSAGE))))
                .isEqualTo(CryptoAssetConstraintTranslator.GENERIC_REJECTION);
        assertThat(CryptoAssetConstraintTranslator.describe(null))
                .isEqualTo(CryptoAssetConstraintTranslator.GENERIC_REJECTION);
    }

    @Test
    void aSchemaQualifiedAndUppercasedConstraintNameStillResolves() {
        assertThat(CryptoAssetConstraintTranslator.describe(failure("core.UQ_CRYPTO_ASSET_SOURCE")))
                .isEqualTo("This CBOM's contribution to the cryptographic asset is already recorded.");
    }

    @Test
    void theConstraintNameIsTakenFromTheCauseChainNotTheMessage() {
        assertThat(CryptoAssetConstraintTranslator.constraintNameOf(failure("uq_crypto_asset_source")))
                .contains("uq_crypto_asset_source");
        assertThat(CryptoAssetConstraintTranslator
                .constraintNameOf(new IllegalStateException("uq_crypto_asset_source appears only in this text")))
                .describedAs("a constraint name that appears only in a message must not be trusted")
                .isEmpty();
    }
}
