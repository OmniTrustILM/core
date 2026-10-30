package com.otilm.core.service.writer.cbom;

import com.otilm.api.exception.ValidationException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The length pre-checks {@link CryptoAssetWriter} runs before it writes.
 *
 * <p>
 * They exist so the two length CHECK constraints are never the thing that refuses a row. A failed CHECK makes
 * PostgreSQL emit {@code DETAIL: Failing row contains (...)}, which Hibernate logs at ERROR upstream of every catch,
 * and that row carries the identity key. The bound has to be enforced where it can still be refused quietly.
 */
class CryptoAssetWriterTest {

    private static final String MIGRATION = "db/migration/V202608271000__crypto_asset_inventory.sql";

    /**
     * A pre-check that drifts from its constraint is worse than no pre-check: it either rejects rows the database would
     * accept, or leaves the constraint reachable for exactly the inputs it was added to stop. So the bounds are read
     * out of the migration rather than restated here.
     */
    @Test
    void theBoundsAreTheOnesTheMigrationDeclares() throws IOException {
        assertThat(CryptoAssetWriter.MAX_OID_LENGTH)
                .describedAs("the bound ck_crypto_asset_oid_length declares")
                .isEqualTo(boundDeclaredOn("oid"));
        assertThat(CryptoAssetWriter.MAX_NAME_LENGTH)
                .describedAs("the bound ck_crypto_asset_name_length declares")
                .isEqualTo(boundDeclaredOn("name"));
    }

    @Test
    void aValueAtTheBoundIsAccepted() {
        assertThatCode(() -> CryptoAssetWriter
                .rejectIfLonger("x".repeat(CryptoAssetWriter.MAX_OID_LENGTH), CryptoAssetWriter.MAX_OID_LENGTH,
                        "ck_crypto_asset_oid_length"))
                .doesNotThrowAnyException();
    }

    @Test
    void anAbsentValueIsAccepted() {
        assertThatCode(() -> CryptoAssetWriter
                .rejectIfLonger(null, CryptoAssetWriter.MAX_OID_LENGTH, "ck_crypto_asset_oid_length"))
                .doesNotThrowAnyException();
    }

    @Test
    void anOverLongValueIsRefusedWithTheConstraintsOwnSentence() {
        assertThatThrownBy(() -> CryptoAssetWriter
                .rejectIfLonger("x".repeat(CryptoAssetWriter.MAX_NAME_LENGTH + 1), CryptoAssetWriter.MAX_NAME_LENGTH,
                        "ck_crypto_asset_name_length"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("longer than 1024 characters");
    }

    @Test
    void invalidIdentityKeysAreRefusedBeforeAnyWrite() {
        assertThatCode(() -> CryptoAssetWriter.requireIdentityKeyShape("0".repeat(64))).doesNotThrowAnyException();
        assertThatThrownBy(() -> CryptoAssetWriter.requireIdentityKeyShape(null))
                .isInstanceOf(ValidationException.class);
        assertThatThrownBy(() -> CryptoAssetWriter.requireIdentityKeyShape("0".repeat(63)))
                .isInstanceOf(ValidationException.class);
        assertThatThrownBy(() -> CryptoAssetWriter.requireIdentityKeyShape("0".repeat(63) + "G"))
                .isInstanceOf(ValidationException.class);
    }

    /**
     * PostgreSQL's {@code length()} counts characters, so a name of exactly the bound in astral code points is a row
     * the constraint accepts. Counting UTF-16 units here would refuse it -- half the permitted length for anyone
     * outside the Basic Multilingual Plane.
     */
    @Test
    void anAstralValueIsCountedTheWayPostgresCountsIt() {
        String atTheBound = "🔐".repeat(CryptoAssetWriter.MAX_NAME_LENGTH);
        assertThat(atTheBound.length())
                .describedAs("twice the bound in UTF-16 units, which is what a naive check would measure")
                .isEqualTo(2 * CryptoAssetWriter.MAX_NAME_LENGTH);

        assertThatCode(() -> CryptoAssetWriter
                .rejectIfLonger(atTheBound, CryptoAssetWriter.MAX_NAME_LENGTH, "ck_crypto_asset_name_length"))
                .doesNotThrowAnyException();
        assertThatThrownBy(() -> CryptoAssetWriter
                .rejectIfLonger(atTheBound + "🔐", CryptoAssetWriter.MAX_NAME_LENGTH, "ck_crypto_asset_name_length"))
                .isInstanceOf(ValidationException.class);
    }

    private static int boundDeclaredOn(String column) throws IOException {
        String sql = new ClassPathResource(MIGRATION).getContentAsString(StandardCharsets.UTF_8);
        Matcher bound = Pattern
                .compile("CHECK \\(length\\(\"" + column + "\"\\) <= (\\d+)\\)")
                .matcher(sql.replaceAll("(?m)--.*$", ""));
        assertThat(bound.find()).describedAs("the migration declares a length bound on %s", column).isTrue();
        return Integer.parseInt(bound.group(1));
    }
}
