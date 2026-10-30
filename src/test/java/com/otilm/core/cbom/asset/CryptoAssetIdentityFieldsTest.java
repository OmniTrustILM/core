package com.otilm.core.cbom.asset;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import java.util.Locale;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The storage fold, which decides every filterable column on an asset row.
 *
 * <p>
 * {@code normalized()} no longer feeds the identity key, so it is easy to read as incidental. It is not: it is the only
 * thing standing between a producer's spelling and what an {@code EQUALS} filter matches. Two mutations to its four
 * lines survive the rest of the suite -- reordering the case fold ahead of the first NFKC, and dropping
 * {@link Locale#ROOT} -- because every other fixture in the codebase uses plain lowercase ASCII, where neither bug can
 * show. Each case below fails under one of them.
 */
class CryptoAssetIdentityFieldsTest {

    /** Written as a cast rather than a {@code \\u0085} escape, which the compiler resolves before the lexer runs. */
    private static final char NEXT_LINE = (char) 0x0085;

    private static CryptoAssetIdentityFields withName(String name) {
        return new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, name, null, null, null, null, null, null,
                null, null);
    }

    /**
     * NFKC runs before the case fold, not after.
     *
     * <p>
     * A compatibility character carries no case mapping of its own, so folding first leaves it untouched and the
     * decomposition then yields an uppercase letter -- an uppercase result out of a case fold, and a column no
     * lowercase filter value can match.
     */
    @Test
    void aCompatibilityCharacterFoldsToLowercase() {
        assertThat(withName("𝐀𝐄𝐒").normalized().name())
                .describedAs("mathematical bold AES decomposes to AES, which must then be cased")
                .isEqualTo("aes");
    }

    /** The case fold is locale-independent, so every node of a cluster writes the same column value. */
    @Test
    void theCaseFoldIgnoresTheDefaultLocale() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr"));
            assertThat(withName("KYBER-I").normalized().name())
                    .describedAs("a Turkish default locale folds I to a dotless i, splitting the inventory by node")
                    .isEqualTo("kyber-i");
        } finally {
            Locale.setDefault(original);
        }
    }

    /**
     * Blank after folding is absent, not whitespace. Producers omit a field and send {@code ""} interchangeably, and
     * the fold must not let that formatting choice decide an {@code EMPTY} result set.
     */
    @Test
    void aFieldThatIsBlankAfterFoldingIsStoredAsAbsent() {
        assertThat(withName("   ").normalized().name()).isNull();
        assertThat(withName("").normalized().name()).isNull();
        assertThat(withName(null).normalized().name()).isNull();
        assertThat(withName("RSA ").normalized().name())
                .describedAs("a no-break space survives trim and would otherwise become a trailing ordinary space")
                .isEqualTo("rsa");
    }

    /**
     * The strip uses the reference's whitespace set, which NFKC does not make redundant.
     *
     * <p>
     * Three of the four code points the JDK disagrees on -- {@code U+00A0}, {@code U+202F}, {@code U+2007} -- decompose
     * to an ordinary space, so {@link String#strip()} removes them and the bug is invisible. {@code U+0085 NEXT LINE}
     * does not decompose and is not whitespace to {@link Character#isWhitespace}, so it is the one character that
     * reaches the column. The key is built without it, so the row would not match a filter on its own name.
     */
    @Test
    void aTrailingNextLineIsStrippedFromTheStoredColumn() {
        assertThat(withName("RSA" + NEXT_LINE).normalized().name())
                .describedAs("U+0085 has no NFKC decomposition and is not whitespace to the JDK")
                .isEqualTo("rsa");
    }

    /** Folding an already-folded value changes nothing, so a re-sync cannot move a row's columns. */
    @Test
    void theFoldIsIdempotent() {
        CryptoAssetIdentityFields once = withName("𝐀𝐄𝐒  ").normalized();

        assertThat(withName(once.name()).normalized().name()).isEqualTo(once.name());
    }

    /** The asset type is this platform's own enum constant, already canonical, and is passed through untouched. */
    @Test
    void theAssetTypeIsNotFolded() {
        assertThat(withName("AES").normalized().assetType()).isEqualTo(CryptographicAssetType.ALGORITHM);
    }
}
