package com.otilm.core.cbom.asset;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.core.cbom.asset.identity.AsciiText;
import com.otilm.core.cbom.asset.identity.NormalizedAsset;
import java.text.Normalizer;
import java.util.Locale;

/**
 * The typed columns an asset row carries: the asset type and the nine producer-supplied identity fields.
 *
 * <p>
 * These are what the inventory <em>filters</em> on. They are no longer the input to the identity key -- the ratified
 * key is routed by asset type and built from the whole component, including evidence a column cannot hold -- so this
 * record describes the row rather than determining it.
 */
public record CryptoAssetIdentityFields(CryptographicAssetType assetType, String name, String oid,
        String algorithmFamily, String primitive, String parameterSet, String curve, String mode, String padding,
        String variant) {

    /**
     * The canonical form the platform stores: every producer-text field folded, and a field that is blank after folding
     * stored as absent rather than as whitespace.
     *
     * <p>
     * Storing this rather than the raw input is what makes a filter answer independent of ingest order. The row's
     * columns used to be reassigned from whichever producer synced last, so an {@code EQUALS} predicate matched or
     * missed depending on sync order, and a field one producer omitted and another sent as {@code "  "} moved the row
     * in and out of an {@code EMPTY} result set. Nine of the fourteen crypto-asset filter fields were exposed to that.
     *
     * <p>
     * <b>What this does not buy, corrected.</b> This method used to claim the stored row was sufficient to re-derive
     * its own key, so a staleness sweep could re-key from the columns alone. That is false under the ratified rules and
     * was false the moment the identity chain became tier-routed. A certificate keyed on the distinguished-name
     * composite hashes subject, issuer, both validity bounds and a resolved public key; none of those five is a column.
     * So {@code ruleset_version} still makes a stale row <em>findable</em>, but repairing one means re-ingesting its
     * source document -- which is the sync path's job, not a sweep over this table.
     *
     * <p>
     * The fold is NFKC, then case, then NFKC again. The order is not interchangeable: a compatibility character has no
     * case mapping of its own, so folding first leaves {@code U+1D400 MATHEMATICAL BOLD CAPITAL A} untouched and NFKC
     * then yields {@code A} -- an uppercase result out of a case fold. The second pass exists because a full case
     * mapping can itself emit an unnormalised sequence. Case folding uses {@link Locale#ROOT}, never the platform
     * default: a Turkish-locale JVM folds {@code I} to a dotless {@code i}, so two nodes of one cluster would write
     * different values into the same column.
     *
     * <p>
     * Stripping happens <em>after</em> NFKC and uses {@link String#strip()} rather than {@link String#trim()}, because
     * both orders and both methods decide different things about Unicode space: {@code trim} removes only characters at
     * or below {@code U+0020}, so a trailing {@code U+00A0 NO-BREAK SPACE} would survive it and NFKC would then turn it
     * into an ordinary trailing space -- storing {@code "RSA "} where another producer stored {@code "RSA"}.
     *
     * <p>
     * {@code assetType} is passed through: it is this platform's own enum constant, already canonical, and running the
     * producer-text fold over it would imply it is producer text.
     */
    /**
     * The columns a normalized asset becomes, before folding.
     *
     * <p>
     * This is the one place the derivation's shape and the row's shape are stated against each other, and it exists
     * because both the ingest path (core#2073) and the PQC re-evaluation sweep depend on them agreeing. The sweep reads
     * a stored row and must reach the verdict ingest would have reached in memory; if these two shapes drift, the two
     * answers drift with them, silently and only for the assets whose derivation touched the field that moved.
     *
     * <p>
     * {@code parameterSet} is the drift most likely to happen: {@link NormalizedAsset#parameterSet()} is an
     * {@code Integer} and this column is text, so a rule comparing a stored {@code "2048"} against a derived
     * {@code 2048} would be false for every RSA key in the inventory while looking correct.
     */
    public static CryptoAssetIdentityFields of(CryptographicAssetType assetType, NormalizedAsset asset) {
        return new CryptoAssetIdentityFields(assetType, asset.name(), asset.oid(), asset.family(), asset.primitive(),
                asset.parameterSet() == null ? null : String.valueOf(asset.parameterSet()), asset.curve(), asset.mode(),
                asset.padding(), asset.variant());
    }

    public CryptoAssetIdentityFields normalized() {
        return new CryptoAssetIdentityFields(assetType, fold(name), fold(oid), fold(algorithmFamily), fold(primitive),
                fold(parameterSet), fold(curve), fold(mode), fold(padding), fold(variant));
    }

    /**
     * Folds one producer-supplied field for storage, or returns {@code null} for a field that carries no value.
     *
     * <p>
     * A field that is blank after folding is <em>absent</em>, and absent is distinct from every present value:
     * producers omit a field and emit {@code ""} interchangeably, and treating those as different would split the
     * inventory on a formatting choice.
     *
     * <p>
     * The strip is {@link AsciiText#strip} rather than {@link String#strip()}, and NFKC does not make the two
     * equivalent. NFKC maps {@code U+00A0}, {@code U+202F} and {@code U+2007} onto an ordinary space, so the JDK strip
     * removes them -- but {@code U+0085 NEXT LINE} has no NFKC decomposition and is not whitespace to
     * {@link Character#isWhitespace}. A trailing one therefore survived into the stored column while the key was built
     * from the value without it, so {@code name EQUALS rsa} missed the row it had keyed.
     */
    static String fold(String raw) {
        if (raw == null) {
            return null;
        }
        String stripped = AsciiText.strip(Normalizer.normalize(raw, Normalizer.Form.NFKC));
        if (stripped.isEmpty()) {
            return null;
        }
        return Normalizer.normalize(stripped.toLowerCase(Locale.ROOT), Normalizer.Form.NFKC);
    }
}
