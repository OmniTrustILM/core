package com.otilm.core.cbom.asset.identity;

/**
 * The generation of the keying rules, stamped on every asset row.
 *
 * <p>
 * Deliberately not part of any pre-image: folding it in would re-key every row on a bump, re-migrating the whole
 * inventory, whereas recording it makes staleness a query. It is bumped whenever a ruling changes a key.
 *
 * <p>
 * <b>One standing exemption, and it expires.</b> Rulings have changed keys since generation 2 was stamped without the
 * generation moving, because no environment holds a keyed row: {@code CryptoAssetWriter} has no production caller, so
 * there is nothing for a bump to make findable. That is the only ground on which the rule above may be skipped, and it
 * stops holding the moment ingest gains a caller -- after which a row keyed under the old rulings and a row keyed under
 * the new ones would both read generation 2, and the stamp would no longer separate them. Since a row cannot be
 * recomputed from its columns (see below), that separation cannot be reconstructed afterwards.
 *
 * <p>
 * The exemption is not left to a reader's diligence: {@code IdentityRulesetStampArchTest} asserts the writer is
 * unreachable from production, so wiring ingest turns the build red and forces the bump then rather than never. Do not
 * delete that test to make the build green -- bump this constant, and delete the test in the same commit.
 *
 * <p>
 * Note what the stamp can and cannot buy. A row keyed on a certificate's distinguished-name composite cannot be
 * re-keyed from the stored columns, because the composite's inputs -- subject, issuer, validity, public key -- are not
 * columns. A stale row is therefore <em>findable</em> but not recomputable: repairing it means re-ingesting its source
 * document, which is the sync path's job rather than a sweep over the asset table.
 *
 * <p>
 * It lives apart from {@code CryptoAssetIdentity} because the persistence layer stamps rows with it and must not
 * therefore depend on the ratified decision tables, which the chain loads and the writer has no use for.
 */
public final class IdentityRuleset {

    /**
     * Generation 2 routes by asset-type tier. Generation 1 framed ten typed fields, so every key this build writes
     * differs from that generation's.
     */
    public static final int VERSION = 2;

    private IdentityRuleset() {
    }
}
