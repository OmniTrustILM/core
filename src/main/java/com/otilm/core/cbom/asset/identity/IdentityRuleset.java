package com.otilm.core.cbom.asset.identity;

/**
 * The generation of the keying rules, stamped on every asset row.
 *
 * <p>
 * Deliberately not part of any pre-image: folding it in would re-key every row on a bump, re-migrating the whole
 * inventory, whereas recording it makes staleness a query. It is bumped whenever a ruling changes a key.
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
     * Generation 3 is the first generation an environment can actually hold: it is stamped from the commit that wires
     * ingest to {@code CryptoAssetWriter}. Generation 2 routed by asset-type tier and was never reachable from
     * production, and rulings changed keys while it stood -- the cipher-suite repair and the regenerated decision
     * tables among them -- so rows written from here are separated from the keys that generation would have produced.
     * Generation 1 framed ten typed fields, so every key this build writes differs from that generation's too.
     */
    public static final int VERSION = 3;

    private IdentityRuleset() {
    }
}
