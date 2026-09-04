package com.otilm.core.cbom.pqc;

/**
 * The generation of the PQC readiness rules, stamped on every verdict as {@code crypto_asset.pqc_ruleset_version}.
 *
 * <p>
 * <b>Not {@code IdentityRuleset.VERSION}.</b> The two answer different questions and move for different reasons: the
 * identity generation moves when a ruling changes what a row <em>is</em>, this one when a ruling changes what the
 * platform <em>says about</em> a row. Stamping one with the other would make a verdict re-evaluation look like a
 * re-keying, and the re-evaluation sweep's work list -- rows whose verdict generation is below this constant -- would
 * then select on a number nobody bumped for it.
 *
 * <p>
 * Bump it whenever a rule changes the verdict, rule id or evaluated fields any row would receive. The sweep is what
 * makes a bump safe to ship: every row stamped below the current constant is restamped, in batches, so a rolling deploy
 * cannot strand a verdict decided by rules that no longer exist.
 *
 * <p>
 * Generation 1 evaluates algorithms and related cryptographic material. Certificates, protocols and unroutable assets
 * are {@code NOT_APPLICABLE} in this generation, and that is a deferral rather than a finding -- a certificate's
 * algorithm reaches it only through {@code subjectPublicKeyRef}, which resolves at ingest and not from a stored row.
 */
public final class PqcRuleset {

    public static final int VERSION = 1;

    private PqcRuleset() {
    }
}
