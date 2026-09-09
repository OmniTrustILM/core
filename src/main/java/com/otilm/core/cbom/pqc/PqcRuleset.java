package com.otilm.core.cbom.pqc;

/**
 * Stamped on every verdict as {@code crypto_asset.pqc_ruleset_version}. Bump it whenever a rule changes any row's
 * verdict, rule id or evidence; the sweep restamps everything below it. A change to the identity tables can move a
 * verdict with no rule changing, and the artifact digest pinned by {@code PqcFamiliesTest} is what forces that re-read.
 *
 * <p>
 * Not {@code IdentityRuleset.VERSION}: that one moves when a row's identity changes, this one when what the platform
 * says about the row changes. Sharing them would make a re-evaluation look like a re-keying.
 */
public final class PqcRuleset {

    public static final int VERSION = 5;

    private PqcRuleset() {
    }
}
