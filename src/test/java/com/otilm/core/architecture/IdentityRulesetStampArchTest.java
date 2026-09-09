package com.otilm.core.architecture;

import com.otilm.core.cbom.asset.identity.IdentityRuleset;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.core.importer.Location;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * A tripwire, not an architectural rule: it exists to expire.
 *
 * <p>
 * {@link IdentityRuleset#VERSION} is stamped on every asset row so a row keyed under superseded rulings stays findable,
 * and its contract is that it moves whenever a ruling changes a key. Rulings have changed keys since generation 2 was
 * stamped without the generation moving, on one ground only: no environment holds a keyed row, because
 * {@link CryptoAssetWriter} has no production caller, so there is no row for a bump to make findable.
 *
 * <p>
 * That ground is a fact about the wiring, and nothing about the wiring announces its own change. Once ingest gains a
 * caller, a row keyed under the old rulings and a row keyed under the new ones both read generation 2, and the stamp
 * stops separating them -- irreversibly, because a row cannot be recomputed from its columns, only re-ingested. So the
 * exemption is asserted rather than remembered: wiring the writer turns this red at the moment the decision is actually
 * due.
 *
 * <p>
 * <b>When this fails, the fix is not to delete it.</b> Bump {@link IdentityRuleset#VERSION}, then delete this class in
 * the same commit -- the tripwire has done its work and the unconditional rule applies again from there.
 */
@AnalyzeClasses(packages = "com.otilm.core", importOptions = IdentityRulesetStampArchTest.OnlyThisModule.class)
class IdentityRulesetStampArchTest {

    /**
     * Exempts the class, not its package. A package exemption would have covered the four sibling writers that already
     * coordinate with each other, so an ingest orchestrator placed beside them -- the natural home, given that
     * coordination -- would wire the writer into production with this tripwire still green, at the one moment the
     * exemption depends on it firing.
     */
    @ArchTest
    static final ArchRule theAssetWriterIsStillUnreachableFromProduction = noClasses()
            .that()
            .doNotHaveFullyQualifiedName(CryptoAssetWriter.class.getName())
            .should()
            .dependOnClassesThat()
            .haveFullyQualifiedName(CryptoAssetWriter.class.getName())
            .because("IdentityRuleset.VERSION stays at a generation whose rulings have since moved, which is sound "
                    + "only while no environment holds a keyed row; the first production caller of CryptoAssetWriter "
                    + "ends that, so bump IdentityRuleset.VERSION and delete IdentityRulesetStampArchTest in the "
                    + "same commit");

    /**
     * Restricts the import to this module's own output, the way the sibling fences do: the {@code interfaces} artifact
     * publishes into {@code com.otilm.core} too, and its classes are not ours to constrain.
     */
    static class OnlyThisModule implements ImportOption {

        @Override
        public boolean includes(Location location) {
            return location.contains("/target/classes/");
        }
    }
}
