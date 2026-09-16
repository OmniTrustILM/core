package com.otilm.core.cbom.ingest;

import com.otilm.core.cbom.asset.identity.CbomAssetExtractor;
import com.otilm.core.model.cbom.CbomIngestFindingKind;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The report's shape, as a pure function of one extraction.
 *
 * <p>
 * Tested without a database or a document: what is decided here is how many rows a hostile document can cause, which of
 * them survive the bound, and whether a re-ingest of the same document writes the same rows -- none of which a Spring
 * context makes clearer.
 */
class IngestFindingRollupTest {

    @Test
    void theSameFindingFromManyComponentsIsOneRowWithACountAndAnExample() {
        IngestFindingRollup.Rollup report = IngestFindingRollup
                .of(extraction(List
                        .of(asset("first", "a key material value was dropped"),
                                asset("second", "a key material value was dropped"),
                                asset("third", "a key material value was dropped")),
                        List.of(), List.of()));

        assertThat(report.rows()).singleElement().satisfies(row -> {
            assertThat(row.kind()).isEqualTo(CbomIngestFindingKind.FINDING);
            assertThat(row.occurrences()).isEqualTo(3);
            assertThat(row.componentName()).isEqualTo("first");
            assertThat(row.detail()).isEqualTo("a key material value was dropped");
        });
        assertThat(report.dropped()).isZero();
    }

    /** A skip is what yielded no asset at all, and it names the failure class rather than the payload. */
    @Test
    void skipsAreTheirOwnKind() {
        IngestFindingRollup.Rollup report = IngestFindingRollup
                .of(extraction(List.of(), List.of(new CbomAssetExtractor.Skip("broken", "IllegalArgumentException")),
                        List.of()));

        assertThat(report.rows()).singleElement().satisfies(row -> {
            assertThat(row.kind()).isEqualTo(CbomIngestFindingKind.SKIP);
            assertThat(row.componentName()).isEqualTo("broken");
            assertThat(row.detail()).contains("IllegalArgumentException");
        });
    }

    /** A duplicated ref is a property of the document's reference graph, so no one component answers for it. */
    @Test
    void aDuplicatedRefIsReportedWithoutAComponent() {
        IngestFindingRollup.Rollup report = IngestFindingRollup.of(extraction(List.of(), List.of(), List.of("dup")));

        assertThat(report.rows()).singleElement().satisfies(row -> {
            assertThat(row.componentName()).isNull();
            assertThat(row.detail())
                    .isEqualTo("bom-ref dup is defined more than once, and CycloneDX requires it to be unique");
        });
    }

    /**
     * A finding names the producer member it is about, so distinct messages are as unbounded as the document. The bound
     * keeps the most frequent, counts the rest, and -- being per kind -- cannot let findings crowd out the record of
     * what could not be extracted at all.
     */
    @Test
    void aFloodOfDistinctFindingsIsBoundedWithoutCostingTheSkips() {
        List<CbomAssetExtractor.ExtractedAsset> assets = new ArrayList<>();
        for (int index = 0; index < IngestFindingRollup.MAX_ROWS_PER_KIND + 5; index++) {
            assets.add(asset("component-" + index, "member " + index + " was dropped"));
        }
        assets.add(asset("loudest", "the same thing happened twice"));
        assets.add(asset("also", "the same thing happened twice"));

        IngestFindingRollup.Rollup report = IngestFindingRollup
                .of(extraction(assets, List.of(new CbomAssetExtractor.Skip("broken", "IllegalStateException")),
                        List.of()));

        assertThat(report.rows())
                .filteredOn(row -> row.kind() == CbomIngestFindingKind.FINDING)
                .hasSize(IngestFindingRollup.MAX_ROWS_PER_KIND);
        // 105 distinct dropped-member messages plus the repeated one, against a bound of 100.
        assertThat(report.dropped()).isEqualTo(6);
        assertThat(report.rows().get(0).detail())
                .describedAs("the most frequent message is the one that survives first")
                .isEqualTo("the same thing happened twice");
        assertThat(report.rows()).filteredOn(row -> row.kind() == CbomIngestFindingKind.SKIP).hasSize(1);
    }

    /**
     * {@code detail} is a column of the report's unique index, and a btree tuple wider than about 2704 bytes is
     * refused. The text is producer-derived and neither CycloneDX nor the extractor bounds it, so without this an
     * over-long {@code bom-ref} is a producer-chosen way to make the insert fail.
     */
    @Test
    void anOverlongMessageIsCutToTheBoundAndSaysSo() {
        IngestFindingRollup.Rollup report = IngestFindingRollup
                .of(extraction(List.of(), List.of(), List.of("r".repeat(4000))));

        String detail = report.rows().getFirst().detail();
        assertThat(detail).hasSize(IngestFindingRollup.MAX_DETAIL_LENGTH);
        assertThat(detail).endsWith(IngestFindingRollup.TRUNCATION_MARKER);
    }

    /**
     * Cutting between the halves of a surrogate pair would leave a string with no UTF-8 encoding, which the column
     * refuses outright -- the cure would be the disease.
     */
    @Test
    void theCutFallsOnACodePointBoundary() {
        String astral = "\uD83D\uDD10".repeat(2000);

        IngestFindingRollup.Rollup report = IngestFindingRollup
                .of(extraction(List.of(asset("c", astral)), List.of(), List.of()));

        assertThat(isWellPaired(report.rows().getFirst().detail()))
                .describedAs("no half of a pair survives alone")
                .isTrue();
    }

    @Test
    void anOverlongComponentNameIsCutToo() {
        IngestFindingRollup.Rollup report = IngestFindingRollup
                .of(extraction(List.of(asset("n".repeat(4000), "something happened")), List.of(), List.of()));

        assertThat(report.rows().getFirst().componentName())
                .hasSize(IngestFindingRollup.MAX_COMPONENT_NAME_LENGTH)
                .endsWith(IngestFindingRollup.TRUNCATION_MARKER);
    }

    private static boolean isWellPaired(String text) {
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            if (Character.isHighSurrogate(character)) {
                if (index + 1 == text.length() || !Character.isLowSurrogate(text.charAt(index + 1))) {
                    return false;
                }
                index++;
            } else if (Character.isLowSurrogate(character)) {
                return false;
            }
        }
        return true;
    }

    private static CbomAssetExtractor.Extraction extraction(List<CbomAssetExtractor.ExtractedAsset> assets,
            List<CbomAssetExtractor.Skip> skips, List<String> ambiguousRefs) {
        return new CbomAssetExtractor.Extraction(assets, skips, false, false, ambiguousRefs);
    }

    /** Only the component name and the findings are read here, so the rest of the record is left out. */
    private static CbomAssetExtractor.ExtractedAsset asset(String componentName, String finding) {
        return new CbomAssetExtractor.ExtractedAsset(null, null, null, componentName, null, null, 0, null,
                List.of(finding));
    }
}
