package com.otilm.core.cbom.ingest;

import com.otilm.core.cbom.asset.identity.CbomAssetExtractor;
import com.otilm.core.model.cbom.CbomIngestFindingKind;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Turns one extraction's findings and skips into the handful of rows a CBOM's ingest report holds.
 *
 * <p>
 * A pure function over the extraction, so the rule it encodes -- what is rolled up, in what order, and what is dropped
 * when a document raises more distinct messages than a report can hold -- is testable without a database, a document or
 * a Spring context.
 *
 * <p>
 * <b>Rolled up per distinct message.</b> A document reports the same finding for every component of a kind: one real
 * document raises one withheld-digest finding per certificate, and storing a row each would write thousands of
 * identical lines. The count is the useful part, and one component name is what a producer needs to find the rest.
 *
 * <p>
 * <b>And bounded.</b> A finding names the producer member it is about, so a document carrying a thousand distinct
 * member names carries a thousand distinct messages -- unbounded input deciding how many rows an ingest writes. Each
 * kind keeps its {@link #MAX_ROWS_PER_KIND} most frequent messages and the rest are counted, not stored; the caller
 * says so in the log, which is where {@code cbom_sync_skip} already puts a write-off.
 */
public final class IngestFindingRollup {

    /**
     * How many distinct messages of one kind a report keeps.
     *
     * <p>
     * Per kind rather than over the whole report, or a document with a hundred distinct findings would crowd out every
     * record of what it could not extract at all -- the half an operator is more likely to act on.
     */
    public static final int MAX_ROWS_PER_KIND = 100;

    /**
     * How long a message may be.
     *
     * <p>
     * {@code detail} is a column of the report's unique index, and PostgreSQL refuses a btree tuple wider than about
     * 2704 bytes. The text is producer-derived -- a finding names the member it is about, and a duplicated
     * {@code bom-ref} is quoted whole -- and neither CycloneDX nor the extractor bounds either, so an unbounded message
     * is a producer-chosen way to make the insert fail. 512 code points is at most 2048 bytes of UTF-8, which leaves
     * the rest of the tuple room.
     */
    static final int MAX_DETAIL_LENGTH = 512;

    /** As {@code crypto_asset.name}, which is the same producer text arriving by another path. */
    static final int MAX_COMPONENT_NAME_LENGTH = 1024;

    /** Says the message was cut, so a reader does not take a truncated member name for the whole one. */
    static final String TRUNCATION_MARKER = "[...]";

    private IngestFindingRollup() {
    }

    /** One rolled-up line: a message, how many components raised it, and one of them by name. */
    public record Row(CbomIngestFindingKind kind, String componentName, String detail, int occurrences) {
    }

    /**
     * The report, and how many distinct messages did not fit into it.
     *
     * <p>
     * {@code dropped} is the count of distinct messages left out, not of components: the components they speak for are
     * counted inside the rows that were kept only when they raised a kept message.
     */
    public record Rollup(List<Row> rows, int dropped) {
    }

    /**
     * Rolls up everything the extraction has to report.
     *
     * <p>
     * A duplicated {@code bom-ref} is a document-level finding and carries no component name: it is a property of the
     * document's reference graph, not of any one component, and it is the reason the ingest refuses the document
     * outright -- see {@link CbomAssetIngestService}.
     */
    public static Rollup of(CbomAssetExtractor.Extraction extraction) {
        final Map<String, Row> findings = new LinkedHashMap<>();
        for (String ref : extraction.ambiguousRefs()) {
            add(findings, CbomIngestFindingKind.FINDING, null,
                    "bom-ref %s is defined more than once, and CycloneDX requires it to be unique".formatted(ref));
        }
        for (CbomAssetExtractor.ExtractedAsset asset : extraction.assets()) {
            for (String finding : asset.findings()) {
                add(findings, CbomIngestFindingKind.FINDING, asset.componentName(), finding);
            }
        }
        final Map<String, Row> skips = new LinkedHashMap<>();
        for (CbomAssetExtractor.Skip skip : extraction.skips()) {
            add(skips, CbomIngestFindingKind.SKIP, skip.componentName(),
                    "the component could not be turned into an asset: " + skip.reason());
        }

        final List<Row> rows = new ArrayList<>();
        int dropped = keepMostFrequent(findings, rows) + keepMostFrequent(skips, rows);
        return new Rollup(List.copyOf(rows), dropped);
    }

    private static void add(Map<String, Row> rolled, CbomIngestFindingKind kind, String rawComponentName,
            String rawDetail) {
        final String detail = bounded(rawDetail, MAX_DETAIL_LENGTH);
        final String componentName = bounded(rawComponentName, MAX_COMPONENT_NAME_LENGTH);
        final Row seen = rolled.get(detail);
        if (seen == null) {
            rolled.put(detail, new Row(kind, componentName, detail, 1));
            return;
        }
        // The first component in document order stays the example: which one is arbitrary, and a stable choice keeps
        // a re-ingest of the same document writing the same row.
        rolled.put(detail, new Row(kind, seen.componentName(), detail, seen.occurrences() + 1));
    }

    /**
     * The text as the column will hold it: cut to the bound, on a code-point boundary, with the cut marked.
     *
     * <p>
     * Cut rather than refused, because the report is advisory -- refusing it would cost the document its ingest for a
     * message about the document. On a code-point boundary because splitting a surrogate pair leaves a string with no
     * UTF-8 encoding, which the column refuses outright: the cure would be the disease. Two distinct messages that
     * agree for their first {@link #MAX_DETAIL_LENGTH} code points roll up as one, which is the right answer for text
     * whose tail an operator will not see anyway.
     *
     * <p>
     * Measured in code points throughout, because that is the unit PostgreSQL's {@code length()} counts and so the unit
     * the CHECK constraints are written in. Measuring the guard in UTF-16 units instead would still never fail an
     * insert -- code points never outnumber units -- but it would cut a message of astral characters to half the
     * content the column would have taken.
     */
    private static String bounded(String text, int maxLength) {
        if (text == null || text.codePointCount(0, text.length()) <= maxLength) {
            return text;
        }
        final int keep = maxLength - TRUNCATION_MARKER.length();
        return text.substring(0, text.offsetByCodePoints(0, keep)) + TRUNCATION_MARKER;
    }

    /** Adds this kind's most frequent messages to the report and answers how many were left out. */
    private static int keepMostFrequent(Map<String, Row> rolled, List<Row> rows) {
        rolled
                .values()
                .stream()
                .sorted(Comparator.comparingInt(Row::occurrences).reversed().thenComparing(Row::detail))
                .limit(MAX_ROWS_PER_KIND)
                .forEach(rows::add);
        return Math.max(0, rolled.size() - MAX_ROWS_PER_KIND);
    }
}
