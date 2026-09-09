package com.otilm.core.cbom.asset;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OccurrenceEvidenceCapperTest {

    private static final String SECRET_MARKER = "AKIA-SECRET-MARKER";

    private static Map<String, Object> occurrence(String location, String additionalContext) {
        Map<String, Object> occurrence = new LinkedHashMap<>();
        occurrence.put("location", location);
        occurrence.put("line", 42);
        if (additionalContext != null) {
            occurrence.put("additionalContext", additionalContext);
        }
        return occurrence;
    }

    private static Map<String, Object> occurrenceWithDetail(String location, String detail) {
        Map<String, Object> occurrence = occurrence(location, null);
        occurrence.put("detail", detail);
        return occurrence;
    }

    private static String snippet(int length) {
        return SECRET_MARKER + "x".repeat(length);
    }

    private static String render(List<Map<String, Object>> evidence) {
        return String.valueOf(JsonColumnText.render(evidence));
    }

    @Test
    void noEvidenceStaysNoEvidence() {
        assertThat(OccurrenceEvidenceCapper.cap(null))
                .describedAs("a source that reported nothing differs from one whose evidence capping emptied")
                .isNull();
        assertThat(OccurrenceEvidenceCapper.cap(List.of())).isEmpty();
    }

    @Test
    void evidenceWithinBothBudgetsKeepsEveryOccurrenceButNeverTheSnippet() {
        List<Map<String, Object>> occurrences = List
                .of(occurrence("src/a.java", "one line of context"), occurrence("src/b.java", null));

        List<Map<String, Object>> capped = OccurrenceEvidenceCapper.cap(occurrences);

        assertThat(capped)
                .describedAs("both occurrences are retained -- neither budget was exceeded")
                .isEqualTo(List.of(occurrence("src/a.java", null), occurrence("src/b.java", null)))
                .describedAs("the snippet goes even under budget: at a secret-scanner finding it IS the secret, so "
                        + "whether it reaches a stored column must not depend on how large the rest of the array was")
                .noneMatch(occurrence -> occurrence.containsKey("additionalContext"));
    }

    @Test
    void storedLocationsAreSanitizedEvenWhenEvidenceFits() {
        List<Map<String, Object>> capped = OccurrenceEvidenceCapper
                .cap(List.of(occurrence("https://user:p@ss@host/path?token=secret#fragment", null)));

        assertThat(capped).containsExactly(occurrence("https://host/path", null));
        assertThat(render(capped))
                .doesNotContain("user")
                .doesNotContain("p@ss")
                .doesNotContain("token=secret")
                .doesNotContain("fragment");
    }

    @Test
    void aLoneSmallOccurrenceStillLosesItsSnippet() {
        List<Map<String, Object>> capped = OccurrenceEvidenceCapper
                .cap(List.of(occurrence("src/a.java", SECRET_MARKER + " = \"AKIAIOSFODNN7EXAMPLE\"")));

        assertThat(render(capped))
                .describedAs("one occurrence, far below every budget -- the branch that used to retain it verbatim")
                .doesNotContain(SECRET_MARKER);
    }

    /** The cap is inclusive: exactly {@code MAX_OCCURRENCES} keeps every one, and one more loses exactly one. */
    @Test
    void theCapIsInclusive() {
        List<Map<String, Object>> atCap = new ArrayList<>();
        for (int i = 0; i < OccurrenceEvidenceCapper.MAX_OCCURRENCES; i++) {
            atCap.add(occurrence("src/file" + i + ".java", null));
        }
        List<Map<String, Object>> oneOver = new ArrayList<>(atCap);
        oneOver.add(occurrence("src/one-over.java", null));

        assertThat(OccurrenceEvidenceCapper.cap(atCap)).hasSize(OccurrenceEvidenceCapper.MAX_OCCURRENCES);
        assertThat(OccurrenceEvidenceCapper.cap(oneOver))
                .hasSize(OccurrenceEvidenceCapper.MAX_OCCURRENCES)
                .noneMatch(kept -> "src/one-over.java".equals(kept.get("location")));
    }

    @Test
    void tooManyOccurrencesAreCutToTheCapInProducerOrder() {
        List<Map<String, Object>> occurrences = new ArrayList<>();
        for (int i = 0; i < OccurrenceEvidenceCapper.MAX_OCCURRENCES + 25; i++) {
            occurrences.add(occurrence("src/file" + i + ".java", null));
        }

        List<Map<String, Object>> capped = OccurrenceEvidenceCapper.cap(occurrences);

        assertThat(capped).hasSize(OccurrenceEvidenceCapper.MAX_OCCURRENCES);
        assertThat(capped.getFirst()).containsEntry("location", "src/file0.java");
        assertThat(capped.getLast())
                .containsEntry("location", "src/file" + (OccurrenceEvidenceCapper.MAX_OCCURRENCES - 1) + ".java");
    }

    @Test
    void anOversizedSnippetIsDroppedWholeAndNeverTruncated() {
        List<Map<String, Object>> occurrences = List
                .of(occurrence("src/a.java", snippet(OccurrenceEvidenceCapper.MAX_EVIDENCE_BYTES)),
                        occurrence("src/b.java", "short context"));

        List<Map<String, Object>> capped = OccurrenceEvidenceCapper.cap(occurrences);

        assertThat(capped).hasSize(2);
        assertThat(capped).allSatisfy(occurrence -> assertThat(occurrence).doesNotContainKey("additionalContext"));
        assertThat(render(capped))
                .describedAs("at a secret-scanner finding the snippet is the secret line; a truncated secret is "
                        + "still a secret")
                .doesNotContain(SECRET_MARKER);
        assertThat(capped.getFirst()).containsEntry("location", "src/a.java").containsEntry("line", 42);
    }

    @Test
    void aNestedSnippetIsDroppedToo() {
        Map<String, Object> nested = new LinkedHashMap<>();
        nested.put("evidence", occurrence("src/inner.java", snippet(OccurrenceEvidenceCapper.MAX_EVIDENCE_BYTES)));
        nested.put("location", "src/outer.java");

        List<Map<String, Object>> capped = OccurrenceEvidenceCapper.cap(List.of(nested));

        assertThat(render(capped))
                .describedAs("a producer nesting the snippet one level down still nests the same secret")
                .doesNotContain(SECRET_MARKER);
        assertThat(capped).isNotEmpty();
    }

    @Test
    void whatWillNotFitWithoutSnippetsIsDroppedOccurrenceByOccurrenceFromTheTail() {
        // Ten occurrences with an oversized non-location field each: no additionalContext to drop, so whole
        // occurrences go. Location is different because the published contract caps it at 1024 characters.
        List<Map<String, Object>> occurrences = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            occurrences
                    .add(occurrenceWithDetail("marker" + i,
                            "y".repeat(OccurrenceEvidenceCapper.MAX_EVIDENCE_BYTES / 8)));
        }

        List<Map<String, Object>> capped = OccurrenceEvidenceCapper.cap(occurrences);

        assertThat(capped).hasSizeLessThan(occurrences.size()).isNotEmpty();
        assertThat(render(capped)).hasSizeLessThanOrEqualTo(OccurrenceEvidenceCapper.MAX_EVIDENCE_BYTES + 64);
        assertThat(capped.getFirst()).isEqualTo(occurrences.getFirst());
        assertThat(render(capped))
                .describedAs("dropping is from the tail, so the earliest occurrences survive")
                .contains("marker0");
    }

    @Test
    void oneOccurrenceTooBigToStoreLeavesNoEvidenceRatherThanAFragment() {
        List<Map<String, Object>> occurrences = List
                .of(occurrenceWithDetail("src/a.java", "x".repeat(OccurrenceEvidenceCapper.MAX_EVIDENCE_BYTES * 2)));

        assertThat(OccurrenceEvidenceCapper.cap(occurrences))
                .describedAs("the occurrence count on the row still records that it was seen")
                .isEmpty();
    }

    /**
     * A JSON array may legally contain a null element. It used to reach {@code List.copyOf}, which rejects nulls, and
     * the unshaped NullPointerException failed the whole source upsert.
     */
    @Test
    void aNullOccurrenceIsDroppedRatherThanThrown() {
        java.util.List<java.util.Map<String, Object>> withNull = new java.util.ArrayList<>();
        withNull.add(java.util.Map.of("location", "a.java"));
        withNull.add(null);

        assertThat(OccurrenceEvidenceCapper.cap(withNull))
                .describedAs("the occurrence that carries evidence survives; the one that carries none is dropped")
                .containsExactly(java.util.Map.of("location", "a.java"));
    }
}
