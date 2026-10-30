package com.otilm.core.cbom.asset;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.otilm.core.cbom.asset.identity.Occurrences;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Bounds the occurrence evidence retained for one CBOM's contribution to one asset.
 *
 * <p>
 * Capping <b>drops</b>; it never truncates. The CycloneDX 1.7 schema documents an occurrence's
 * {@code additionalContext} as "e.g. a code snippet", and at a secret-scanner finding the snippet <em>is</em> the
 * secret line -- a truncated secret is still a secret, and a truncated one is worse than none because it looks handled.
 * The same rule holds for every other field: an occurrence that will not fit is removed whole rather than shortened.
 *
 * <p>
 * Applied in order:
 * <ol>
 * <li>keep at most {@link #MAX_OCCURRENCES}, in producer order;</li>
 * <li>remove {@code additionalContext} entirely, at every depth, from every retained occurrence -- always, not only
 * when the budget is exceeded, because whether a secret reaches a stored column must not depend on how large the rest
 * of the array happened to be;</li>
 * <li>if the rendering still exceeds {@link #MAX_EVIDENCE_BYTES}, drop whole occurrences from the tail until it
 * fits.</li>
 * </ol>
 *
 * <p>
 * The caller records the <em>unclipped</em> occurrence count on the row, so the gap between that count and the retained
 * array is the visible record that capping happened. No separate flag is needed, and none can drift.
 */
public final class OccurrenceEvidenceCapper {

    /** Enough occurrences to characterise a finding; far short of enough to make the row a document store. */
    public static final int MAX_OCCURRENCES = 50;

    /** Budget for the rendered evidence array of a single source row. */
    public static final int MAX_EVIDENCE_BYTES = 64 * 1024;

    static final String ADDITIONAL_CONTEXT = "additionalContext";
    static final String LOCATION = "location";

    private static final ObjectWriter WRITER = ObjectMapperFactory.jsonColumn().writer();

    private OccurrenceEvidenceCapper() {
    }

    /**
     * The evidence to store for the given occurrences. {@code null} in, {@code null} out: a source that reported no
     * evidence is distinct from one that reported evidence which capping emptied.
     */
    public static List<Map<String, Object>> cap(List<Map<String, Object>> occurrences) {
        if (occurrences == null) {
            return null;
        }
        // A JSON array may legally contain a null element, which parses to a null entry carrying no evidence at all.
        // Dropping it keeps the document ingestible; leaving it in throws from List.copyOf, which rejects nulls, or
        // from the strip below -- an unshaped NullPointerException that would fail the whole source upsert.
        List<Map<String, Object>> present = occurrences.stream().filter(Objects::nonNull).toList();
        List<Map<String, Object>> kept = new ArrayList<>(
                present.size() > MAX_OCCURRENCES ? present.subList(0, MAX_OCCURRENCES) : present);
        // Unconditionally, not only under budget pressure. The snippet at a secret-scanner finding IS the secret
        // line, so whether it reaches a stored column must not depend on how large the rest of the array happened to
        // be -- a single small occurrence kept `AWS_SECRET_ACCESS_KEY = "..."` verbatim in a column the read surface
        // serves back.
        kept.replaceAll(OccurrenceEvidenceCapper::withoutAdditionalContext);
        while (!kept.isEmpty() && renderedSize(kept) > MAX_EVIDENCE_BYTES) {
            kept.removeLast();
        }
        return List.copyOf(kept);
    }

    /**
     * The occurrence without {@code additionalContext} at any depth. Depth matters: a producer nesting the snippet one
     * level down would otherwise keep it, and the nested snippet is the same secret.
     */
    private static Map<String, Object> withoutAdditionalContext(Map<String, Object> occurrence) {
        Map<String, Object> stripped = new LinkedHashMap<>();
        occurrence.forEach((key, value) -> {
            if (ADDITIONAL_CONTEXT.equals(key)) {
                return;
            }
            stripped.put(key, LOCATION.equals(key) ? sanitizeLocation(value) : strip(value));
        });
        return stripped;
    }

    private static String sanitizeLocation(Object value) {
        return value instanceof String location ? Occurrences.sanitizeLocation(location) : "";
    }

    @SuppressWarnings("unchecked")
    private static Object strip(Object value) {
        if (value instanceof Map<?, ?> map) {
            return withoutAdditionalContext((Map<String, Object>) map);
        }
        if (value instanceof Collection<?> collection) {
            return collection.stream().map(OccurrenceEvidenceCapper::strip).toList();
        }
        return value;
    }

    private static int renderedSize(List<Map<String, Object>> occurrences) {
        try {
            return WRITER.writeValueAsBytes(occurrences).length;
        } catch (JsonProcessingException e) {
            // The evidence came from parsed JSON, so it is maps, lists and scalars; nothing here can fail to
            // serialize. The message deliberately carries no evidence content.
            throw new IllegalStateException("Occurrence evidence could not be rendered for capping");
        }
    }
}
