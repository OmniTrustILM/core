package com.otilm.core.dao.repository.cbom;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.springframework.data.jpa.repository.Query;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The two statements that write a PQC verdict must write the same row.
 *
 * <p>
 * {@code applyPqcVerdict} is ingest's write and {@code applyPqcVerdictIfStale} is the sweep's; they differ only in the
 * guard on their {@code WHERE}, and their {@code SET} lists are the two-timestamp contract -- the
 * {@code pqc_decided_at} {@code CASE}, the {@code jsonb} cast, the {@code i_upd} bump. Nothing else pins them equal:
 * {@code CryptoAssetInventoryITest} pins the first, and the day someone edits one {@code CASE} and not the other,
 * ingest and the sweep write different row shapes for the same verdict and {@code decidedAt} dates itself differently
 * depending on which path wrote the row.
 *
 * <p>
 * A text comparison, deliberately: one statement with optional guards would make the guards themselves nullable
 * parameters, which is worse to read than a duplicate the build refuses to let diverge.
 */
class CryptoAssetPqcVerdictSqlTest {

    private static final Pattern SET_CLAUSE = Pattern.compile("(?s)\\bSET\\b(.*?)\\bWHERE\\b");

    @Test
    void theGuardedVerdictUpdateWritesExactlyWhatTheUnguardedOneWrites() {
        String unguarded = setClauseOf("applyPqcVerdict");

        assertThat(unguarded)
                .describedAs("the extraction has to have found the real SET list, or two empty strings would match")
                .contains("pqc_decided_at")
                .contains("i_upd = CURRENT_TIMESTAMP");
        assertThat(setClauseOf("applyPqcVerdictIfStale")).isEqualTo(unguarded);
    }

    private static String setClauseOf(String method) {
        Matcher matcher = SET_CLAUSE.matcher(queryOf(method));
        assertThat(matcher.find()).describedAs("%s has no SET ... WHERE", method).isTrue();
        return matcher.group(1).strip();
    }

    private static String queryOf(String method) {
        Method[] candidates = Arrays
                .stream(CryptoAssetRepository.class.getDeclaredMethods())
                .filter(candidate -> candidate.getName().equals(method))
                .toArray(Method[]::new);
        assertThat(candidates).describedAs("exactly one %s", method).hasSize(1);
        return candidates[0].getAnnotation(Query.class).value();
    }
}
