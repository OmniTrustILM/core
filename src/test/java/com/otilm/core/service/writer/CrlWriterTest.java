package com.otilm.core.service.writer;

import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CrlWriterTest {

    @Test
    void usesOnlyFixedStatementSizes_whenSplittingAnyRowCount() {
        // given
        var fixedSizes = List.of(1_000, 100, 10, 1);

        // when
        List<List<Integer>> splits = IntStream
                .rangeClosed(1, CrlWriter.ENTRIES_PER_STATEMENT)
                .mapToObj(CrlWriter::statementSizes)
                .toList();

        // then
        for (int rows = 1; rows <= CrlWriter.ENTRIES_PER_STATEMENT; rows++) {
            List<Integer> sizes = splits.get(rows - 1);
            assertThat(fixedSizes).containsAll(sizes);
            assertThat(sizes.stream().mapToInt(Integer::intValue).sum()).as("rows covered of %d", rows).isEqualTo(rows);
        }
    }

    @Test
    void splitsRemainderByDigits_whenRowCountIsNotRound() {
        // given
        var rows = 345;

        // when
        List<Integer> sizes = CrlWriter.statementSizes(rows);

        // then
        assertThat(sizes).containsExactly(100, 100, 100, 10, 10, 10, 10, 1, 1, 1, 1, 1);
    }
}
