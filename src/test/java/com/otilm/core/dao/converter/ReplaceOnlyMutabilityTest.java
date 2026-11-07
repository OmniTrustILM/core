package com.otilm.core.dao.converter;

import java.io.Serializable;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ReplaceOnlyMutabilityTest {

    private final ReplaceOnlyMutability mutability = new ReplaceOnlyMutability();

    @Test
    void returnsTheValueItself_whenDeepCopying() {
        // given
        var loaded = List.of("handle");

        // when
        Object snapshot = mutability.deepCopy(loaded);

        // then
        assertThat(snapshot).isSameAs(loaded);
    }

    @Test
    void returnsTheCachedValue_whenAssemblingWhatItDisassembled() {
        // given
        var loaded = List.of("handle");
        Serializable cached = mutability.disassemble(loaded, null);

        // when
        Object assembled = mutability.assemble(cached, null);

        // then
        assertThat(assembled).isSameAs(loaded);
    }
}
