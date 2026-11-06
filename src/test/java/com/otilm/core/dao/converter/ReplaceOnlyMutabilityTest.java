package com.otilm.core.dao.converter;

import java.io.Serializable;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ReplaceOnlyMutabilityTest {

    private final ReplaceOnlyMutability mutability = new ReplaceOnlyMutability();

    @Test
    void keepsTheValueItselfAsTheSnapshot() {
        // given
        var loaded = List.of("handle");

        // when
        Object snapshot = mutability.deepCopy(loaded);

        // then
        assertThat(snapshot).isSameAs(loaded);
        assertThat(mutability.isMutable()).isTrue();
    }

    @Test
    void returnsTheCachedValue_whenAssemblingWhatItDisassembled() {
        // given
        var loaded = List.of("handle");

        // when
        Serializable cached = mutability.disassemble(loaded, null);

        // then
        assertThat(mutability.assemble(cached, null)).isSameAs(loaded);
    }
}
