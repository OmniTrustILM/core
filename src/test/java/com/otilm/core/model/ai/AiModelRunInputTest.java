package com.otilm.core.model.ai;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiModelRunInputTest {
    private static final UUID RUN = UUID.randomUUID();
    private static final UUID PROFILE = UUID.randomUUID();
    private static final Set<UUID> EMPTY = Set.of();

    @Test
    void ownsScopeAndDoesNotExposePromptOrScopeInToString() {
        UUID certificate = UUID.randomUUID();
        Set<UUID> caller = new HashSet<>(Set.of(certificate));
        var input = new AiModelRunInput(RUN, PROFILE, caller, "PRIVATE_INSTRUCTION_CANARY", "PRIVATE_PROMPT_CANARY",
                32);
        caller.clear();
        assertThat(input.certificateUuids()).containsExactly(certificate);
        Set<UUID> retained = input.certificateUuids();
        assertThatThrownBy(() -> retained.clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThat(input.toString()).doesNotContain("PRIVATE_", certificate.toString(), PROFILE.toString());
    }

    @Test
    void acceptsExistingEmptyScopeAndTheExactHundredObjectBoundary() {
        var empty = new AiModelRunInput(RUN, PROFILE, EMPTY, "instructions", "prompt", 1);
        Set<UUID> hundred = IntStream.range(0, 100).mapToObj(value -> new UUID(0, value)).collect(Collectors.toSet());
        var bounded = new AiModelRunInput(RUN, PROFILE, hundred, "instructions", "prompt", 1);
        assertThat(empty.certificateUuids()).isEmpty();
        assertThat(bounded.certificateUuids()).hasSize(100);
        hundred.add(new UUID(0, 100));
        assertThatThrownBy(() -> new AiModelRunInput(RUN, PROFILE, hundred, "instructions", "prompt", 1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void reusesDispatchTextRulesForUnicodeBoundsAndOutputLimit() {
        String text = "🧪 retained certificate\ntext";
        var valid = new AiModelRunInput(RUN, PROFILE, EMPTY, text, text, 32);
        assertThat(valid.instructions()).isEqualTo(text);
        for (String invalid : new String[]{"", " ", "x\u0000y", "\uD800", "\uDC00", "x".repeat(65537)}) {
            assertThatThrownBy(() -> new AiModelRunInput(RUN, PROFILE, EMPTY, invalid, "prompt", 1))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> new AiModelRunInput(RUN, PROFILE, EMPTY, "instructions", invalid, 1))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> new AiModelRunInput(RUN, PROFILE, EMPTY, "instructions", "prompt", 0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusesMissingIdentityAndNullScopeMembers() {
        Set<UUID> nullMember = new HashSet<>();
        nullMember.add(null);
        assertThatThrownBy(() -> new AiModelRunInput(null, PROFILE, EMPTY, "instructions", "prompt", 1))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new AiModelRunInput(RUN, null, EMPTY, "instructions", "prompt", 1))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new AiModelRunInput(RUN, PROFILE, nullMember, "instructions", "prompt", 1))
                .isInstanceOf(NullPointerException.class);
    }
}
