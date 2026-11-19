package com.otilm.core.security.authz;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;

class BatchLoaderTest {

    final UUID owned = UUID.randomUUID();

    final UUID notOwned = UUID.randomUUID();

    final UUID askedLater = UUID.randomUUID();

    final List<Set<UUID>> reads = new ArrayList<>();

    final BatchLoader<Boolean> loader = new BatchLoader<>(missing -> {
        reads.add(Set.copyOf(missing));
        return Map.of(owned, true);
    }, false);

    @Test
    void readsTheAnnouncedObjectsInTheFirstReadThatMisses() {
        // given
        loader.announce(List.of(owned, notOwned));

        // when
        Map<UUID, Boolean> answer = loader.get(List.of(askedLater));

        // then
        assertThat(answer).containsExactly(entry(askedLater, false));
        assertThat(reads).containsExactly(Set.of(owned, notOwned, askedLater));
    }

    @Test
    void answersFromMemory_whenEveryAskedObjectWasRead() {
        // given
        loader.announce(List.of(owned, notOwned));
        loader.get(List.of(owned));

        // when
        Map<UUID, Boolean> answer = loader.get(List.of(owned, notOwned));

        // then
        assertThat(answer).containsOnly(entry(owned, true), entry(notOwned, false));
        assertThat(reads).hasSize(1);
    }

    @Test
    void readsTheAnnouncedObjectsAgain_whenAnEarlierReadFailed() {
        // given
        List<Set<UUID>> attempts = new ArrayList<>();
        BatchLoader<Boolean> failingOnce = new BatchLoader<>(missing -> {
            attempts.add(Set.copyOf(missing));
            if (attempts.size() == 1) {
                throw new IllegalStateException("connection lost");
            }
            return Map.of(owned, true);
        }, false);
        failingOnce.announce(List.of(owned, notOwned));
        ThrowingCallable failingRead = () -> failingOnce.get(List.of(owned));
        assertThatThrownBy(failingRead).isInstanceOf(IllegalStateException.class);

        // when
        Map<UUID, Boolean> answer = failingOnce.get(List.of(notOwned));

        // then
        assertThat(answer).containsExactly(entry(notOwned, false));
        assertThat(attempts).containsExactly(Set.of(owned, notOwned), Set.of(owned, notOwned));
    }

    @Test
    void answersARepeatedObjectOnce() {
        // when
        Map<UUID, Boolean> answer = loader.get(List.of(owned, owned));

        // then
        assertThat(answer).containsExactly(entry(owned, true));
    }
}
