package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AssociationReaderTest {

    final UUID ownedObject = UUID.randomUUID();

    final UUID unownedObject = UUID.randomUUID();

    final List<Set<UUID>> groupReads = new ArrayList<>();

    final AssociationReader reader = new AssociationReader(
            (resource, asked) -> asked.stream().filter(ownedObject::equals).collect(Collectors.toSet()),
            (resource, asked) -> {
                groupReads.add(Set.copyOf(asked));
                return Map.of();
            });

    @Test
    void leavesOwnedObjectsOutOfTheGroupRead_whenAnUnownedObjectFallsBackToGroups() {
        // given
        reader.prefetch(Resource.CERTIFICATE, List.of(ownedObject, unownedObject));
        reader.ownsAll(Resource.CERTIFICATE, List.of(ownedObject));

        // when
        reader.groupsOf(Resource.CERTIFICATE, unownedObject);

        // then
        assertThat(groupReads).containsExactly(Set.of(unownedObject));
    }

    @Test
    void readsTheGroupsOfAnOwnedObject_whenItIsAskedFor() {
        // given
        reader.prefetch(Resource.CERTIFICATE, List.of(ownedObject, unownedObject));
        reader.ownsAll(Resource.CERTIFICATE, List.of(ownedObject));

        // when
        reader.groupsOf(Resource.CERTIFICATE, ownedObject);

        // then
        assertThat(groupReads).containsExactly(Set.of(ownedObject, unownedObject));
    }
}
