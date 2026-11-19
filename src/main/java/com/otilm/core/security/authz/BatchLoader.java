package com.otilm.core.security.authz;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Reads one value per object and remembers it, folding every announced object into the first read that misses.
 * Announced objects are cleared only after a successful read, so a failed read is retried by the next lookup.
 */
final class BatchLoader<V> {

    private final Function<Set<UUID>, Map<UUID, V>> read;

    private final V absent;

    private final Map<UUID, V> loaded = new HashMap<>();

    private final Set<UUID> announced = new LinkedHashSet<>();

    BatchLoader(Function<Set<UUID>, Map<UUID, V>> read, V absent) {
        this.read = read;
        this.absent = absent;
    }

    void announce(Collection<UUID> uuids) {
        announced.addAll(uuids);
    }

    Map<UUID, V> get(Collection<UUID> uuids) {
        if (!loaded.keySet().containsAll(uuids)) {
            Set<UUID> missing = Stream
                    .concat(uuids.stream(), announced.stream())
                    .filter(uuid -> !loaded.containsKey(uuid))
                    .collect(Collectors.toCollection(LinkedHashSet::new));
            Map<UUID, V> found = read.apply(missing);
            missing.forEach(uuid -> loaded.put(uuid, found.getOrDefault(uuid, absent)));
            announced.clear();
        }
        return uuids.stream().distinct().collect(Collectors.toMap(Function.identity(), loaded::get));
    }
}
