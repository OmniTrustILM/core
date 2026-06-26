package com.otilm.core.attribute.engine;

import com.otilm.api.model.core.auth.AttributeResource;

import java.util.Set;
import java.util.UUID;

/**
 * Pure, Spring-free kernel for the expander's cycle and depth guards (core CLAUDE.md kernel/integration split).
 * Extracted so the traversal invariants are unit-testable without a Spring context, DB, or the auth aspect.
 */
final class ReferenceTraversal {

    private ReferenceTraversal() {
    }

    /**
     * Cycle guard. Returns {@code true} the first time a (kind, uuid) pair is seen on a call and records it;
     * {@code false} on any subsequent sighting so the caller stops descending. The key is {@code kind:uuid}
     * (never uuid-only — an authority and a credential could legitimately share a UUID; Q6). The visited set is
     * shared across the whole top-level call and across multi-select siblings, so a self-referential multi-select
     * cannot blow the budget across siblings.
     */
    static boolean shouldDescend(AttributeResource kind, UUID uuid, Set<String> visited) {
        return visited.add(key(kind, uuid));
    }

    static boolean exceedsDepth(int depth, int maxDepth) {
        return depth > maxDepth;
    }

    static String key(AttributeResource kind, UUID uuid) {
        return kind.name() + ":" + uuid;
    }
}
