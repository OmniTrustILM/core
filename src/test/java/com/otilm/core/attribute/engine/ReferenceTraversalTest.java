package com.otilm.core.attribute.engine;

import com.otilm.api.model.core.auth.AttributeResource;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Pure-kernel tests for the cycle/depth invariants (core CLAUDE.md kernel/integration split). */
class ReferenceTraversalTest {

    private final UUID uuid = UUID.randomUUID();

    @Test
    void firstSightingDescends_repeatDoesNot() {
        Set<String> visited = new HashSet<>();
        assertTrue(ReferenceTraversal.shouldDescend(AttributeResource.CREDENTIAL, uuid, visited));
        assertFalse(ReferenceTraversal.shouldDescend(AttributeResource.CREDENTIAL, uuid, visited),
                "a (kind,uuid) seen twice on one call must not be re-expanded (cycle guard)");
    }

    @Test
    void cycleKeyIsKindQualified_notUuidOnly() {
        Set<String> visited = new HashSet<>();
        assertTrue(ReferenceTraversal.shouldDescend(AttributeResource.AUTHORITY, uuid, visited));
        assertTrue(ReferenceTraversal.shouldDescend(AttributeResource.CREDENTIAL, uuid, visited),
                "same UUID under a different kind must still expand — key is kind:uuid, never uuid-only");
        assertNotEquals(
                ReferenceTraversal.key(AttributeResource.AUTHORITY, uuid),
                ReferenceTraversal.key(AttributeResource.CREDENTIAL, uuid));
    }

    @Test
    void depthOverflowIsDetectedAtCapPlusOne() {
        assertFalse(ReferenceTraversal.exceedsDepth(AttributeReferenceExpander.MAX_DEPTH, AttributeReferenceExpander.MAX_DEPTH));
        assertTrue(ReferenceTraversal.exceedsDepth(AttributeReferenceExpander.MAX_DEPTH + 1, AttributeReferenceExpander.MAX_DEPTH));
    }

    @Test
    void depthExceededFactoryBuildsDescriptiveMessage() {
        ReferenceExpansionException e =
                ReferenceExpansionException.depthExceeded(AttributeResource.CREDENTIAL, uuid, 3);
        assertTrue(e.getMessage().contains("3"), "message names the cap");
        assertTrue(e.getMessage().contains("CREDENTIAL"), "message names the kind");
        assertTrue(e.getMessage().contains(uuid.toString()), "message names the uuid");
        assertInstanceOf(com.otilm.api.exception.PlatformException.class, e,
                "must be a PlatformException so safeMessage() can gate it at the wire");
    }
}
