package com.otilm.core.util.lifecycle;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.GenericApplicationContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TestSessionContextOwnerTest {
    @Test
    void sessionFinishesDatabaseDependentDestructionBeforeDatabaseStop() throws SQLException {
        var owner = new TestSessionContextOwner.SessionContexts();
        Object session = new Object();
        List<String> outcomes = new ArrayList<>();
        try (Database database = new Database(); GenericApplicationContext context = context(database, outcomes)) {
            owner.open(session);
            owner.register(context);
            owner.close(session);
            assertFalse(context.isActive());
            assertEquals(List.of("database available during destruction"), outcomes);
            database.stop();
        }
    }

    @Test
    void stoppedDatabaseMakesDestructionOrderingEvidenceFail() throws SQLException {
        List<String> outcomes = new ArrayList<>();
        try (Database database = new Database(); GenericApplicationContext context = context(database, outcomes)) {
            database.stop();
            context.close();
            assertEquals(List.of("database unavailable during destruction"), outcomes);
        }
    }

    @Test
    void sharedParentClosesAfterBothChildrenAndInactiveEvictionIsHarmless() {
        var owner = new TestSessionContextOwner.SessionContexts();
        Object session = new Object();
        List<String> outcomes = new ArrayList<>();
        try (var parent = tracked("parent", outcomes);
                var left = tracked("left", outcomes);
                var right = tracked("right", outcomes);
                var evicted = tracked("evicted", outcomes)) {
            left.setParent(parent);
            right.setParent(parent);
            owner.open(session);
            owner.register(parent);
            owner.register(left);
            owner.register(right);
            owner.register(evicted);
            owner.register(left);
            evicted.close();
            owner.close(session);
            assertFalse(parent.isActive());
            assertFalse(left.isActive());
            assertFalse(right.isActive());
            assertEquals(4, outcomes.size());
            assertEquals("evicted", outcomes.getFirst());
            assertEquals("parent", outcomes.getLast());
            assertTrue(outcomes.indexOf("left") < outcomes.indexOf("parent"));
            assertTrue(outcomes.indexOf("right") < outcomes.indexOf("parent"));
        }
    }

    @Test
    void emptyDiscoveryCanPrecedeExecutionButClosedCachedContextsCannotBeReused() {
        var owner = new TestSessionContextOwner.SessionContexts();
        Object discovery = new Object();
        owner.open(discovery);
        owner.close(discovery);
        Object execution = new Object();
        try (var context = tracked("execution", new ArrayList<>())) {
            owner.open(execution);
            owner.register(context);
            owner.close(execution);
            Object repeatedSession = new Object();
            assertThrows(IllegalStateException.class, () -> owner.open(repeatedSession));
        }
    }

    @Test
    void overlappingSessionAndWrongSessionCloseAreRejectedWithoutClosingResources() {
        var owner = new TestSessionContextOwner.SessionContexts();
        Object session = new Object();
        try (var context = tracked("context", new ArrayList<>())) {
            owner.open(session);
            owner.register(context);
            Object otherSession = new Object();
            assertThrows(IllegalStateException.class, () -> owner.open(otherSession));
            assertThrows(IllegalStateException.class, () -> owner.close(otherSession));
            assertTrue(context.isActive());
            owner.close(session);
            assertFalse(context.isActive());
        }
    }

    @Test
    void registrationRequiresAnOpenSession() {
        var owner = new TestSessionContextOwner.SessionContexts();
        try (var context = tracked("context", new ArrayList<>())) {
            assertThrows(IllegalStateException.class, () -> owner.register(context));
            assertTrue(context.isActive());
        }
    }

    @Test
    void failedChildDoesNotCloseItsParentButIndependentRootStillCloses() {
        var owner = new TestSessionContextOwner.SessionContexts();
        Object session = new Object();
        try (var parent = tracked("parent", new ArrayList<>());
                var independent = tracked("independent", new ArrayList<>());
                var child = new CloseFailureContext()) {
            child.setParent(parent);
            child.refresh();
            owner.open(session);
            owner.register(parent);
            owner.register(child);
            owner.register(independent);
            assertThrows(IllegalStateException.class, () -> owner.close(session));
            assertTrue(parent.isActive());
            assertTrue(child.isActive());
            assertFalse(independent.isActive());
            child.fail = false;
        }
    }

    @Test
    void unownedLiveParentFailsWithoutClosingThatParent() {
        var owner = new TestSessionContextOwner.SessionContexts();
        Object session = new Object();
        try (var parent = tracked("parent", new ArrayList<>());
                var child = tracked("child", new ArrayList<>());
                var independent = tracked("independent", new ArrayList<>())) {
            child.setParent(parent);
            owner.open(session);
            owner.register(child);
            owner.register(independent);
            assertThrows(IllegalStateException.class, () -> owner.close(session));
            assertTrue(parent.isActive());
            assertFalse(independent.isActive());
        }
    }

    @Test
    void refreshFailureKeepsItsOriginalFailureAndDestroysCreatedSingletons() {
        var owner = new TestSessionContextOwner.SessionContexts();
        Object session = new Object();
        List<String> outcomes = new ArrayList<>();
        try (var context = new GenericApplicationContext()) {
            context.getBeanFactory().registerSingleton("owned", new Object());
            context.getDefaultListableBeanFactory().registerDisposableBean("owned", () -> outcomes.add("destroyed"));
            context.registerBean("failing", Object.class, () -> {
                throw new IllegalStateException("Intentional startup failure");
            });
            owner.open(session);
            owner.register(context);
            assertThrows(BeanCreationException.class, context::refresh);
            owner.close(session);
            assertFalse(context.isActive());
            assertEquals(List.of("destroyed"), outcomes);
        }
    }

    @Test
    void disabledCustomizerLeavesExistingCacheKeysAlone() {
        withFlag("false", () -> assertNull(
                new TestSessionContextCustomizerFactory().createContextCustomizer(getClass(), List.of())));
        assertFalse(TestSessionContextOwner.enabled(null));
        assertFalse(TestSessionContextOwner.enabled("false"));
        assertTrue(TestSessionContextOwner.enabled("true"));
    }

    @Test
    void separatelyDiscoveredCustomizersReuseTheSameCacheEntry() {
        withFlag("true", () -> {
            var factory = new TestSessionContextCustomizerFactory();
            var first = factory.createContextCustomizer(getClass(), List.of());
            var second = new TestSessionContextCustomizerFactory().createContextCustomizer(getClass(), List.of());
            var cache = new HashMap<org.springframework.test.context.ContextCustomizer, String>();
            cache.put(first, "cached context");
            assertEquals("cached context", cache.get(second));
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "TRUE", " true", "yes"})
    void malformedFlagCannotEnableOrSilentlyDisableOwnership(String flag) {
        assertThrows(IllegalArgumentException.class, () -> TestSessionContextOwner.enabled(flag));
    }

    @Test
    void contextThatDoesNotFinishCloseFailsAndKeepsItsParentAvailable() {
        var owner = new TestSessionContextOwner.SessionContexts();
        Object session = new Object();
        try (var parent = tracked("parent", new ArrayList<>()); var child = new NonClosingContext()) {
            try {
                child.setParent(parent);
                child.refresh();
                owner.open(session);
                owner.register(parent);
                owner.register(child);
                assertThrows(IllegalStateException.class, () -> owner.close(session));
                assertTrue(parent.isActive());
                assertTrue(child.isActive());
            } finally {
                child.defer = false;
            }
        }
    }

    @Test
    void cyclicHierarchyFailsWhileIndependentRootStillCloses() {
        var owner = new TestSessionContextOwner.SessionContexts();
        Object session = new Object();
        try (var first = new HierarchyContext();
                var second = new HierarchyContext();
                var independent = tracked("independent", new ArrayList<>())) {
            try {
                first.refresh();
                second.refresh();
                first.observedParent = second;
                second.observedParent = first;
                owner.open(session);
                owner.register(first);
                owner.register(second);
                owner.register(independent);
                assertThrows(IllegalStateException.class, () -> owner.close(session));
                assertTrue(first.isActive());
                assertTrue(second.isActive());
                assertFalse(independent.isActive());
            } finally {
                first.observedParent = null;
                second.observedParent = null;
            }
        }
    }

    @Test
    void destructorCannotRegisterAContextDuringSessionClosure() {
        var owner = new TestSessionContextOwner.SessionContexts();
        Object session = new Object();
        var refused = new AtomicReference<IllegalStateException>();
        try (var context = tracked("context", new ArrayList<>()); var late = new GenericApplicationContext()) {
            context.getDefaultListableBeanFactory().registerDisposableBean("late-registration", () -> {
                try {
                    owner.register(late);
                } catch (IllegalStateException failure) {
                    refused.set(failure);
                }
            });
            owner.open(session);
            owner.register(context);
            owner.close(session);
            assertNotNull(refused.get());
            assertFalse(context.isActive());
        }
    }

    private static void withFlag(String flag, Runnable action) {
        String property = "ilm.test.close-contexts-before-exit";
        String previous = System.getProperty(property);
        try {
            System.setProperty(property, flag);
            action.run();
        } finally {
            if (previous == null) {
                System.clearProperty(property);
            } else {
                System.setProperty(property, previous);
            }
        }
    }

    private static final class HierarchyContext extends GenericApplicationContext {
        private ApplicationContext observedParent;

        @Override
        public ApplicationContext getParent() {
            return observedParent;
        }
    }

    private static final class NonClosingContext extends GenericApplicationContext {
        private boolean defer = true;

        @Override
        public void close() {
            if (!defer) {
                super.close();
            }
        }
    }

    private static final class CloseFailureContext extends GenericApplicationContext {
        private boolean fail = true;

        @Override
        public void close() {
            if (fail) {
                throw new IllegalStateException("Intentional close failure");
            }
            super.close();
        }
    }

    private static GenericApplicationContext context(Database database, List<String> outcomes) {
        var context = new GenericApplicationContext();
        context.getBeanFactory().registerSingleton("database-dependent", new Object());
        context.getDefaultListableBeanFactory().registerDisposableBean("database-dependent", () -> {
            try {
                database.query();
                outcomes.add("database available during destruction");
            } catch (SQLException failure) {
                outcomes.add("database unavailable during destruction");
            }
        });
        context.refresh();
        return context;
    }

    private static GenericApplicationContext tracked(String name, List<String> outcomes) {
        var context = new GenericApplicationContext();
        context.getBeanFactory().registerSingleton(name, new Object());
        context.getDefaultListableBeanFactory().registerDisposableBean(name, () -> outcomes.add(name));
        context.refresh();
        return context;
    }

    private static final class Database implements AutoCloseable {
        private final Connection connection = DriverManager.getConnection("jdbc:hsqldb:mem:" + UUID.randomUUID());

        private Database() throws SQLException {
            try (var statement = connection.createStatement()) {
                statement.execute("CREATE TABLE lifecycle_probe (probe_value INTEGER)");
            }
        }

        private void query() throws SQLException {
            try (var statement = connection.createStatement();
                    var result = statement.executeQuery("SELECT COUNT(*) FROM lifecycle_probe")) {
                result.next();
            }
        }

        private void stop() throws SQLException {
            if (!connection.isClosed()) {
                try (var statement = connection.createStatement()) {
                    statement.execute("SHUTDOWN");
                }
                connection.close();
            }
        }

        @Override
        public void close() throws SQLException {
            stop();
        }
    }
}
