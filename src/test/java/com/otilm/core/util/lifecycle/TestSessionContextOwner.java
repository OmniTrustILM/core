package com.otilm.core.util.lifecycle;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.junit.platform.launcher.LauncherSession;
import org.junit.platform.launcher.LauncherSessionListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;

/** Closes cached test contexts before the fork begins JVM-wide resource cleanup. */
public final class TestSessionContextOwner implements LauncherSessionListener {
    private static final String ENABLED_PROPERTY = "ilm.test.close-contexts-before-exit";
    private static final Logger LOGGER = LoggerFactory.getLogger(TestSessionContextOwner.class);
    private static final SessionContexts CONTEXTS = new SessionContexts();

    public static boolean isEnabled() {
        return enabled(System.getProperty(ENABLED_PROPERTY));
    }

    static boolean enabled(String value) {
        if (value == null || "false".equals(value)) {
            return false;
        }
        if ("true".equals(value)) {
            return true;
        }
        throw new IllegalArgumentException("Invalid test context lifecycle setting");
    }

    @Override
    public void launcherSessionOpened(LauncherSession session) {
        if (isEnabled()) {
            CONTEXTS.open(session);
        }
    }

    @Override
    public void launcherSessionClosed(LauncherSession session) {
        if (isEnabled()) {
            CONTEXTS.close(session);
        }
    }

    static void register(ConfigurableApplicationContext context) {
        CONTEXTS.register(context);
    }

    static final class SessionContexts {
        private final Set<ConfigurableApplicationContext> contexts = identitySet();
        private Object activeSession;
        private boolean closing;
        private boolean completed;

        synchronized void open(Object session) {
            Objects.requireNonNull(session, "session");
            if (activeSession != null || completed) {
                throw new IllegalStateException("Test context ownership requires one execution session");
            }
            activeSession = session;
            LOGGER.info("Test context session opened session={}", identity(session));
        }

        synchronized void register(ConfigurableApplicationContext context) {
            if (activeSession == null || closing) {
                throw new IllegalStateException("Test context registration requires an open session");
            }
            contexts.add(Objects.requireNonNull(context, "context"));
            LOGGER.info("Test context registered session={} context={}", identity(activeSession), identity(context));
        }

        synchronized void close(Object session) {
            if (activeSession == null || activeSession != session || closing) {
                throw new IllegalStateException("Test context session does not own these contexts");
            }
            closing = true;
            try {
                closeContexts();
                LOGGER.info("Test context session closed session={} contexts={}", identity(session), contexts.size());
            } finally {
                completed = !contexts.isEmpty();
                contexts.clear();
                activeSession = null;
                closing = false;
            }
        }

        private void closeContexts() {
            var failure = new IllegalStateException("Test context cleanup failed");
            Map<ConfigurableApplicationContext, Integer> depths = new IdentityHashMap<>();
            Set<ConfigurableApplicationContext> blocked = identitySet();
            for (ConfigurableApplicationContext context : contexts) {
                if (context.isActive()) {
                    try {
                        depths.put(context, depth(context));
                    } catch (IllegalStateException invalidHierarchy) {
                        failure.addSuppressed(invalidHierarchy);
                        blockParents(context, blocked);
                    }
                }
            }
            var ordered = new ArrayList<>(depths.keySet());
            ordered.sort(Comparator.comparingInt(depths::get).reversed());
            for (ConfigurableApplicationContext context : ordered) {
                if (!blocked.contains(context)) {
                    try {
                        LOGGER
                                .info("Test context close started session={} context={}", identity(activeSession),
                                        identity(context));
                        context.close();
                        if (context.isActive()) {
                            throw new IllegalStateException("Test context remained active after close");
                        }
                        LOGGER
                                .info("Test context close completed session={} context={}", identity(activeSession),
                                        identity(context));
                    } catch (RuntimeException closeFailure) {
                        failure.addSuppressed(closeFailure);
                        blockParents(context, blocked);
                    }
                }
            }
            if (failure.getSuppressed().length != 0) {
                throw failure;
            }
        }

        private int depth(ConfigurableApplicationContext context) {
            Set<ApplicationContext> seen = identitySet();
            ApplicationContext current = context;
            int depth = 0;
            while (current != null) {
                if (!seen.add(current)) {
                    throw new IllegalStateException("Test context hierarchy contains a cycle");
                }
                if (current instanceof ConfigurableApplicationContext configurable && configurable.isActive()
                        && !contexts.contains(configurable)) {
                    throw new IllegalStateException("Test context has an unowned active parent");
                }
                depth++;
                current = current.getParent();
            }
            return depth;
        }

        private void blockParents(ConfigurableApplicationContext context, Set<ConfigurableApplicationContext> blocked) {
            Set<ApplicationContext> seen = identitySet();
            ApplicationContext parent = context.getParent();
            while (parent != null && seen.add(parent)) {
                if (parent instanceof ConfigurableApplicationContext configurable) {
                    blocked.add(configurable);
                }
                parent = parent.getParent();
            }
        }
    }

    private static <T> Set<T> identitySet() {
        return Collections.newSetFromMap(new IdentityHashMap<>());
    }

    private static String identity(Object value) {
        return Integer.toHexString(System.identityHashCode(value));
    }
}
