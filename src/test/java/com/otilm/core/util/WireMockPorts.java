package com.otilm.core.util;

/**
 * Fixed ports for the WireMock stubs that stand in for external services, plus the property assignments that bind those
 * services to them.
 * <p>
 * <b>When a fixed port is warranted</b> — only when the URL must be known before the Spring context is created, so it
 * can be written into a {@code @TestPropertySource} or the test {@code application.yml}. The three services below
 * qualify; stubs that hand their URL over at runtime use {@link LoopbackWireMock}.
 * <p>
 * <b>Why the ports are off the context signature</b> — a per-class {@code @TestPropertySource} forks a context, because
 * {@link com.otilm.core.architecture.ContextSignature} compares the annotation's source text. The
 * {@code *_URL_PROPERTY} assignments below are instead declared once on {@link BaseSpringBootTest} and
 * {@link BaseSpringBootTestNoAuth}, so every subclass inherits identical text and none of them forks.
 * <p>
 * <b>Duplication in YAML</b> — the test {@code application.yml} repeats these ports as literals, because it cannot
 * reference constants, as the floor for the context-loading tests that extend neither base class.
 * {@code WireMockPortsGuardTest} pins the two in sync.
 */
public final class WireMockPorts {

    /** auth-service stub. */
    public static final int AUTH_SERVICE = 10001;

    /** provisioning-api stub. */
    public static final int PROVISIONING_API = 10010;

    /** scheduler stub. */
    public static final int SCHEDULER = 10011;

    public static final String AUTH_SERVICE_URL_KEY = "auth-service.base-url";

    public static final String SCHEDULER_URL_KEY = "scheduler.base-url";

    public static final String PROVISIONING_API_URL_KEY = "provisioning.api.url";

    /** Binds auth-service to its stub. Declared on the base test classes, above any {@code AUTH_SERVICE_BASE_URL}. */
    public static final String AUTH_SERVICE_URL_PROPERTY = AUTH_SERVICE_URL_KEY + "=http://localhost:" + AUTH_SERVICE;

    /** Binds the scheduler to its stub. Declared on the base test classes, above any {@code SCHEDULER_BASE_URL}. */
    public static final String SCHEDULER_URL_PROPERTY = SCHEDULER_URL_KEY + "=http://localhost:" + SCHEDULER;

    /**
     * Binds provisioning-api to its stub. Declared on the base test classes, above any {@code PROVISIONING_API_URL}.
     */
    public static final String PROVISIONING_API_URL_PROPERTY = PROVISIONING_API_URL_KEY + "=http://localhost:"
            + PROVISIONING_API;

    private WireMockPorts() {
    }
}
