package com.otilm.core.util;

/**
 * Fixed ports for the WireMock stubs that stand in for external services, plus the property assignments that bind those
 * services to them.
 * <p>
 * <b>Why fixed ports are safe</b> — Surefire runs test classes sequentially in one fork, so no two stubs contend for a
 * port, and every class stops its server when it finishes. A fixed port below the 49152 ephemeral floor is also immune
 * to the collisions {@code dynamicPort()} suffers when another process asks for an ephemeral port.
 * <p>
 * <b>Why the ports are off the context signature</b> — a per-class {@code @TestPropertySource} forks a context, because
 * {@link com.otilm.core.architecture.ContextSignature} compares the annotation's source text. The
 * {@code *_URL_PROPERTY} assignments below are instead declared once on {@link BaseSpringBootTest} and
 * {@link BaseSpringBootTestNoAuth}, so every subclass inherits identical text and none of them forks. Whether two
 * classes stubbing the same service also share a cached context depends on their other context axes; the port is not
 * one of them, which is the point.
 * <p>
 * <b>When a new constant is warranted</b> — only when two stubs must be alive at the same time. That happens within a
 * single class, since separate classes run in sequence and share one port.
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

    /**
     * The connector stub a test class starts for itself, whatever function group it impersonates. One constant serves
     * them all, because each class stops its server before the next begins.
     */
    public static final int CONNECTOR = 10020;

    /** {@link com.otilm.core.util.mocks.CryptographyProviderConnectorMock}. */
    public static final int CRYPTOGRAPHY_PROVIDER = 10021;

    /** {@link com.otilm.core.util.mocks.ContentSigningFormattingMock}. */
    public static final int CONTENT_SIGNING_FORMATTING = 10022;

    /**
     * A second {@link com.otilm.core.util.mocks.ContentSigningFormattingMock}, for tests that move a signing profile
     * between two formatting connectors.
     */
    public static final int CONTENT_SIGNING_FORMATTING_SECONDARY = 10023;

    /** {@link com.otilm.core.util.mocks.TimestampingFormattingConnectorMock}. */
    public static final int TIMESTAMPING_FORMATTING = 10024;

    /** {@link com.otilm.core.util.mocks.SignerConnectorMock}. */
    public static final int SIGNER = 10025;

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
