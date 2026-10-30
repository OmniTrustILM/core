package com.otilm.core.architecture;

import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.BaseSpringBootTestNoAuth;
import com.otilm.core.util.WireMockPorts;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.test.context.TestPropertySource;
import org.yaml.snakeyaml.Yaml;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the stub URLs in the test {@code application.yml} to the ports {@link WireMockPorts} names.
 * <p>
 * The yml cannot reference the constants, so the ports exist as literals in both places. A drift on either side
 * surfaces as connection-refused or never-matched-stub failures spread across many unrelated ITest classes, nowhere
 * near the edit that caused it — this test fails at the edit instead. It loads no Spring context, so it does not affect
 * {@link ContextSignatureGuardTest#BASELINE}.
 */
class WireMockPortsGuardTest {

    private static final Path TEST_YML = Path.of("src/test/resources/application.yml");

    @ParameterizedTest(name = "{0} is pinned to port {1}")
    @CsvSource({
            WireMockPorts.AUTH_SERVICE_URL_KEY + "," + WireMockPorts.AUTH_SERVICE,
            WireMockPorts.SCHEDULER_URL_KEY + "," + WireMockPorts.SCHEDULER,
            WireMockPorts.PROVISIONING_API_URL_KEY + "," + WireMockPorts.PROVISIONING_API})
    void testYmlBindsStubUrlToNamedPort(String propertyKey, int expectedPort) throws IOException {
        assertThat(resolve(propertyKey))
                .describedAs("%s in %s must point at the port com.otilm.core.util.WireMockPorts names, "
                        + "otherwise the WireMock stub and the code under test disagree", propertyKey, TEST_YML)
                .isEqualTo("http://localhost:" + expectedPort);
    }

    @Test
    void baseClassesPinTheStubUrlsAboveEnvironmentVariables() {
        assertBaseClassPinsStubUrls(BaseSpringBootTest.class);
        assertBaseClassPinsStubUrls(BaseSpringBootTestNoAuth.class);
    }

    /**
     * The yml alone is not enough: it sits <em>below</em> OS environment variables in Spring Boot's property
     * precedence, so a developer with {@code AUTH_SERVICE_BASE_URL} and friends exported to run core locally would have
     * these tests bypass WireMock and call the real services. A {@code @TestPropertySource} outranks the environment,
     * so the binding must also be declared on the base classes every affected test extends.
     */
    private static void assertBaseClassPinsStubUrls(Class<?> baseClass) {
        TestPropertySource annotation = AnnotationUtils.findAnnotation(baseClass, TestPropertySource.class);
        assertThat(annotation)
                .describedAs("%s must carry @TestPropertySource pinning the stub URLs; without it the test "
                        + "application.yml is outranked by the environment", baseClass.getSimpleName())
                .isNotNull();
        assertThat(annotation.properties())
                .describedAs("%s must pin every stub URL, else that service escapes WireMock when its environment "
                        + "variable is set", baseClass.getSimpleName())
                .contains(WireMockPorts.AUTH_SERVICE_URL_PROPERTY, WireMockPorts.SCHEDULER_URL_PROPERTY,
                        WireMockPorts.PROVISIONING_API_URL_PROPERTY);
    }

    @SuppressWarnings("unchecked")
    private static String resolve(String propertyKey) throws IOException {
        try (InputStream in = Files.newInputStream(TEST_YML)) {
            Object node = new Yaml().load(in);
            for (String segment : propertyKey.split("\\.")) {
                assertThat(node).describedAs("%s is absent from %s", propertyKey, TEST_YML).isInstanceOf(Map.class);
                node = ((Map<String, Object>) node).get(segment);
            }
            return String.valueOf(node);
        }
    }
}
