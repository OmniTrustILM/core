package com.otilm.core.architecture;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins every test server on an OS-chosen port to the loopback address. A wildcard bind is granted a port another
 * process holds on {@code 127.0.0.1}, and the server's requests then reach that process, so the test fails only in the
 * runs that land on such a port. Loads no Spring context, so it does not affect
 * {@link ContextSignatureGuardTest#BASELINE}.
 */
class LoopbackBindGuardTest {

    private static final Path TEST_SOURCES = Path.of("src/test/java");

    private static final Path LOOPBACK_WIRE_MOCK = TEST_SOURCES.resolve("com/otilm/core/util/LoopbackWireMock.java");

    /** How WireMock and the JDK are asked for an OS-chosen port on the wildcard address. */
    private static final Pattern WILDCARD_OS_CHOSEN_PORT = Pattern
            .compile("dynamic(Https)?Port\\(\\)|new\\s+WireMockServer\\(\\s*0\\s*\\)|\\.(https)?[pP]ort\\(\\s*0\\s*\\)"
                    + "|new\\s+InetSocketAddress\\(\\s*0\\s*\\)");

    /** A test class whose embedded server takes an OS-chosen port, on the wildcard address unless it sets one. */
    private static final Pattern RANDOM_PORT_TEST = Pattern.compile("(?m)^@SpringBootTest\\([^)]*RANDOM_PORT");

    private static final String SERVER_ADDRESS = "server.address=";

    @Test
    void everyServerOnAnOsChosenPortBindsTheLoopbackAddress() throws IOException {
        assertThat(sourcesAskingForAWildcardOsChosenPort())
                .describedAs(
                        "a WireMock stub on an OS-chosen port comes from LoopbackWireMock, a RANDOM_PORT test sets "
                                + "server.address, and any other server binds LoopbackWireMock.HOST")
                .containsExactly(LOOPBACK_WIRE_MOCK);
    }

    private static List<Path> sourcesAskingForAWildcardOsChosenPort() throws IOException {
        try (Stream<Path> sources = Files.walk(TEST_SOURCES)) {
            return sources
                    .filter(path -> path.toString().endsWith(".java"))
                    .filter(LoopbackBindGuardTest::asksForAWildcardOsChosenPort)
                    .sorted()
                    .toList();
        }
    }

    private static boolean asksForAWildcardOsChosenPort(Path source) {
        try {
            String text = Files.readString(source);
            return WILDCARD_OS_CHOSEN_PORT.matcher(text).find()
                    || (RANDOM_PORT_TEST.matcher(text).find() && !text.contains(SERVER_ADDRESS));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
