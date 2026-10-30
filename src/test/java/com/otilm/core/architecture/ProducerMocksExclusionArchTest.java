package com.otilm.core.architecture;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code ProducerMocks} mocks the JMS producers, but {@code @Primary} only shadows them — the real {@code @Component}s
 * stay scanned and instantiated.
 *
 * The module therefore has to be imported together with the {@code @TypeExcludeFilters} that drops those classes from
 * the component scan. This pins them together.
 */
class ProducerMocksExclusionArchTest {

    private static final Path TEST_ROOT = Path.of("src/test/java");

    private static final String MODULE = "ProducerMocks";

    private static final String EXCLUSION_FILTER = "ProducerMocks.MockedProducersTypeExcludeFilter";

    @Test
    void everyProducerMocksImportAlsoExcludesTheRealProducersFromTheScan() {
        Map<String, String> inheritance = TestClassTaxonomy.parseExtends(TEST_ROOT);
        List<Path> importers = testSources()
                // Only a context-loading class can be affected; that also keeps meta-test fixture sources out.
                .filter(file -> TestClassTaxonomy.loadsContext(file, inheritance))
                .filter(file -> TestClassTaxonomy.annotationTokens(file).imports().contains(MODULE))
                .toList();

        assertThat(importers)
                .describedAs("ProducerMocks is expected to be in use; this guard is vacuous otherwise")
                .isNotEmpty()
                .describedAs("every test class importing ProducerMocks must also declare "
                        + "@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class) — without it "
                        + "the real producers stay in the component scan, so NotificationProducer's "
                        + "@TransactionalEventListener can still dispatch real JMS sends after a commit")
                .allMatch(ProducerMocksExclusionArchTest::declaresExclusion);
    }

    /** Any declaration form counts: an array of filters, wrapped lines, or a fully-qualified filter reference. */
    private static boolean declaresExclusion(Path file) {
        return TestClassTaxonomy
                .annotationTokens(file)
                .typeExcludeFilters()
                .stream()
                .anyMatch(filter -> filter.endsWith(EXCLUSION_FILTER));
    }

    private static Stream<Path> testSources() {
        try (Stream<Path> files = Files.walk(TEST_ROOT)) {
            return files
                    .filter(Files::isRegularFile)
                    .filter(file -> file.toString().endsWith(".java"))
                    .toList()
                    .stream();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
