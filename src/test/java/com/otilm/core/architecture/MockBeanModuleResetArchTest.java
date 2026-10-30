package com.otilm.core.architecture;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The mock modules in {@code com.otilm.core.util.mockbeans} declare their mocks as {@code @Bean @Primary} context
 * singletons, which Spring's reset lifecycle does not touch — it only discovers {@code @MockitoBean} fields on the test
 * class, its superclasses and its enclosing classes.
 *
 * {@code MockBeanResetListener} resets them instead, and {@code BaseSpringBootTest} is the only class registering it.
 * An importer that does not inherit from there keeps its stubbings and interactions across tests sharing the cached
 * context. This pins the two together.
 */
class MockBeanModuleResetArchTest {

    private static final Path TEST_ROOT = Path.of("src/test/java");

    private static final Path MODULE_ROOT = TEST_ROOT.resolve("com/otilm/core/util/mockbeans");

    private static final String LISTENER_ROOT = "BaseSpringBootTest";

    @Test
    void everyMockModuleImporterInheritsTheMockResetListener() {
        Set<String> modules = declaredModules();
        Map<String, String> inheritance = TestClassTaxonomy.parseExtends(TEST_ROOT);

        List<Path> importers = testSources()
                // Only a context-loading class can hold module mocks; that also keeps meta-test fixture sources out.
                .filter(file -> TestClassTaxonomy.loadsContext(file, inheritance))
                .filter(file -> TestClassTaxonomy.annotationTokens(file).imports().stream().anyMatch(modules::contains))
                .toList();

        assertThat(importers)
                .describedAs("the mock modules are expected to be in use; this guard is vacuous otherwise")
                .isNotEmpty()
                .describedAs("every test class importing a com.otilm.core.util.mockbeans module must extend "
                        + LISTENER_ROOT + " — it is the only class registering MockBeanResetListener, and without "
                        + "that listener the modules' @Bean @Primary singleton mocks keep their stubbings and "
                        + "interactions across every test sharing the cached context")
                .allMatch(file -> inheritsListenerRoot(file, inheritance));
    }

    /** Every module in the package counts, so a module added later is covered without touching this test. */
    private static Set<String> declaredModules() {
        try (Stream<Path> files = Files.list(MODULE_ROOT)) {
            Set<String> modules = files
                    .map(file -> file.getFileName().toString())
                    .filter(name -> name.endsWith(".java"))
                    .filter(name -> !name.equals("package-info.java"))
                    .map(name -> name.substring(0, name.length() - ".java".length()))
                    .collect(Collectors.toSet());
            assertThat(modules)
                    .describedAs("no mock module found under %s — the path is stale", MODULE_ROOT)
                    .isNotEmpty();
            return modules;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static boolean inheritsListenerRoot(Path file, Map<String, String> inheritance) {
        String current = TestClassTaxonomy.primaryClassName(file);
        int guard = 0;
        while (current != null && guard++ < 50) {
            if (LISTENER_ROOT.equals(current)) {
                return true;
            }
            current = inheritance.get(current);
        }
        return false;
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
