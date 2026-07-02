package com.otilm.core.architecture;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Static kernel for classifying test classes by location/context.
 * <p>
 * Heuristic boundaries (load-bearing for the CI split guards that consume this — know them):
 * <ul>
 *   <li><b>First class per file is the primary type.</b> {@link #parseExtends} records the first {@code class} declaration
 *   in each file and ignores nested/secondary classes. Every test file in this tree declares its primary type first;
 *   files whose primary type is an {@code interface}/{@code enum}/{@code record} are absent from the graph.</li>
 *   <li><b>Source is comment-stripped, not string-literal-aware.</b> Comments are removed so prose containing Java keywords
 *   (e.g. "Base class for ...") is not matched, and annotation/keyword checks are token-anchored (word boundaries) so that
 *   {@code @TestConfiguration} is not mistaken for {@code @Test} nor a {@code "abstract class"} string literal for an abstract
 *   declaration.</li>
 *   <li><b>The inheritance graph is keyed by the simple class name.</b> {@link #parseExtends} records {@code simpleName -> superSimpleName},
 *   and {@link #hasContextBearingAncestor} resolves {@code extends} clauses (which use simple names) against it. {@code parseExtends}
 *   throws only on a duplicate primary simple name with a <em>conflicting</em> supertype — that is the case that would corrupt
 *   context-ancestry resolution. Two unrelated classes sharing a simple name but mapping to the same supertype (commonly both none)
 *   coalesce harmlessly.</li>
 *   <li><b>Context detection is limited to {@code @SpringBootTest} and the known context-root base classes.
 *   </b> Spring test-slice / meta-annotations that also start a context ({@code @WebMvcTest}, {@code @DataJpaTest}, {@code @JsonTest}, {@code @ContextConfiguration},
 *   a bare {@code @ExtendWith(SpringExtension.class)}) are intentionally out of scope — none exist in this tree.</li>
 * </ul>
 */
final class TestClassTaxonomy {

    private static final Set<String> CONTEXT_ROOTS = Set.of("BaseSpringBootTest", "BaseSpringBootTestNoAuth", "BaseMessagingIntTest",
            "BaseMigrationTest", "BaseComplianceTest");

    // Primary class declaration: optional `abstract` modifier (adjacent to `class` in this codebase), the class name,
    // an optional generic parameter list (so `class Foo<T> extends Base` still captures the supertype),
    // and an optional single `extends` supertype (simple name).
    private static final Pattern CLASS_DECL = Pattern.compile("(abstract\\s+)?class\\s+(\\w+)(?:<[^>]*>)?(?:\\s+extends\\s+(\\w+))?");

    // Annotation checks are:
    //   (a) line-anchored — a real annotation begins its line (after indentation)
    //   (b) token-anchored with `\b` so `@Test` does not match `@TestConfiguration`/`@Testcontainers`/`@TestInstance`.
    private static final Pattern TEST_ANNOTATION = Pattern.compile("(?m)^[ \\t]*(?:@Test\\b|@ParameterizedTest\\b|@RepeatedTest\\b)");
    private static final Pattern SPRING_BOOT_TEST = Pattern.compile("(?m)^[ \\t]*@SpringBootTest\\b");

    // Block comments (incl. Javadoc) and line comments — stripped before any matching.
    private static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
    private static final Pattern LINE_COMMENT = Pattern.compile("//[^\\n]*");

    private TestClassTaxonomy() {
    }

    static Set<String> contextBearingRoots() {
        return CONTEXT_ROOTS;
    }

    static Map<String, String> parseExtends(Path testRoot) {
        Map<String, String> graph = new HashMap<>();
        try (Stream<Path> s = Files.walk(testRoot)) {
            s.filter(p -> p.toString().endsWith(".java")).forEach(p -> {
                Matcher m = CLASS_DECL.matcher(code(p));
                if (m.find()) {
                    String name = m.group(2);
                    String superName = m.group(3);
                    if (graph.containsKey(name) && !Objects.equals(graph.get(name), superName)) {
                        throw new IllegalStateException("Duplicate primary test-class simple name '"
                                + name + "' with conflicting supertypes at " + p + "; the context graph is keyed by "
                                + "simple name, so this collision would corrupt context-ancestry resolution. Rename one class.");
                    }
                    graph.put(name, superName); // name -> superclass (may be null)
                }
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return graph;
    }

    static boolean hasContextBearingAncestor(String className, Map<String, String> graph) {
        String cur = className;
        int guard = 0;
        while (cur != null && guard++ < 50) {
            if (CONTEXT_ROOTS.contains(cur)) return true;
            cur = graph.get(cur);
        }
        return false;
    }

    static boolean loadsContext(Path javaFile, Map<String, String> graph) {
        String src = code(javaFile);
        if (SPRING_BOOT_TEST.matcher(src).find()) return true;
        Matcher m = CLASS_DECL.matcher(src);
        return m.find() && hasContextBearingAncestor(m.group(2), graph);
    }

    static boolean isRunnableTest(Path javaFile) {
        String src = code(javaFile);
        if (!TEST_ANNOTATION.matcher(src).find()) return false;
        Matcher m = CLASS_DECL.matcher(src);
        boolean primaryIsAbstract = m.find() && m.group(1) != null;
        return !primaryIsAbstract;
    }

    /**
     * File source with comments removed, so prose containing Java keywords is not matched.
     */
    private static String code(Path p) {
        String src = read(p);
        src = BLOCK_COMMENT.matcher(src).replaceAll("");
        src = LINE_COMMENT.matcher(src).replaceAll("");
        return src;
    }

    private static String read(Path p) {
        try {
            return Files.readString(p);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
