package com.otilm.core.architecture;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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
 * <li><b>First class per file is the primary type.</b> {@link #parseExtends} records the first {@code class}
 * declaration in each file and ignores nested/secondary classes. Every test file in this tree declares its primary type
 * first; files whose primary type is an {@code interface}/{@code enum}/{@code record} are absent from the graph.</li>
 * <li><b>Source is comment-stripped by a string-literal-aware scan.</b> Comments are removed so prose containing Java
 * keywords (e.g. "Base class for ...") is not matched, and annotation/keyword checks are token-anchored (word
 * boundaries) so that {@code @TestConfiguration} is not mistaken for {@code @Test} nor a {@code "abstract class"}
 * string literal for an abstract declaration.</li>
 * <li><b>The inheritance graph is keyed by the simple class name.</b> {@link #parseExtends} records
 * {@code simpleName -> superSimpleName}, and {@link #hasContextBearingAncestor} resolves {@code extends} clauses (which
 * use simple names) against it. {@code parseExtends} throws only on a duplicate primary simple name with a
 * <em>conflicting</em> supertype — that is the case that would corrupt context-ancestry resolution. Two unrelated
 * classes sharing a simple name but mapping to the same supertype (commonly both none) coalesce harmlessly.</li>
 * <li><b>Context detection is limited to {@code @SpringBootTest} and the known context-root base classes. </b> Spring
 * test-slice / meta-annotations that also start a context ({@code @WebMvcTest}, {@code @DataJpaTest},
 * {@code @JsonTest}, {@code @ContextConfiguration}, a bare {@code @ExtendWith(SpringExtension.class)}) are
 * intentionally out of scope — none exist in this tree.</li>
 * </ul>
 */
final class TestClassTaxonomy {

    private static final Set<String> CONTEXT_ROOTS = Set
            .of("BaseSpringBootTest", "BaseSpringBootTestNoAuth", "BaseMessagingIntTest", "BaseMigrationTest",
                    "BaseComplianceTest");

    // Primary class declaration: optional `abstract` modifier (adjacent to `class` in this codebase), the class name,
    // an optional generic parameter list (so `class Foo<T> extends Base` still captures the supertype),
    // and an optional single `extends` supertype (simple name).
    private static final Pattern CLASS_DECL = Pattern
            .compile("(abstract\\s+)?class\\s+(\\w+)(?:<[^>]*>)?(?:\\s+extends\\s+(\\w+))?");

    // Nested class declaration: an indented `class` keyword (the primary type is at column 0), preceded by any run of
    // annotations and modifiers, which may span lines — `@Nested` typically sits on its own line above the keyword.
    private static final Pattern NESTED_CLASS_DECL = Pattern
            .compile("(?m)^[ \\t]+((?:(?:@\\w+(?:\\([^)]*\\))?|public|protected|private|static|final|abstract|sealed"
                    + "|non-sealed)\\s+)*)class\\s+(\\w+)");

    // Annotation checks are:
    // (a) line-anchored — a real annotation begins its line (after indentation)
    // (b) token-anchored with `\b` so `@Test` does not match `@TestConfiguration`/`@Testcontainers`/`@TestInstance`.
    private static final Pattern TEST_ANNOTATION = Pattern
            .compile("(?m)^[ \\t]*(?:@Test\\b|@ParameterizedTest\\b|@RepeatedTest\\b)");
    private static final Pattern SPRING_BOOT_TEST = Pattern.compile("(?m)^[ \\t]*@SpringBootTest\\b");

    // Context-affecting annotations parsed by annotationTokens(). Each contributes one axis of the context cache key.
    private static final Pattern IMPORTS = Pattern.compile("@Import\\s*\\(([^)]*)\\)");
    private static final Pattern IMPORT_CLASS = Pattern.compile("(\\w+)\\s*\\.\\s*class");
    private static final Pattern MOCK_FIELD = Pattern
            .compile("@Mockito(?:Bean|SpyBean)\\b[^;{}]*?\\b(\\w+)\\s+\\w+\\s*;");
    private static final Pattern PROFILES = Pattern.compile("@ActiveProfiles\\s*\\(([^)]*)\\)");
    private static final Pattern QUOTED = Pattern.compile("\"([^\"]*)\"");
    private static final Pattern INHERIT = Pattern.compile("inheritProfiles\\s*=\\s*(true|false)");
    private static final Pattern PROPS = Pattern.compile("@TestPropertySource\\s*\\(([^)]*)\\)");
    private static final Pattern DIRTIES = Pattern.compile("@DirtiesContext\\b(?:\\s*\\(([^)]*)\\))?");
    // Nested @TestConfiguration classes fork the context cache key. Match the annotation (with optional args),
    // tolerate interposed other annotations/modifiers, and capture the declared class simple-name.
    private static final Pattern NESTED_CONFIG = Pattern
            .compile("@TestConfiguration\\b(?:\\s*\\([^)]*\\))?"
                    + "(?:\\s+(?:@\\w+(?:\\([^)]*\\))?|public|protected|private|static|final|abstract))*"
                    + "\\s+class\\s+(\\w+)");
    // @SpringBootTest arguments (webEnvironment=..., classes=...) select distinct contexts from the default.
    private static final Pattern SPRING_BOOT_TEST_ARGS = Pattern.compile("@SpringBootTest\\b\\s*(?:\\(([^)]*)\\))?");
    // @AutoConfigure* slice/test annotations (e.g. @AutoConfigureMockMvc) fork the context cache key.
    private static final Pattern AUTOCONFIGURE = Pattern.compile("@(AutoConfigure\\w+)\\b");
    // @TypeExcludeFilters becomes a TypeExcludeFiltersContextCustomizer whose equals/hashCode are the filter SET,
    // so the filter classes fork the context cache key and their declaration order does not.
    private static final Pattern TYPE_EXCLUDE_FILTERS = Pattern.compile("@TypeExcludeFilters\\s*\\(([^)]*)\\)");
    // Filter class references keep their outer-class qualifier: the filters here are nested types, and two modules
    // could each declare a same-named nested filter.
    private static final Pattern FILTER_CLASS = Pattern.compile("((?:\\w+\\.)*\\w+)\\.class");
    // @DynamicPropertySource becomes a DynamicPropertiesContextCustomizer whose equals/hashCode are the Set<Method>
    // it collected, so each declaring method forks the context cache key.
    private static final Pattern DYNAMIC_PROPERTY_SOURCE = Pattern
            .compile("@DynamicPropertySource\\b(?:\\s*\\([^)]*\\))?"
                    + "(?:\\s+(?:@\\w+(?:\\([^)]*\\))?|public|protected|private|static|final|synchronized))*"
                    + "\\s+void\\s+(\\w+)\\s*\\(");
    // Counts declarations independently of the capture above so an unparseable shape fails.
    private static final Pattern DYNAMIC_PROPERTY_SOURCE_MARKER = Pattern.compile("(?m)^\\s*@DynamicPropertySource\\b");

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
                        throw new IllegalStateException("Duplicate primary test-class simple name '" + name
                                + "' with conflicting supertypes at " + p + "; the context graph is keyed by "
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
            if (CONTEXT_ROOTS.contains(cur)) {
                return true;
            }
            cur = graph.get(cur);
        }
        return false;
    }

    static boolean loadsContext(Path javaFile, Map<String, String> graph) {
        String src = code(javaFile);
        if (SPRING_BOOT_TEST.matcher(src).find()) {
            return true;
        }
        String primary = primaryClassName(src);
        return primary != null && hasContextBearingAncestor(primary, graph);
    }

    /**
     * Simple name of the file's primary type — the first {@code class} declaration, the same one {@link #parseExtends}
     * keys the inheritance graph by — or {@code null} for a file declaring none.
     */
    static String primaryClassName(Path javaFile) {
        return primaryClassName(code(javaFile));
    }

    private static String primaryClassName(String src) {
        Matcher m = CLASS_DECL.matcher(src);
        return m.find() ? m.group(2) : null;
    }

    static boolean isRunnableTest(Path javaFile) {
        String src = code(javaFile);
        if (!TEST_ANNOTATION.matcher(src).find()) {
            return false;
        }
        Matcher m = CLASS_DECL.matcher(src);
        boolean primaryIsAbstract = m.find() && m.group(1) != null;
        return !primaryIsAbstract;
    }

    /**
     * A class declared inside another class in the same file.
     *
     * @param name the nested class simple name
     * @param junitNested whether the declaration carries {@code @Nested}
     */
    record NestedClass(String name, boolean junitNested) {
    }

    /**
     * Every class declared inside the file's primary type, in declaration order.
     */
    static List<NestedClass> nestedClasses(Path javaFile) {
        List<NestedClass> nested = new ArrayList<>();
        Matcher m = NESTED_CLASS_DECL.matcher(code(javaFile));
        while (m.find()) {
            nested.add(new NestedClass(m.group(2), m.group(1).contains("@Nested")));
        }
        return nested;
    }

    /**
     * Context-affecting annotation tokens parsed from ONE file (not its ancestors). Each list is an axis of the Spring
     * context cache key; {@link ContextSignature} combines the axes across the inheritance chain — unioning the
     * inherited ones, and taking only the nearest declaration where Spring itself does (see
     * {@link #typeExcludeFilters()}).
     */
    record ContextTokens(List<String> imports, List<String> mocks, List<String> profiles, List<String> props,
            List<String> dirties, List<String> configs, List<String> springBootTest, List<String> autoconfig,
            List<String> typeExcludeFilters, List<String> dynamicPropertySources) {
    }

    static ContextTokens annotationTokens(Path javaFile) {
        String src = code(javaFile);

        List<String> imports = new ArrayList<>();
        for (String importList : allMatches(IMPORTS, 1, src)) {
            imports.addAll(allMatches(IMPORT_CLASS, 1, importList));
        }

        return new ContextTokens(imports, allMatches(MOCK_FIELD, 1, src), parseProfiles(src),
                normalizedArgs(PROPS, src), parseDirties(src), allMatches(NESTED_CONFIG, 1, src),
                normalizedArgs(SPRING_BOOT_TEST_ARGS, src), allMatches(AUTOCONFIGURE, 1, src),
                parseTypeExcludeFilters(src), parseDynamicPropertySources(javaFile, src));
    }

    /**
     * Method names of every {@code @DynamicPropertySource} declaration, cross-checked against an independent count of
     * the annotation itself.
     */
    private static List<String> parseDynamicPropertySources(Path javaFile, String src) {
        List<String> methods = allMatches(DYNAMIC_PROPERTY_SOURCE, 1, src);
        int declared = allMatches(DYNAMIC_PROPERTY_SOURCE_MARKER, 0, src).size();
        if (methods.size() != declared) {
            throw new IllegalStateException("Parsed " + methods.size() + " @DynamicPropertySource method name(s) "
                    + methods + " but found " + declared + " declaration(s) in " + javaFile
                    + "; DYNAMIC_PROPERTY_SOURCE cannot parse this declaration shape. Widen the pattern rather than "
                    + "reshaping the test class — a dropped method models a forked context as a shared one.");
        }
        return methods;
    }

    /** Every {@code group} capture across all matches of {@code p} in {@code src}. */
    private static List<String> allMatches(Pattern p, int group, String src) {
        List<String> out = new ArrayList<>();
        Matcher m = p.matcher(src);
        while (m.find()) {
            out.add(m.group(group));
        }
        return out;
    }

    /** The {@code group} capture of the first match of {@code p} in {@code src}, or {@code null} if none. */
    private static String firstMatch(Pattern p, int group, String src) {
        Matcher m = p.matcher(src);
        return m.find() ? m.group(group) : null;
    }

    /** First match's group-1 args, whitespace-normalized, as a singleton list (empty when there is no match). */
    private static List<String> normalizedArgs(Pattern p, String src) {
        String args = firstMatch(p, 1, src);
        return args == null ? List.of() : List.of(args.replaceAll("\\s+", " ").trim());
    }

    private static List<String> parseProfiles(String src) {
        String args = firstMatch(PROFILES, 1, src);
        if (args == null) {
            return List.of();
        }
        List<String> profiles = allMatches(QUOTED, 1, args);
        Matcher inherit = INHERIT.matcher(args);
        profiles.add("inheritProfiles=" + (inherit.find() ? inherit.group(1) : "true"));
        return profiles;
    }

    private static List<String> parseTypeExcludeFilters(String src) {
        List<String> filters = new ArrayList<>();
        for (String args : allMatches(TYPE_EXCLUDE_FILTERS, 1, src)) {
            filters.addAll(allMatches(FILTER_CLASS, 1, args.replaceAll("\\s+", "")));
        }
        return filters;
    }

    private static List<String> parseDirties(String src) {
        Matcher m = DIRTIES.matcher(src);
        return m.find() ? List.of(dirtiesMode(m.group(1))) : List.of();
    }

    private static String dirtiesMode(String args) {
        if (args == null) {
            return "DEFAULT";
        }
        if (args.contains("BEFORE_CLASS")) {
            return "BEFORE_CLASS";
        }
        if (args.contains("AFTER_CLASS")) {
            return "AFTER_CLASS";
        }
        if (args.contains("AFTER_EACH") || args.contains("AFTER_METHOD")) {
            return "AFTER_METHOD";
        }
        return "OTHER";
    }

    /**
     * Source with comments removed and text blocks emptied.
     */
    private static String code(Path p) {
        String src = read(p);
        StringBuilder out = new StringBuilder(src.length());
        int i = 0;
        while (i < src.length()) {
            char c = src.charAt(i);
            if (src.startsWith("\"\"\"", i)) {
                int end = src.indexOf("\"\"\"", i + 3);
                out.append("\"\"");
                i = end < 0 ? src.length() : end + 3;
            } else if (src.startsWith("/*", i)) {
                int end = src.indexOf("*/", i + 2);
                i = end < 0 ? src.length() : end + 2;
            } else if (src.startsWith("//", i)) {
                int end = src.indexOf('\n', i);
                i = end < 0 ? src.length() : end;
            } else if (c == '"' || c == '\'') {
                int j = i + 1;
                while (j < src.length() && src.charAt(j) != c) {
                    j += src.charAt(j) == '\\' ? 2 : 1;
                }
                out.append(src, i, Math.min(j + 1, src.length()));
                i = j + 1;
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }

    private static String read(Path p) {
        try {
            return Files.readString(p);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
