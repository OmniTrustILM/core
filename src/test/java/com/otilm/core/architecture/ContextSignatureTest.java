package com.otilm.core.architecture;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContextSignatureTest {

    private Path write(Path dir, String name, String src) throws IOException {
        Path f = dir.resolve(name);
        Files.writeString(f, src);
        return f;
    }

    @Test
    void parsesImportsMocksProfilesPropsAndDirties(@TempDir Path dir) throws IOException {
        Path f = write(dir, "SampleITest.java", """
                package x;
                @Import({ProducerMocks.class, PollMocks.class})
                @ActiveProfiles(value = {"messaging-int-test"}, inheritProfiles = false)
                @TestPropertySource(properties = {"a=1"})
                @DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
                class SampleITest extends BaseSpringBootTest {
                    @MockitoBean private OpaClient opaClient;
                    @MockitoSpyBean ActionProducer actionProducer;
                }
                """);
        TestClassTaxonomy.ContextTokens t = TestClassTaxonomy.annotationTokens(f);
        assertThat(t.imports()).containsExactlyInAnyOrder("ProducerMocks", "PollMocks");
        assertThat(t.mocks()).containsExactlyInAnyOrder("OpaClient", "ActionProducer");
        assertThat(t.profiles()).contains("messaging-int-test", "inheritProfiles=false");
        assertThat(t.props()).isNotEmpty();
        assertThat(t.dirties()).contains("BEFORE_CLASS");
    }

    @Test
    void signatureUnionsAncestorChainAndIsOrderInsensitiveForImports(@TempDir Path dir) throws IOException {
        write(dir, "BaseSpringBootTest.java", """
                @SpringBootTest class BaseSpringBootTest {
                    @MockitoBean OpaClient opaClient;
                    @MockitoBean AuditLogsProducer auditLogsProducer;
                }
                """);
        write(dir, "AbITest.java", """
                @Import({ProducerMocks.class, PollMocks.class})
                class AbITest extends BaseSpringBootTest {}
                """);
        write(dir, "BaITest.java", """
                @Import({PollMocks.class, ProducerMocks.class})
                class BaITest extends BaseSpringBootTest {}
                """);
        Map<String, String> graph = TestClassTaxonomy.parseExtends(dir);
        Map<String, Path> byName = ContextSignature.filesBySimpleName(dir);
        assertThat(ContextSignature.of("AbITest", graph, byName))
                .isEqualTo(ContextSignature.of("BaITest", graph, byName));
    }

    @Test
    void nestedTestConfigurationForksSignatureAndIsCaptured(@TempDir Path dir) throws IOException {
        write(dir, "BaseSpringBootTest.java", """
                @SpringBootTest class BaseSpringBootTest {}
                """);
        Path a = write(dir, "AuditLogAspectITest.java", """
                class AuditLogAspectITest extends BaseSpringBootTest {
                    @TestConfiguration
                    static class AuditConfig {}
                }
                """);
        write(dir, "UpdateTrustedCaMarkITest.java", """
                class UpdateTrustedCaMarkITest extends BaseSpringBootTest {
                    @TestConfiguration
                    static class TrustedCaConfig {}
                }
                """);
        TestClassTaxonomy.ContextTokens ta = TestClassTaxonomy.annotationTokens(a);
        assertThat(ta.configs()).containsExactly("AuditConfig");

        Map<String, String> graph = TestClassTaxonomy.parseExtends(dir);
        Map<String, Path> byName = ContextSignature.filesBySimpleName(dir);
        assertThat(ContextSignature.of("AuditLogAspectITest", graph, byName))
                .isNotEqualTo(ContextSignature.of("UpdateTrustedCaMarkITest", graph, byName));
    }

    @Test
    void springBootTestArgumentsForkSignature(@TempDir Path dir) throws IOException {
        write(dir, "RandomPortITest.java", """
                @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
                class RandomPortITest {}
                """);
        write(dir, "DefaultEnvITest.java", """
                @SpringBootTest
                class DefaultEnvITest {}
                """);
        Map<String, String> graph = TestClassTaxonomy.parseExtends(dir);
        Map<String, Path> byName = ContextSignature.filesBySimpleName(dir);
        assertThat(ContextSignature.of("RandomPortITest", graph, byName))
                .isNotEqualTo(ContextSignature.of("DefaultEnvITest", graph, byName));
    }

    @Test
    void autoConfigureAnnotationForksSignature(@TempDir Path dir) throws IOException {
        write(dir, "MockMvcITest.java", """
                @SpringBootTest
                @AutoConfigureMockMvc
                class MockMvcITest {}
                """);
        write(dir, "PlainITest.java", """
                @SpringBootTest
                class PlainITest {}
                """);
        Map<String, String> graph = TestClassTaxonomy.parseExtends(dir);
        Map<String, Path> byName = ContextSignature.filesBySimpleName(dir);
        assertThat(ContextSignature.of("MockMvcITest", graph, byName))
                .isNotEqualTo(ContextSignature.of("PlainITest", graph, byName));
    }

    @Test
    void typeExcludeFiltersForkSignature(@TempDir Path dir) throws IOException {
        Path filtered = write(dir, "FilteredITest.java", """
                @SpringBootTest
                @Import(ProducerMocks.class)
                @TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
                class FilteredITest {}
                """);
        write(dir, "UnfilteredITest.java", """
                @SpringBootTest
                @Import(ProducerMocks.class)
                class UnfilteredITest {}
                """);
        assertThat(TestClassTaxonomy.annotationTokens(filtered).typeExcludeFilters())
                .containsExactly("ProducerMocks.MockedProducersTypeExcludeFilter");

        Map<String, String> graph = TestClassTaxonomy.parseExtends(dir);
        Map<String, Path> byName = ContextSignature.filesBySimpleName(dir);
        assertThat(ContextSignature.of("FilteredITest", graph, byName))
                .isNotEqualTo(ContextSignature.of("UnfilteredITest", graph, byName));
    }

    @Test
    void typeExcludeFilterOrderIsNotASignatureAxis(@TempDir Path dir) throws IOException {
        // TypeExcludeFiltersContextCustomizer's equals/hashCode are the filter SET, so order cannot fork the context.
        write(dir, "AbFilterITest.java", """
                @SpringBootTest
                @TypeExcludeFilters({ProducerMocks.MockedProducersTypeExcludeFilter.class, PollMocks.PollFilter.class})
                class AbFilterITest {}
                """);
        write(dir, "BaFilterITest.java", """
                @SpringBootTest
                @TypeExcludeFilters({PollMocks.PollFilter.class, ProducerMocks.MockedProducersTypeExcludeFilter.class})
                class BaFilterITest {}
                """);
        Map<String, String> graph = TestClassTaxonomy.parseExtends(dir);
        Map<String, Path> byName = ContextSignature.filesBySimpleName(dir);
        assertThat(ContextSignature.of("AbFilterITest", graph, byName))
                .isEqualTo(ContextSignature.of("BaFilterITest", graph, byName));
    }

    @Test
    void typeExcludeFiltersKeepTheirOuterClassQualifier(@TempDir Path dir) throws IOException {
        // Two modules may each declare a same-named nested filter; dropping the qualifier would collapse them.
        Path a = write(dir, "AModuleITest.java", """
                @SpringBootTest
                @TypeExcludeFilters(AMocks.ExcludeFilter.class)
                class AModuleITest {}
                """);
        write(dir, "BModuleITest.java", """
                @SpringBootTest
                @TypeExcludeFilters(BMocks.ExcludeFilter.class)
                class BModuleITest {}
                """);
        assertThat(TestClassTaxonomy.annotationTokens(a).typeExcludeFilters()).containsExactly("AMocks.ExcludeFilter");

        Map<String, String> graph = TestClassTaxonomy.parseExtends(dir);
        Map<String, Path> byName = ContextSignature.filesBySimpleName(dir);
        assertThat(ContextSignature.of("AModuleITest", graph, byName))
                .isNotEqualTo(ContextSignature.of("BModuleITest", graph, byName));
    }

    @Test
    void typeExcludeFiltersAreInheritedWhenTheSubclassDeclaresNone(@TempDir Path dir) throws IOException {
        // @TypeExcludeFilters is @Inherited, so a base class's filters apply to a subclass that declares none.
        write(dir, "BaseFilteredTest.java", """
                @SpringBootTest
                @TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
                abstract class BaseFilteredTest {}
                """);
        write(dir, "ChildITest.java", """
                class ChildITest extends BaseFilteredTest {}
                """);
        write(dir, "StandaloneITest.java", """
                @SpringBootTest
                @TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
                class StandaloneITest {}
                """);
        Map<String, String> graph = TestClassTaxonomy.parseExtends(dir);
        Map<String, Path> byName = ContextSignature.filesBySimpleName(dir);
        assertThat(ContextSignature.of("ChildITest", graph, byName))
                .isEqualTo(ContextSignature.of("StandaloneITest", graph, byName));
    }

    @Test
    void aSubclassTypeExcludeFiltersDeclarationShadowsTheAncestors(@TempDir Path dir) throws IOException {
        // TypeExcludeFiltersContextCustomizerFactory resolves the NEAREST @TypeExcludeFilters declaration and uses
        // only its value(), so the base class's filter A does not reach the context at all.
        write(dir, "BaseFilteredTest.java", """
                @SpringBootTest
                @TypeExcludeFilters(AMocks.ExcludeFilter.class)
                abstract class BaseFilteredTest {}
                """);
        write(dir, "ShadowingITest.java", """
                @TypeExcludeFilters(BMocks.ExcludeFilter.class)
                class ShadowingITest extends BaseFilteredTest {}
                """);
        write(dir, "OnlyBITest.java", """
                @SpringBootTest
                @TypeExcludeFilters(BMocks.ExcludeFilter.class)
                class OnlyBITest {}
                """);
        write(dir, "BothFiltersITest.java", """
                @SpringBootTest
                @TypeExcludeFilters({AMocks.ExcludeFilter.class, BMocks.ExcludeFilter.class})
                class BothFiltersITest {}
                """);
        Map<String, String> graph = TestClassTaxonomy.parseExtends(dir);
        Map<String, Path> byName = ContextSignature.filesBySimpleName(dir);
        assertThat(ContextSignature.of("ShadowingITest", graph, byName))
                .isEqualTo(ContextSignature.of("OnlyBITest", graph, byName))
                .isNotEqualTo(ContextSignature.of("BothFiltersITest", graph, byName));
    }

    @Test
    void ownDynamicPropertySourceMethodsForkEvenWhenTheyRegisterIdenticalProperties(@TempDir Path dir)
            throws IOException {
        // DynamicPropertiesContextCustomizer keys on the Set<Method>, so what a method registers is irrelevant:
        // two classes each declaring their own can never share a context, and one declaring none is distinct again.
        write(dir, "BaseSpringBootTest.java", """
                @SpringBootTest class BaseSpringBootTest {}
                """);
        write(dir, "OwnAITest.java", """
                class OwnAITest extends BaseSpringBootTest {
                    @DynamicPropertySource
                    static void authServiceProperties(DynamicPropertyRegistry registry) {
                        registry.add("auth-service.base-url", () -> "http://localhost:10001");
                    }
                }
                """);
        write(dir, "OwnBITest.java", """
                class OwnBITest extends BaseSpringBootTest {
                    @DynamicPropertySource
                    static void authServiceProperties(DynamicPropertyRegistry registry) {
                        registry.add("auth-service.base-url", () -> "http://localhost:10001");
                    }
                }
                """);
        write(dir, "NoneITest.java", """
                class NoneITest extends BaseSpringBootTest {}
                """);
        Map<String, String> graph = TestClassTaxonomy.parseExtends(dir);
        Map<String, Path> byName = ContextSignature.filesBySimpleName(dir);
        assertThat(ContextSignature.of("OwnAITest", graph, byName))
                .isNotEqualTo(ContextSignature.of("OwnBITest", graph, byName))
                .isNotEqualTo(ContextSignature.of("NoneITest", graph, byName));
    }

    @Test
    void anInheritedDynamicPropertySourceMethodIsSharedBySubclasses(@TempDir Path dir) throws IOException {
        // MethodIntrospector resolves an inherited static method to the base class's Method, so every subclass
        // collects the same Set<Method> and they share one context — the reason a base class is the way to hoist one.
        write(dir, "BaseContainerTest.java", """
                @SpringBootTest
                abstract class BaseContainerTest {
                    @DynamicPropertySource
                    static void brokerProperties(DynamicPropertyRegistry registry) {
                        registry.add("spring.messaging.broker-url", container::getAmqpUrl);
                    }
                }
                """);
        write(dir, "FirstChildITest.java", """
                class FirstChildITest extends BaseContainerTest {}
                """);
        write(dir, "SecondChildITest.java", """
                class SecondChildITest extends BaseContainerTest {}
                """);
        Map<String, String> graph = TestClassTaxonomy.parseExtends(dir);
        Map<String, Path> byName = ContextSignature.filesBySimpleName(dir);
        assertThat(ContextSignature.of("FirstChildITest", graph, byName))
                .isEqualTo(ContextSignature.of("SecondChildITest", graph, byName));
    }

    @Test
    void aSubclassDynamicPropertySourceMethodUnionsWithTheInheritedOne(@TempDir Path dir) throws IOException {
        // Unlike @TypeExcludeFilters, findMethods() collects the enclosing/base methods AND the local one, so a
        // subclass that adds its own does not shadow the base's — it forks away from its plain siblings.
        write(dir, "BaseContainerTest.java", """
                @SpringBootTest
                abstract class BaseContainerTest {
                    @DynamicPropertySource
                    static void brokerProperties(DynamicPropertyRegistry registry) {
                        registry.add("spring.messaging.broker-url", container::getAmqpUrl);
                    }
                }
                """);
        write(dir, "PlainChildITest.java", """
                class PlainChildITest extends BaseContainerTest {}
                """);
        write(dir, "AddsOwnITest.java", """
                class AddsOwnITest extends BaseContainerTest {
                    @DynamicPropertySource
                    static void extraProperties(DynamicPropertyRegistry registry) {
                        registry.add("proxy.enabled", () -> "false");
                    }
                }
                """);
        Map<String, String> graph = TestClassTaxonomy.parseExtends(dir);
        Map<String, Path> byName = ContextSignature.filesBySimpleName(dir);
        assertThat(ContextSignature.of("AddsOwnITest", graph, byName))
                .isNotEqualTo(ContextSignature.of("PlainChildITest", graph, byName))
                // Inequality alone would also hold under a nearest-declaration-wins model, so assert the union
                // itself: both hops must appear, each keyed by the class that declares it.
                .contains("BaseContainerTest#brokerProperties", "AddsOwnITest#extraProperties");
        assertThat(TestClassTaxonomy.annotationTokens(byName.get("AddsOwnITest")).dynamicPropertySources())
                .containsExactly("extraProperties");
    }

    @Test
    void anInterposedAnnotationDoesNotHideADynamicPropertySourceDeclaration(@TempDir Path dir) throws IOException {
        // A declaration the capture cannot parse would drop out of the axis silently and understate the fork count,
        // so the shape must tolerate whatever sits between the annotation and `void`.
        Path f = write(dir, "AnnotatedDpsITest.java", """
                @SpringBootTest
                class AnnotatedDpsITest {
                    @DynamicPropertySource
                    @SuppressWarnings({"unused"})
                    static void extraProperties(DynamicPropertyRegistry registry) {
                        registry.add("proxy.enabled", () -> "false");
                    }
                }
                """);
        assertThat(TestClassTaxonomy.annotationTokens(f).dynamicPropertySources()).containsExactly("extraProperties");
    }

    @Test
    void anUnparseableDynamicPropertySourceDeclarationFailsLoudly(@TempDir Path dir) throws IOException {
        // The guard's distinct count only ever falls when a declaration is dropped, so silence is indistinguishable
        // from correctness. Anything the capture cannot read must raise instead.
        Path f = write(dir, "OddDpsITest.java", """
                @SpringBootTest
                class OddDpsITest {
                    @DynamicPropertySource
                    static <T> void extraProperties(DynamicPropertyRegistry registry) {
                        registry.add("proxy.enabled", () -> "false");
                    }
                }
                """);
        assertThatThrownBy(() -> TestClassTaxonomy.annotationTokens(f))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("@DynamicPropertySource");
    }

    @Test
    void aUrlInsideAnAnnotationValueIsNotMistakenForALineComment(@TempDir Path dir) throws IOException {
        // The `//` of a URL scheme is string content. Stripping it as a comment would truncate the line before the
        // annotation's closing parenthesis, so the arg capture would run on into the class body and no two classes
        // would ever look alike. A real trailing comment on the same line must still be stripped.
        Path f = write(dir, "UrlPropsITest.java", """
                @SpringBootTest
                @TestPropertySource(properties = "auth-service.base-url=http://localhost:10001") // pinned mock port
                class UrlPropsITest {
                    @MockitoBean OpaClient opaClient;
                }
                """);
        TestClassTaxonomy.ContextTokens t = TestClassTaxonomy.annotationTokens(f);
        assertThat(t.props()).containsExactly("properties = \"auth-service.base-url=http://localhost:10001\"");
        assertThat(t.mocks()).containsExactly("OpaClient");

        write(dir, "SameUrlPropsITest.java", """
                @SpringBootTest
                @TestPropertySource(properties = "auth-service.base-url=http://localhost:10001")
                class SameUrlPropsITest {
                    @MockitoBean OpaClient opaClient;
                }
                """);
        write(dir, "OtherUrlPropsITest.java", """
                @SpringBootTest
                @TestPropertySource(properties = "auth-service.base-url=http://localhost:10002")
                class OtherUrlPropsITest {
                    @MockitoBean OpaClient opaClient;
                }
                """);
        Map<String, String> graph = TestClassTaxonomy.parseExtends(dir);
        Map<String, Path> byName = ContextSignature.filesBySimpleName(dir);
        assertThat(ContextSignature.of("UrlPropsITest", graph, byName))
                .isEqualTo(ContextSignature.of("SameUrlPropsITest", graph, byName))
                .isNotEqualTo(ContextSignature.of("OtherUrlPropsITest", graph, byName));
    }

    @Test
    void textBlockFixtureContentIsNotParsedAsRealAnnotations(@TempDir Path dir) throws IOException {
        // A meta-test whose only "annotations" live inside a text block (fixture data), like this very
        // class. code() strips text blocks, so these must not be misread as real context annotations.
        String content = """
                package x;
                class MetaTest {
                    String fixture = \"""
                            @Import({ProducerMocks.class, PollMocks.class})
                            @ActiveProfiles("messaging-int-test")
                            @TestConfiguration static class Nested {}
                            class Sample extends BaseSpringBootTest {}
                            \""";
                }
                """;
        Path f = write(dir, "MetaTest.java", content);
        TestClassTaxonomy.ContextTokens t = TestClassTaxonomy.annotationTokens(f);
        assertThat(t.imports()).isEmpty();
        assertThat(t.profiles()).isEmpty();
        assertThat(t.configs()).isEmpty();
    }
}
