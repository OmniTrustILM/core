package com.otilm.core.architecture;

import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import java.util.Map;
import static org.assertj.core.api.Assertions.assertThat;

class TestClassTaxonomyTest {

    private static final Path TEST_ROOT = Path.of("src/test/java");

    @Test
    void resolvesDirectContextExtension() {
        Map<String,String> graph = TestClassTaxonomy.parseExtends(TEST_ROOT);
        assertThat(graph).containsEntry("BaseMessagingIntTest", "BaseSpringBootTest");
    }

    @Test
    void detectsTransitiveContextThroughIntermediateBase() {
        // A class extending BaseMessagingIntTest loads a context transitively.
        Map<String,String> graph = TestClassTaxonomy.parseExtends(TEST_ROOT);
        assertThat(TestClassTaxonomy.hasContextBearingAncestor("BaseMessagingIntTest", graph))
                .isTrue();
    }

    @Test
    void treatsAnnotationOnlyNoAuthBaseAsContextRoot() {
        assertThat(TestClassTaxonomy.contextBearingRoots()).contains("BaseSpringBootTestNoAuth");
    }

    @Test
    void abstractBaseIsNotRunnable() {
        assertThat(TestClassTaxonomy.isRunnableTest(
                TEST_ROOT.resolve("com/otilm/core/integration/messaging/jms/AbstractJmsResilienceITest.java"))).isFalse();
    }

    @Test
    void concreteTestClassIsRunnable() {
        // A concrete class with real @Test methods is runnable (this very test class).
        assertThat(TestClassTaxonomy.isRunnableTest(
                TEST_ROOT.resolve("com/otilm/core/architecture/TestClassTaxonomyTest.java"))).isTrue();
    }

    @Test
    void abstractClassWithTestMethodsIsNotRunnable() {
        // BaseMessagingIntTest is `public abstract class` and declares an @Test method:
        // exercises the abstract-exclusion branch, not just the no-annotation branch.
        assertThat(TestClassTaxonomy.isRunnableTest(
                TEST_ROOT.resolve("com/otilm/core/util/BaseMessagingIntTest.java"))).isFalse();
    }

    @Test
    void abstractClassStringLiteralDoesNotMakeClassNonRunnable() {
        // CiTestSplitTest's own source contains the literal "abstract class" (in a helper that
        // scans files); a whole-file substring check would wrongly mark it non-runnable.
        assertThat(TestClassTaxonomy.isRunnableTest(
                TEST_ROOT.resolve("com/otilm/core/architecture/CiTestSplitTest.java"))).isTrue();
    }

    @Test
    void testConfigurationAnnotationIsNotAtTestMethod() {
        // SpringBootTestContext is a concrete @TestConfiguration with no @Test method:
        // a naive @Test-substring check matches @TestConfiguration and wrongly marks it runnable.
        assertThat(TestClassTaxonomy.isRunnableTest(
                TEST_ROOT.resolve("com/otilm/core/util/SpringBootTestContext.java"))).isFalse();
    }

    @Test
    void loadsContextViaDirectSpringBootTestAnnotation() {
        // ApplicationITest is annotated @SpringBootTest and is neither a CONTEXT_ROOT nor extends one,
        // so a true verdict can only come from the direct-annotation branch of loadsContext.
        Map<String,String> graph = TestClassTaxonomy.parseExtends(TEST_ROOT);
        assertThat(TestClassTaxonomy.loadsContext(
                TEST_ROOT.resolve("com/otilm/core/integration/ApplicationITest.java"), graph)).isTrue();
    }

    @Test
    void loadsContextViaTransitiveContextBearingAncestor() {
        // V3AsyncPollITest carries no @SpringBootTest of its own; it extends BaseMessagingIntTest,
        // which extends BaseSpringBootTest — so a true verdict can only come from the extends-chain branch.
        Map<String,String> graph = TestClassTaxonomy.parseExtends(TEST_ROOT);
        assertThat(TestClassTaxonomy.loadsContext(
                TEST_ROOT.resolve("com/otilm/core/integration/service/v3/V3AsyncPollITest.java"), graph)).isTrue();
    }

    @Test
    void annotationLikeStringLiteralsDoNotSelfClassify() {
        // The kernel's own source contains the string literals "@Test\\b" and "@SpringBootTest\\b"
        // (its regexes). Mid-line literals must not count as annotations: the kernel is neither a
        // runnable test nor a context loader.
        Path kernel = TEST_ROOT.resolve("com/otilm/core/architecture/TestClassTaxonomy.java");
        Map<String,String> graph = TestClassTaxonomy.parseExtends(TEST_ROOT);
        assertThat(TestClassTaxonomy.isRunnableTest(kernel)).isFalse();
        assertThat(TestClassTaxonomy.loadsContext(kernel, graph)).isFalse();
    }
}
