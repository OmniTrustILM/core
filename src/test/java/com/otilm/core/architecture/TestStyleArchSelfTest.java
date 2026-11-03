package com.otilm.core.architecture;

import com.otilm.core.util.BaseSpringBootTest;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.lang.ArchRule;
import java.io.IOException;
import java.util.List;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Evaluates each unfrozen {@link TestStyleArchTest} rule against a planted departure it must report and the nearest
 * compliant neighbour it must pass. Planted test methods are abstract, so no test runner executes them.
 */
class TestStyleArchSelfTest {

    // ── AssertionLibraries ───────────────────────────────────────────────────

    @Nested
    class AssertionLibraries {

        @ParameterizedTest
        @ValueSource(classes = {
                PlantedJunitAssertions.class,
                PlantedJunit4Assertions.class,
                PlantedHamcrestAssertions.class})
        void reportsTheMethod_whenItCallsAnAssertionLibraryOtherThanAssertJ(Class<?> departure) {
            // given
            JavaClasses planted = importPlanted(departure);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.noJunitOrHamcrestAssertions(), planted);

            // then
            assertThat(violations).singleElement().asString().contains("<" + departure.getName() + ".checksSum()>");
        }

        @Test
        void reportsTheMethodOnce_whenItCallsSeveralAssertions() {
            // given
            JavaClasses planted = importPlanted(PlantedRepeatedJunitAssertions.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.noJunitOrHamcrestAssertions(), planted);

            // then
            assertThat(violations).hasSize(1);
        }

        @Test
        void reportsEachOverload_whenSeveralOverloadsCallAssertions() {
            // given
            JavaClasses planted = importPlanted(PlantedOverloadedJunitAssertions.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.noJunitOrHamcrestAssertions(), planted);

            // then
            assertThat(violations)
                    .hasSize(2)
                    .anyMatch(violation -> violation.contains(".checksValue(int)>"))
                    .anyMatch(violation -> violation.contains(".checksValue(java.lang.String)>"));
        }

        @Test
        void namesTheEnclosingMethod_whenTheAssertionIsInALambda() {
            // given
            JavaClasses planted = importPlanted(PlantedJunitAssertionInLambda.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.noJunitOrHamcrestAssertions(), planted);

            // then
            assertThat(violations).singleElement().asString().contains("PlantedJunitAssertionInLambda.checksLater()>");
        }

        @Test
        void passes_whenTheMethodAssertsWithAssertJ() {
            // given
            JavaClasses planted = importPlanted(PlantedAssertJAssertions.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.noJunitOrHamcrestAssertions(), planted);

            // then
            assertThat(violations).isEmpty();
        }
    }

    // ── ThrowsClauses ────────────────────────────────────────────────────────

    @Nested
    class ThrowsClauses {

        @Test
        void reportsTheMethod_whenItThrowsANarrowerType() {
            // given
            JavaClasses planted = importPlanted(PlantedNarrowThrows.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.testMethodsThrowNothingOrException(), planted);

            // then
            assertThat(violations).singleElement().asString().contains("PlantedNarrowThrows.readsFile()>");
        }

        @Test
        void reportsEachKindOfTestMethod_whenItThrowsANarrowerType() {
            // given
            JavaClasses planted = importPlanted(PlantedLegacyTestKinds.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.testMethodsThrowNothingOrException(), planted);

            // then
            assertThat(violations).hasSize(4);
        }

        @Test
        void passes_whenTheMethodThrowsExceptionOrNothing() {
            // given
            JavaClasses planted = importPlanted(PlantedBroadThrows.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.testMethodsThrowNothingOrException(), planted);

            // then
            assertThat(violations).isEmpty();
        }
    }

    // ── LifecycleNames ───────────────────────────────────────────────────────

    @Nested
    class LifecycleNames {

        @Test
        void reportsTheMethods_whenTheyHaveGenericNames() {
            // given
            JavaClasses planted = importPlanted(PlantedGenericLifecycle.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.lifecycleMethodsAreNamedForWhatTheyArrange(),
                    planted);

            // then
            assertThat(violations)
                    .hasSize(4)
                    .anyMatch(violation -> violation.contains(".setUp()>"))
                    .anyMatch(violation -> violation.contains(".tearDown()>"))
                    .anyMatch(violation -> violation.contains(".init()>"))
                    .anyMatch(violation -> violation.contains(".teardown()>"));
        }

        @Test
        void passes_whenTheMethodIsNamedForWhatItArranges() {
            // given
            JavaClasses planted = importPlanted(PlantedNamedLifecycle.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.lifecycleMethodsAreNamedForWhatTheyArrange(),
                    planted);

            // then
            assertThat(violations).isEmpty();
        }
    }

    // ── TestNames ────────────────────────────────────────────────────────────

    @Nested
    class TestNames {

        @Test
        void reportsTheMethods_whenTheirNamesDepartFromVerbOutcomeWhenCondition() {
            // given
            JavaClasses planted = importPlanted(PlantedLegacyTestNames.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.testMethodsFollowVerbOutcomeWhenCondition(),
                    planted);

            // then
            assertThat(violations)
                    .hasSize(3)
                    .anyMatch(violation -> violation.contains(".testSigning()>"))
                    .anyMatch(violation -> violation.contains(".readsAgain_afterTheLoaderFailed_andKeepsTheOthers()>"))
                    .anyMatch(violation -> violation.contains(".ReturnsPolicy()>"));
        }

        @Test
        void reportsEachKindOfTestMethod_whenItsNameDepartsFromVerbOutcomeWhenCondition() {
            // given
            JavaClasses planted = importPlanted(PlantedLegacyTestKinds.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.testMethodsFollowVerbOutcomeWhenCondition(),
                    planted);

            // then
            assertThat(violations).hasSize(4);
        }

        @Test
        void passes_whenTheNamesFollowVerbOutcomeWhenCondition() {
            // given
            JavaClasses planted = importPlanted(PlantedStyledTestNames.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.testMethodsFollowVerbOutcomeWhenCondition(),
                    planted);

            // then
            assertThat(violations).isEmpty();
        }
    }

    // ── NestedClasses ────────────────────────────────────────────────────────

    @Nested
    class NestedClasses {

        @Test
        void reportsTheClass_whenItsNameEndsWithTests() {
            // given
            JavaClasses planted = importPlanted(PlantedNestedGroups.SigningTests.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.nestedClassesAreOneLevelDeepWithoutTestSuffix(),
                    planted);

            // then
            assertThat(violations).singleElement().asString().contains("PlantedNestedGroups$SigningTests>");
        }

        @Test
        void reportsTheClass_whenItIsNestedInAnotherNestedClass() {
            // given
            JavaClasses planted = importPlanted(PlantedNestedGroups.Export.class,
                    PlantedNestedGroups.Export.Pinned.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.nestedClassesAreOneLevelDeepWithoutTestSuffix(),
                    planted);

            // then
            assertThat(violations).singleElement().asString().contains("PlantedNestedGroups$Export$Pinned>");
        }

        @Test
        void passes_whenTheGroupIsOneLevelDeepAndNamedForWhatItGroups() {
            // given
            JavaClasses planted = importPlanted(PlantedNestedGroups.Signing.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.nestedClassesAreOneLevelDeepWithoutTestSuffix(),
                    planted);

            // then
            assertThat(violations).isEmpty();
        }
    }

    // ── BuilderClasses ───────────────────────────────────────────────────────

    @Nested
    class BuilderClasses {

        @Test
        void reportsTheClass_whenItIsNotPublicFinal() {
            // given
            JavaClasses planted = importPlanted(PlantedLooseBuilder.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.buildersArePublicFinalAndInMemory(), planted);

            // then
            assertThat(violations).hasSize(2).allMatch(violation -> violation.contains("PlantedLooseBuilder>"));
        }

        @ParameterizedTest
        @ValueSource(classes = {PlantedRepositoryBuilder.class, PlantedEntityManagerBuilder.class})
        void reportsTheClass_whenItDependsOnPersistence(Class<?> departure) {
            // given
            JavaClasses planted = importPlanted(departure);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.buildersArePublicFinalAndInMemory(), planted);

            // then
            assertThat(violations).singleElement().asString().contains("<" + departure.getName() + ">");
        }

        @Test
        void passes_whenTheBuilderIsPublicFinalAndInMemory() {
            // given
            JavaClasses planted = importPlanted(PlantedBuilder.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.buildersArePublicFinalAndInMemory(), planted);

            // then
            assertThat(violations).isEmpty();
        }
    }

    // ── FixtureClasses ───────────────────────────────────────────────────────

    @Nested
    class FixtureClasses {

        @Test
        void reportsTheClass_whenItIsOpenAndInstantiable() {
            // given
            JavaClasses planted = importPlanted(PlantedOpenFixtures.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.fixturesArePublicFinalWithPrivateConstructors(),
                    planted);

            // then
            assertThat(violations)
                    .hasSize(3)
                    .allMatch(violation -> violation.contains("TestStyleArchSelfTest$PlantedOpenFixtures"));
        }

        @Test
        void passes_whenTheClassIsPublicFinalWithAPrivateConstructor() {
            // given
            JavaClasses planted = importPlanted(PlantedFixtures.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.fixturesArePublicFinalWithPrivateConstructors(),
                    planted);

            // then
            assertThat(violations).isEmpty();
        }
    }

    // ── SpringBootTestPlacement ──────────────────────────────────────────────

    @Nested
    class SpringBootTestPlacement {

        @Test
        void reportsTheClass_whenItDeclaresItsOwnSpringBootTest() {
            // given
            JavaClasses planted = importPlanted(PlantedSpringBootTestCarrier.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.onlyBaseClassesCarrySpringBootTest(), planted);

            // then
            assertThat(violations).singleElement().asString().contains("PlantedSpringBootTestCarrier>");
        }

        @Test
        void passes_whenTheBaseClassDeclaresIt() {
            // given
            JavaClasses planted = importPlanted(BaseSpringBootTest.class);

            // when
            List<String> violations = violationsOf(TestStyleArchTest.onlyBaseClassesCarrySpringBootTest(), planted);

            // then
            assertThat(violations).isEmpty();
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static JavaClasses importPlanted(Class<?>... planted) {
        return new ClassFileImporter().importClasses(planted);
    }

    private static List<String> violationsOf(ArchRule rule, JavaClasses planted) {
        return rule.evaluate(planted).getFailureReport().getDetails();
    }

    // ── Planted samples ──────────────────────────────────────────────────────

    static class PlantedJunitAssertions {

        void checksSum() {
            Assertions.assertEquals(2, 1 + 1);
        }
    }

    static class PlantedJunit4Assertions {

        void checksSum() {
            Assert.assertEquals(2, 1 + 1);
        }
    }

    static class PlantedHamcrestAssertions {

        void checksSum() {
            MatcherAssert.assertThat(1 + 1, Matchers.is(2));
        }
    }

    static class PlantedRepeatedJunitAssertions {

        void checksSumAndProduct() {
            Assertions.assertEquals(2, 1 + 1);
            Assertions.assertEquals(1, 1 * 1);
        }
    }

    static class PlantedOverloadedJunitAssertions {

        void checksValue(int value) {
            Assertions.assertEquals(2, value);
        }

        void checksValue(String value) {
            Assertions.assertEquals("2", value);
        }
    }

    static class PlantedJunitAssertionInLambda {

        void checksLater() {
            Runnable check = () -> Assertions.assertTrue(true);
            check.run();
        }
    }

    static class PlantedAssertJAssertions {

        void checksSum() {
            assertThat(1 + 1).isEqualTo(2);
        }
    }

    abstract static class PlantedNarrowThrows {

        @Test
        abstract void readsFile() throws IOException;
    }

    abstract static class PlantedBroadThrows {

        @Test
        abstract void readsFile() throws Exception;

        @Test
        abstract void addsNumbers();
    }

    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    abstract static class PlantedGenericLifecycle {

        @BeforeAll
        abstract void init();

        @BeforeEach
        abstract void setUp();

        @AfterEach
        abstract void tearDown();

        @AfterAll
        abstract void teardown();
    }

    abstract static class PlantedNamedLifecycle {

        @BeforeEach
        abstract void createCertificate();

        @AfterEach
        abstract void stopMockServer();
    }

    abstract static class PlantedLegacyTestNames {

        @Test
        abstract void testSigning();

        @Test
        abstract void readsAgain_afterTheLoaderFailed_andKeepsTheOthers();

        @Test
        abstract void ReturnsPolicy();
    }

    abstract static class PlantedStyledTestNames {

        @Test
        abstract void returnsPolicy_whenRequestNamesOne();

        @Test
        abstract void throwsUnsupported();

        @Test
        abstract void asksAgain_afterTheLoaderFailed();

        @Test
        abstract void selectsV2_forCryptographyV2Interface();

        @ParameterizedTest
        abstract void testsConnection_whenUrlIsReachable();
    }

    abstract static class PlantedLegacyTestKinds {

        @ParameterizedTest
        abstract void testParameterized() throws IOException;

        @RepeatedTest(2)
        abstract void testRepeated() throws IOException;

        @TestFactory
        abstract List<DynamicTest> testFactory() throws IOException;

        @TestTemplate
        abstract void testTemplate() throws IOException;
    }

    static class PlantedNestedGroups {

        @Nested
        class Signing {
        }

        @Nested
        class SigningTests {
        }

        @Nested
        class Export {

            @Nested
            class Pinned {
            }
        }
    }

    static class PlantedOpenFixtures {
    }

    public static final class PlantedFixtures {

        private PlantedFixtures() {
        }
    }
}
