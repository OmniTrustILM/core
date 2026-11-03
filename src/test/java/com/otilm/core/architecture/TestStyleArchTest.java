package com.otilm.core.architecture;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.Dependency;
import com.tngtech.archunit.core.domain.JavaAccess;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaCodeUnit;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.core.importer.Location;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.lang.conditions.ArchConditions;
import com.tngtech.archunit.library.freeze.FreezingArchRule;
import jakarta.persistence.EntityManager;
import java.lang.annotation.Annotation;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.params.ParameterizedTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.repository.Repository;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;

/**
 * Checks tests against the mechanical part of {@code .claude/rules/test-style.md} and {@code test-support.md}. Each
 * rule is frozen, so a departure recorded in {@code archunit_store} passes.
 */
@AnalyzeClasses(packages = "com.otilm.core",
        importOptions = {ImportOption.OnlyIncludeTests.class, TestStyleArchTest.WithoutPlantedDepartures.class})
public class TestStyleArchTest {

    private static final String TEST_STYLE = "the test style in .claude/rules/test-style.md asks for it";
    private static final String SUPPORT_STYLE = "the support-class style in .claude/rules/test-support.md asks for it";

    private static final Pattern VERB_OUTCOME_WHEN_CONDITION = Pattern
            .compile("(?!test(?:[A-Z0-9_]|$))[a-z][a-zA-Z0-9]*(?:_when[A-Z0-9][a-zA-Z0-9]*)?");
    private static final String GENERIC_LIFECYCLE_NAME = "setUp|setup|init|tearDown|teardown";
    private static final List<String> ASSERTION_LIBRARY_PREFIXES = List
            .of("org.junit.jupiter.api.Assertions", "org.junit.Assert", "org.hamcrest.");
    private static final Pattern LAMBDA_BODY = Pattern.compile("lambda\\$(.+)\\$\\d+");

    private static final DescribedPredicate<JavaMethod> TEST_METHODS = annotatedWithAnyOf("are JUnit test methods",
            List.of(Test.class, ParameterizedTest.class, RepeatedTest.class, TestFactory.class, TestTemplate.class));
    private static final DescribedPredicate<JavaMethod> LIFECYCLE_METHODS = annotatedWithAnyOf(
            "are JUnit lifecycle methods", List.of(BeforeEach.class, AfterEach.class, BeforeAll.class, AfterAll.class));

    @ArchTest
    static final ArchRule no_junit_or_hamcrest_assertions = FreezingArchRule.freeze(noJunitOrHamcrestAssertions());

    @ArchTest
    static final ArchRule test_methods_throw_nothing_or_exception = FreezingArchRule
            .freeze(testMethodsThrowNothingOrException());

    @ArchTest
    static final ArchRule lifecycle_methods_are_named_for_what_they_arrange = FreezingArchRule
            .freeze(lifecycleMethodsAreNamedForWhatTheyArrange());

    @ArchTest
    static final ArchRule test_methods_follow_verb_outcome_when_condition = FreezingArchRule
            .freeze(testMethodsFollowVerbOutcomeWhenCondition());

    @ArchTest
    static final ArchRule nested_classes_are_one_level_deep_without_test_suffix = FreezingArchRule
            .freeze(nestedClassesAreOneLevelDeepWithoutTestSuffix());

    @ArchTest
    static final ArchRule builders_are_public_final_and_in_memory = FreezingArchRule
            .freeze(buildersArePublicFinalAndInMemory());

    @ArchTest
    static final ArchRule fixtures_are_public_final_with_private_constructors = FreezingArchRule
            .freeze(fixturesArePublicFinalWithPrivateConstructors());

    @ArchTest
    static final ArchRule only_base_classes_carry_spring_boot_test = FreezingArchRule
            .freeze(onlyBaseClassesCarrySpringBootTest());

    // TestStyleArchSelfTest evaluates these unfrozen rules against planted departures.

    static ArchRule noJunitOrHamcrestAssertions() {
        return classes().should(callNoJunitOrHamcrestAssertions()).because(TEST_STYLE);
    }

    static ArchRule testMethodsThrowNothingOrException() {
        return methods().that(TEST_METHODS).should(throwNothingOrException()).because(TEST_STYLE);
    }

    static ArchRule lifecycleMethodsAreNamedForWhatTheyArrange() {
        return methods()
                .that(LIFECYCLE_METHODS)
                .should()
                .haveNameNotMatching(GENERIC_LIFECYCLE_NAME)
                .because(TEST_STYLE);
    }

    static ArchRule testMethodsFollowVerbOutcomeWhenCondition() {
        return methods().that(TEST_METHODS).should(beNamedVerbOutcomeWhenCondition()).because(TEST_STYLE);
    }

    static ArchRule nestedClassesAreOneLevelDeepWithoutTestSuffix() {
        return classes()
                .that()
                .areAnnotatedWith(Nested.class)
                .should(notBeNestedInAnotherNestedClass())
                .andShould()
                .haveNameNotMatching(".*Tests?")
                .because(TEST_STYLE);
    }

    static ArchRule buildersArePublicFinalAndInMemory() {
        return classes()
                .that()
                .areTopLevelClasses()
                .and()
                .haveSimpleNameEndingWith("Builder")
                .should()
                .bePublic()
                .andShould()
                .haveModifier(JavaModifier.FINAL)
                .andShould(notDependOnPersistence())
                .because(SUPPORT_STYLE);
    }

    static ArchRule fixturesArePublicFinalWithPrivateConstructors() {
        return classes()
                .that()
                .haveSimpleNameEndingWith("Fixtures")
                .should()
                .bePublic()
                .andShould()
                .haveModifier(JavaModifier.FINAL)
                .andShould()
                .haveOnlyPrivateConstructors()
                .because(SUPPORT_STYLE);
    }

    static ArchRule onlyBaseClassesCarrySpringBootTest() {
        return classes()
                .that()
                .areAnnotatedWith(SpringBootTest.class)
                .should(ArchConditions
                        .be(DescribedPredicate
                                .describe("a context-bearing base class",
                                        testClass -> TestClassTaxonomy
                                                .contextBearingRoots()
                                                .contains(testClass.getSimpleName()))))
                .because(TEST_STYLE);
    }

    /**
     * Reports each method once, and a lambda as the method it was written in. The store then counts methods to restyle.
     */
    private static ArchCondition<JavaClass> callNoJunitOrHamcrestAssertions() {
        return new ArchCondition<>("call no JUnit or Hamcrest assertions") {
            @Override
            public void check(JavaClass testClass, ConditionEvents events) {
                Map<String, JavaAccess<?>> firstAssertionByMethod = new TreeMap<>();
                testClass
                        .getCodeUnits()
                        .stream()
                        .flatMap(codeUnit -> codeUnit.getAccessesFromSelf().stream())
                        .filter(access -> isAssertionLibrary(access.getTargetOwner()))
                        .sorted(Comparator.comparingInt(JavaAccess::getLineNumber))
                        .forEach(access -> firstAssertionByMethod.putIfAbsent(writtenIn(access.getOrigin()), access));
                firstAssertionByMethod
                        .forEach((method, access) -> events
                                .add(SimpleConditionEvent
                                        .violated(testClass,
                                                "Method <%s.%s> calls JUnit or Hamcrest assertions in %s"
                                                        .formatted(testClass.getName(), method,
                                                                access.getSourceCodeLocation()))));
            }
        };
    }

    private static boolean isAssertionLibrary(JavaClass owner) {
        return ASSERTION_LIBRARY_PREFIXES.stream().anyMatch(owner.getName()::startsWith);
    }

    private static String writtenIn(JavaCodeUnit codeUnit) {
        Matcher lambda = LAMBDA_BODY.matcher(codeUnit.getName());
        return lambda.matches() ? lambda.group(1) : codeUnit.getName();
    }

    private static ArchCondition<JavaMethod> throwNothingOrException() {
        return new ArchCondition<>("declare no throws clause or throws Exception alone") {
            @Override
            public void check(JavaMethod method, ConditionEvents events) {
                List<JavaClass> thrown = method.getThrowsClause().getTypes();
                if (!thrown.isEmpty() && !(thrown.size() == 1 && thrown.get(0).isEquivalentTo(Exception.class))) {
                    events
                            .add(SimpleConditionEvent
                                    .violated(method, "%s declares a throws clause other than Exception in %s"
                                            .formatted(method.getDescription(), method.getSourceCodeLocation())));
                }
            }
        };
    }

    private static ArchCondition<JavaMethod> beNamedVerbOutcomeWhenCondition() {
        return new ArchCondition<>("be named verb_outcome_whenCondition") {
            @Override
            public void check(JavaMethod method, ConditionEvents events) {
                if (!VERB_OUTCOME_WHEN_CONDITION.matcher(method.getName()).matches()) {
                    events
                            .add(SimpleConditionEvent
                                    .violated(method, "%s is not named verb_outcome_whenCondition in %s"
                                            .formatted(method.getDescription(), method.getSourceCodeLocation())));
                }
            }
        };
    }

    private static ArchCondition<JavaClass> notBeNestedInAnotherNestedClass() {
        return new ArchCondition<>("not be nested in another @Nested class") {
            @Override
            public void check(JavaClass nestedClass, ConditionEvents events) {
                if (nestedClass.getEnclosingClass().filter(outer -> outer.isAnnotatedWith(Nested.class)).isPresent()) {
                    events
                            .add(SimpleConditionEvent
                                    .violated(nestedClass,
                                            "%s is nested in another @Nested class in %s"
                                                    .formatted(nestedClass.getDescription(),
                                                            nestedClass.getSourceCodeLocation())));
                }
            }
        };
    }

    private static ArchCondition<JavaClass> notDependOnPersistence() {
        return new ArchCondition<>("not depend on a Repository or an EntityManager") {
            @Override
            public void check(JavaClass builder, ConditionEvents events) {
                boolean persists = builder
                        .getDirectDependenciesFromSelf()
                        .stream()
                        .map(Dependency::getTargetClass)
                        .anyMatch(target -> target.isAssignableTo(Repository.class)
                                || target.isAssignableTo(EntityManager.class));
                if (persists) {
                    events
                            .add(SimpleConditionEvent
                                    .violated(builder, "%s depends on a Repository or an EntityManager in %s"
                                            .formatted(builder.getDescription(), builder.getSourceCodeLocation())));
                }
            }
        };
    }

    private static DescribedPredicate<JavaMethod> annotatedWithAnyOf(String description,
            List<Class<? extends Annotation>> annotations) {
        return DescribedPredicate
                .describe(description, method -> annotations.stream().anyMatch(method::isAnnotatedWith));
    }

    /** Leaves out the departures planted for {@link TestStyleArchSelfTest}. */
    public static final class WithoutPlantedDepartures implements ImportOption {

        private static final Pattern PLANTED = Pattern
                .compile(".*/com/otilm/core/architecture/(TestStyleArchSelfTest\\$)?Planted.*");

        @Override
        public boolean includes(Location location) {
            return !location.matches(PLANTED);
        }
    }
}
