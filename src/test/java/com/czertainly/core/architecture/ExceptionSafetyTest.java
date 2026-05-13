package com.czertainly.core.architecture;

import com.czertainly.api.exception.PlatformException;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaMethodCall;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.library.freeze.FreezingArchRule;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Structural safety rules for exception message handling.
 * <p>
 * Rule 1: All concrete Throwable subclasses in com.czertainly.core must implement PlatformException so safeMessage()
 * can gate message exposure at wire boundaries. A similar rule is enforced for exceptions declared in interfaces.
 * <p>
 * Rule 2: No @RestControllerAdvice class may call Throwable.getMessage() or getCause() — use PlatformException.safeMessage()
 * instead, log the cause via the Throwable itself.
 * <p>
 * Rule 3 (frozen): No production class in com.czertainly.core may call Throwable.getMessage() anywhere. Existing violations
 * are frozen in archunit/; only net-new calls fail the build. Fix frozen violations incrementally; when the store
 * is empty, this rule can become a plain @ArchTest.
 */
@AnalyzeClasses(packages = "com.czertainly.core")
class ExceptionSafetyTest {

    @ArchTest
    static final ArchRule coreExceptionsMustImplementPlatformException =
            classes()
                    .that().resideInAPackage("com.czertainly.core..")
                    .and().haveSimpleNameEndingWith("Exception")
                    .and().areNotInterfaces()
                    .and().doNotHaveModifier(JavaModifier.ABSTRACT)
                    .should().implement(PlatformException.class)
                    .because("all platform exceptions must implement PlatformException " +
                            "so safeMessage() can gate message exposure at wire boundaries");

    /**
     * Matches any call to getMessage() where the receiver's static type is Throwable or a subtype.
     * ArchUnit's callMethod(Throwable.class, "getMessage") only matches calls where the bytecode
     * owner is literally Throwable (i.e. getCause().getMessage() chains). This predicate catches
     * all getMessage() calls on typed exception parameters too.
     */
    private static final DescribedPredicate<JavaMethodCall> GET_MESSAGE_ON_THROWABLE =
            new DescribedPredicate<>("calls getMessage() on a Throwable or subtype") {
                @Override
                public boolean test(JavaMethodCall call) {
                    if (!"getMessage".equals(call.getTarget().getName())) {
                        return false;
                    }
                    if (!call.getTarget().getRawParameterTypes().isEmpty()) {
                        return false;
                    }
                    try {
                        Class<?> owner = Class.forName(call.getTarget().getOwner().getName(),
                                false, Thread.currentThread().getContextClassLoader());
                        return Throwable.class.isAssignableFrom(owner);
                    } catch (ClassNotFoundException e) {
                        return false;
                    }
                }
            };

    @ArchTest
    static final ArchRule noRawGetMessageInRestAdvice =
            noClasses()
                    .that().areAnnotatedWith(RestControllerAdvice.class)
                    .should().callMethodWhere(GET_MESSAGE_ON_THROWABLE)
                    .because("exception messages must be gated through " +
                            "PlatformException.safeMessage() before reaching HTTP responses");

    /**
     * Blanket freeze: no net-new Throwable.getMessage() calls anywhere in core.
     * Existing violations are stored in archunit/ and must shrink over time.
     * When the store file is empty (all violations fixed), replace @Test + FreezingArchRule with a plain @ArchTest on the rule.
     */
    @Test
    void noRawGetMessageAnywhere_frozenBaseline() {
        JavaClasses classes = new ClassFileImporter().importPackages("com.czertainly.core");
        ArchRule blanket = noClasses()
                .that().resideInAPackage("com.czertainly.core..")
                .should().callMethod(Throwable.class, "getMessage")
                .because("use PlatformException.safeMessage() at wire boundaries; " +
                        "pass the Throwable object itself to loggers");
        FreezingArchRule.freeze(blanket).check(classes);
    }
}
