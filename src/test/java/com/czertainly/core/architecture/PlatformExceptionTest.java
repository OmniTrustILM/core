package com.czertainly.core.architecture;

import com.czertainly.api.exception.PlatformException;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.core.intune.scepvalidation.IntuneClientException;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaCall;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.conditions.ArchConditions.callCodeUnitWhere;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

/**
 * Structural safety rules for exception message handling.
 * <p>
 * Rule 1: All concrete Throwable subclasses in com.czertainly.core must implement PlatformException so safeMessage()
 * can gate message exposure at wire boundaries. PlatformException is the "controlled domain-exception type" gate:
 * its getMessage() is shaped by us and therefore safe to expose, whereas raw Exception.getMessage() can carry SQL
 * fragments, stack-frame class names, or upstream vendor payloads that must never reach the wire.
 * com.czertainly.core.intune is excluded: these are vendor-forked Microsoft exception classes whose getMessage()
 * embeds uncontrolled upstream payloads — raw HTTP response bodies, SCEP activity/transaction IDs, and Microsoft
 * Graph service names — not shaped by us and therefore never safe to expose at the wire. Code outside this package
 * must not propagate them in method signatures; Rule 3 enforces that boundary.
 * <p>
 * Rule 2: BulkActionMessageDto must be created via BulkActionMessageDto.failure() factory methods so message content
 * can be controlled.
 * <p>
 * Rule 3: No method outside com.czertainly.core.intune may declare throws of IntuneClientException (or any subclass),
 * preventing uncontrolled upstream payloads from escaping the intune package boundary via method signatures.
 */
@AnalyzeClasses(packages = "com.czertainly.core", importOptions = ImportOption.DoNotIncludeTests.class)
class PlatformExceptionTest {

    @ArchTest
    static final ArchRule coreExceptionsMustImplementPlatformException =
            classes()
                    .that().resideInAPackage("com.czertainly.core..")
                    .and().resideOutsideOfPackage("com.czertainly.core.intune..")
                    .and().areAssignableTo(Throwable.class)
                    .and().areNotInterfaces()
                    .and().doNotHaveModifier(JavaModifier.ABSTRACT)
                    .should().implement(PlatformException.class)
                    .because("all platform exceptions must implement PlatformException " +
                            "so safeMessage() can gate message exposure at wire boundaries");

    @ArchTest
    static final ArchRule bulkActionMessageDtoMustUseFactory =
            noClasses()
                    .that().resideInAPackage("com.czertainly.core..")
                    .should(callCodeUnitWhere(DescribedPredicate.describe(
                            "call a constructor of BulkActionMessageDto",
                            (JavaCall<?> call) -> BulkActionMessageDto.class.getName().equals(
                                    call.getTarget().getOwner().getName())
                                    && "<init>".equals(call.getTarget().getName()))))
                    .because("BulkActionMessageDto must be created via BulkActionMessageDto.failure() " +
                            "so message content is controlled at the factory level; " +
                            "direct constructor calls bypass that gate");

    @ArchTest
    static final ArchRule intuneExceptionsMustNotEscapePackageSignatures =
            noMethods()
                    .that().areDeclaredInClassesThat().resideOutsideOfPackage("com.czertainly.core.intune..")
                    .should().declareThrowableOfType(IntuneClientException.class)
                    .because("IntuneClientException and its subclasses carry uncontrolled upstream payloads " +
                            "(raw HTTP response bodies, SCEP activity/transaction IDs, Microsoft Graph service names) " +
                            "not shaped by us; they must be caught and wrapped in a PlatformException with a " +
                            "controlled message before any wire-boundary exposure");
}
