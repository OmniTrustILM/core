package com.czertainly.core.architecture;

import com.czertainly.api.exception.PlatformException;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Structural safety rules for exception message handling.
 * <p>
 * Rule 1: All concrete Throwable subclasses in com.czertainly.core must implement PlatformException so safeMessage()
 * can gate message exposure at wire boundaries. A similar rule is enforced for exceptions declared in interfaces.
 * com.czertainly.core.intune is excluded: those exceptions wrap third-party Microsoft API responses whose messages
 * are not safe to expose via safeMessage().
 * <p>
 * Rule 2: BulkActionMessageDto must be created via BulkActionMessageDto.failure() factory methods so message content
 * can be controlled.
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
                    .should().callConstructor(BulkActionMessageDto.class, String.class, String.class, String.class)
                    .because("BulkActionMessageDto must be created via BulkActionMessageDto.failure() " +
                            "so message content is controlled at the factory level; " +
                            "direct constructor calls bypass that gate");
}
