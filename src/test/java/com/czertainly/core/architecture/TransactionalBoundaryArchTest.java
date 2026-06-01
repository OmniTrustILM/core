package com.czertainly.core.architecture;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaCall;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.domain.JavaMethodCall;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.library.freeze.FreezingArchRule;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.repository.Repository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

/**
 * Enforces the transactional-boundary refactor invariants.
 *
 * <p><b>Rule A</b> — a method effectively annotated {@code @Transactional(propagation = NOT_SUPPORTED)}
 * (either at method level or inherited from its declaring class) must not call
 * {@code save/saveAll/saveAndFlush/delete/deleteAll/deleteAllInBatch/deleteInBatch/flush} on any {@code Repository}.
 * Such a call from a no-tx context either fails outright ({@code TransactionRequiredException}
 * for {@code @Modifying}) or silently loses the write (detached-entity save with no dirty checking).
 * Use a {@code *Writer} bean instead.</p>
 *
 * <p><b>Rule B</b> — no {@code @Transactional} on any class or method in {@code com.czertainly.core.dao.repository..}.
 * The transactional boundary lives on services, not repositories.</p>
 *
 * <p><b>Rule C</b> — only {@code *Writer} beans (production code residing in {@code ..service.writer..}) may invoke
 * a {@code @Modifying}-annotated repository method. Frozen via {@link FreezingArchRule} so pre-existing violations
 * can be resolved incrementally.</p>
 *
 * <p><b>Rule D</b> — all public methods in {@code @Service}-annotated classes in {@code ..service.writer..} must be
 * effectively {@code @Transactional} with propagation {@code REQUIRED} (the default). Combined with Rule C, this
 * statically guarantees that every {@code @Modifying} repository call site has an ambient transaction — for every
 * present and future method, without per-method integration tests.</p>
 */
@AnalyzeClasses(packages = "com.czertainly.core", importOptions = ImportOption.DoNotIncludeTests.class)
public class TransactionalBoundaryArchTest {

    private static final Set<String> FORBIDDEN_REPO_WRITE_METHODS = Set.of(
            "save", "saveAll", "saveAndFlush",
            "delete", "deleteAll", "deleteAllInBatch", "deleteInBatch",
            "flush"
    );

    private static final DescribedPredicate<JavaMethod> EFFECTIVELY_NOT_SUPPORTED =
            new DescribedPredicate<>("be effectively @Transactional(NOT_SUPPORTED)") {
                @Override
                public boolean test(JavaMethod method) {
                    return effectivePropagation(method) == Propagation.NOT_SUPPORTED;
                }
            };

    // ---- Rule A: no writes from NOT_SUPPORTED ----

    @ArchTest
    static final ArchRule no_repository_writes_from_not_supported_methods =
            noMethods()
                    .that(EFFECTIVELY_NOT_SUPPORTED)
                    .should(new ArchCondition<JavaMethod>("call a forbidden write method on a Repository") {
                        @Override
                        public void check(JavaMethod method, ConditionEvents events) {
                            for (JavaMethodCall call : method.getMethodCallsFromSelf()) {
                                JavaClass owner = call.getTargetOwner();
                                if (!owner.isAssignableTo(Repository.class)) continue;
                                if (FORBIDDEN_REPO_WRITE_METHODS.contains(call.getName())) {
                                    events.add(SimpleConditionEvent.violated(method,
                                            method.getFullName()
                                                    + " (effectively NOT_SUPPORTED) calls forbidden write '"
                                                    + call.getName() + "' on "
                                                    + owner.getSimpleName()
                                                    + " — use a *Writer bean instead"));
                                }
                            }
                        }
                    });

    // ---- Rule B: no @Transactional on repositories ----

    @ArchTest
    static final ArchRule no_transactional_on_repository_classes =
            noClasses()
                    .that().resideInAPackage("..dao.repository..")
                    .should().beAnnotatedWith(Transactional.class);

    @ArchTest
    static final ArchRule no_transactional_on_repository_methods =
            noMethods()
                    .that().areDeclaredInClassesThat().resideInAPackage("..dao.repository..")
                    .should().beAnnotatedWith(Transactional.class);

    // ---- Rule C: @Modifying repo methods only called from *Writer beans ----

    /**
     * Inverted form: iterate {@code @Modifying} methods directly and check that every caller resides in {@code ..service.writer..}.
     */
    @ArchTest
    static final ArchRule modifying_repo_methods_only_called_from_writer_beans =
            FreezingArchRule.freeze(
                    methods()
                            .that().areAnnotatedWith(Modifying.class)
                            .should(new ArchCondition<JavaMethod>("only be called from classes in ..service.writer..") {
                                @Override
                                public void check(JavaMethod method, ConditionEvents events) {
                                    for (JavaCall<?> call : method.getCallsOfSelf()) {
                                        JavaClass caller = call.getOriginOwner();
                                        if (caller.getPackageName().contains(".service.writer")) continue;
                                        events.add(SimpleConditionEvent.violated(call,
                                                caller.getName()
                                                        + " calls @Modifying "
                                                        + method.getOwner().getSimpleName() + "." + method.getName()
                                                        + "() from outside ..service.writer.."));
                                    }
                                }
                            }));

    // ---- Rule D: Writer service methods must carry @Transactional(REQUIRED) ----

    @ArchTest
    static final ArchRule writer_service_methods_must_be_transactional_required =
            methods()
                    .that().areDeclaredInClassesThat().resideInAPackage("..service.writer..")
                    .and().areDeclaredInClassesThat().areAnnotatedWith(Service.class)
                    .and().arePublic()
                    .should(new ArchCondition<JavaMethod>(
                            "be effectively @Transactional with REQUIRED propagation") {
                        @Override
                        public void check(JavaMethod method, ConditionEvents events) {
                            Propagation p = effectivePropagation(method);
                            if (p == null || p == Propagation.REQUIRED) return;
                            events.add(SimpleConditionEvent.violated(method,
                                    method.getFullName()
                                            + " is a Writer method with propagation "
                                            + p
                                            + " — Writer methods must use REQUIRED so @Modifying calls"
                                            + " have an ambient transaction (Rule D)"));
                        }
                    });

    private static Propagation effectivePropagation(JavaMethod method) {
        if (method.isAnnotatedWith(Transactional.class)) {
            return method.getAnnotationOfType(Transactional.class).propagation();
        }
        JavaClass clazz = method.getOwner();
        if (clazz.isAnnotatedWith(Transactional.class)) {
            return clazz.getAnnotationOfType(Transactional.class).propagation();
        }
        return null;
    }
}
