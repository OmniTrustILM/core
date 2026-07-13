package com.otilm.core.architecture;

import com.otilm.core.security.authz.AnyPrincipalEndpoint;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.ExternalAuthorizationDynamic;
import com.otilm.core.security.authz.ExternalAuthorizationMissing;
import com.otilm.core.security.authz.ExternalAuthorizationProgrammatic;
import com.otilm.core.security.authz.ProtocolEndpoint;
import com.otilm.core.security.authz.SelfPrincipalEndpoint;
import com.otilm.core.security.authz.UnauthenticatedEndpoint;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.library.freeze.FreezingArchRule;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import org.springframework.stereotype.Controller;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

@AnalyzeClasses(packages = "com.otilm.core", importOptions = ImportOption.DoNotIncludeTests.class)
public class ExternalServiceAuthorizationArchTest {

    private static final Set<String> AUTH_ANNOTATION_NAMES = Set.of(
            AnyPrincipalEndpoint.class.getName(),
            ExternalAuthorization.class.getName(),
            ExternalAuthorizationDynamic.class.getName(),
            ExternalAuthorizationMissing.class.getName(),
            ExternalAuthorizationProgrammatic.class.getName(),
            ProtocolEndpoint.class.getName(),
            SelfPrincipalEndpoint.class.getName(),
            UnauthenticatedEndpoint.class.getName()
    );

    private static final DescribedPredicate<JavaClass> IMPLEMENTS_EXTERNAL_SERVICE =
            new DescribedPredicate<>("implement an *ExternalService interface") {
                @Override
                public boolean test(JavaClass javaClass) {
                    return !javaClass.isInterface() &&
                            javaClass.getAllRawInterfaces().stream()
                                    .anyMatch(ifc -> ifc.getSimpleName().endsWith("ExternalService"));
                }
            };

    private static final DescribedPredicate<JavaClass> ARE_CONTROLLERS =
            new DescribedPredicate<>("controllers") {
                @Override
                public boolean test(JavaClass javaClass) {
                    return !javaClass.isInterface()
                            && (javaClass.isAnnotatedWith(Controller.class) || javaClass.isMetaAnnotatedWith(Controller.class));
                }
            };

    private static boolean isNonExternalCoreServiceType(JavaClass target) {
        String packageName = target.getPackageName();
        boolean inCore = packageName.equals("com.otilm.core") || packageName.startsWith("com.otilm.core.");
        if (!inCore) {
            return false;
        }
        String simpleName = target.getSimpleName();
        return (simpleName.endsWith("Service") || simpleName.endsWith("ServiceImpl"))
                && !simpleName.endsWith("ExternalService");
    }

    @ArchTest
    static final ArchRule external_service_interfaces_must_not_extend_other_interfaces =
            classes()
                    .that().haveSimpleNameEndingWith("ExternalService")
                    .and().areInterfaces()
                    .should(new ArchCondition<>("not extend other interfaces") {
                        @Override
                        public void check(JavaClass javaClass, ConditionEvents events) {
                            if (!javaClass.getRawInterfaces().isEmpty()) {
                                events.add(SimpleConditionEvent.violated(javaClass,
                                        javaClass.getName() + " extends other interfaces; *ExternalService interfaces must be flat so the auth-annotation rule covers all callable methods"));
                            }
                        }
                    });

    @ArchTest
    static final ArchRule every_external_service_method_has_exactly_one_auth_annotation =
            classes()
                    .that(IMPLEMENTS_EXTERNAL_SERVICE)
                    .should(new ArchCondition<>("have exactly one authorization annotation on each method implementing an *ExternalService interface method") {
                        @Override
                        public void check(JavaClass implClass, ConditionEvents events) {
                            implClass.getAllRawInterfaces().stream()
                                    .filter(ifc -> ifc.getSimpleName().endsWith("ExternalService"))
                                    .flatMap(ifc -> ifc.getMethods().stream())
                                    .forEach(ifcMethod -> findImplMethod(implClass, ifcMethod)
                                            .ifPresentOrElse(
                                                    implMethod -> checkAnnotationCount(implMethod, events),
                                                    () -> events.add(SimpleConditionEvent.violated(implClass,
                                                            implClass.getName() + " has no method implementing " + ifcMethod.getFullName()))
                                            ));
                        }

                        private Optional<JavaMethod> findImplMethod(JavaClass implClass, JavaMethod ifcMethod) {
                            List<String> ifcParamTypes = paramTypeNames(ifcMethod);
                            return implClass.getMethods().stream()
                                    .filter(m -> m.getName().equals(ifcMethod.getName())
                                            && paramTypeNames(m).equals(ifcParamTypes))
                                    .findFirst();
                        }

                        private List<String> paramTypeNames(JavaMethod m) {
                            return m.getRawParameterTypes().stream()
                                    .map(JavaClass::getName)
                                    .toList();
                        }

                        private void checkAnnotationCount(JavaMethod method, ConditionEvents events) {
                            long count = method.getAnnotations().stream()
                                    .filter(a -> AUTH_ANNOTATION_NAMES.contains(a.getType().getName()))
                                    .count();
                            if (count != 1) {
                                events.add(SimpleConditionEvent.violated(method, String.format(
                                        "%s has %d authorization annotations (expected exactly 1)",
                                        method.getFullName(), count)));
                            }
                        }
                    });

    /**
     * Ratchet: no method on an *ExternalService implementation may carry @ExternalAuthorizationMissing
     * beyond the set frozen at the time this rule was last updated. The store in
     * src/test/resources/archunit_store/ records outstanding violations by method name.
     * When a violation is resolved the store auto-shrinks on the next run; new violations fail
     * the build immediately.
     */
    @ArchTest
    static final ArchRule no_new_external_authorization_missing =
            FreezingArchRule.freeze(
                    noMethods()
                            .that().areDeclaredInClassesThat(IMPLEMENTS_EXTERNAL_SERVICE)
                            .should().beAnnotatedWith(ExternalAuthorizationMissing.class));

    /**
     * A {@code @ExternalAuthorizationProgrammatic} method declares the resource/action pair for the auth-service
     * sync but enforces imperatively, by calling {@link AuthorizationEnforcer#enforce} in its body. If that call
     * is dropped, the action stays registered with the auth service while no longer being enforced — a silent
     * authorization gap. This rule fails the build when such a method has no call to {@code enforce}. It does not
     * check that the call's arguments match the declared pair; keeping them in sync remains a code-review concern.
     */
    @ArchTest
    static final ArchRule programmatic_auth_methods_must_call_enforce =
            methods()
                    .that().areAnnotatedWith(ExternalAuthorizationProgrammatic.class)
                    .should(new ArchCondition<>("call AuthorizationEnforcer.enforce in their body") {
                        @Override
                        public void check(JavaMethod method, ConditionEvents events) {
                            boolean callsEnforce = method.getMethodCallsFromSelf().stream()
                                    .anyMatch(call -> "enforce".equals(call.getTarget().getName())
                                            && call.getTarget().getOwner().isAssignableTo(AuthorizationEnforcer.class));
                            if (!callsEnforce) {
                                events.add(SimpleConditionEvent.violated(method, String.format(
                                        "%s is annotated @ExternalAuthorizationProgrammatic but does not call AuthorizationEnforcer.enforce; "
                                                + "the action stays registered with the auth service while no longer being enforced",
                                        method.getFullName())));
                            }
                        }
                    });

    /**
     * A controller may reach a service only through its {@code *ExternalService} interface.
     * Injecting a bare {@code *Service}, an {@code *InternalService}, or a concrete {@code *ServiceImpl} would let a controller
     * call a service method that has not been annotated with an authorization annotation.
     */
    @ArchTest
    static final ArchRule controllers_depend_only_on_external_service_interfaces =
            classes()
                    .that(ARE_CONTROLLERS)
                    .should(new ArchCondition<>("depend on core service types only through their *ExternalService interface") {
                        @Override
                        public void check(JavaClass controller, ConditionEvents events) {
                            controller.getDirectDependenciesFromSelf().stream()
                                    .filter(dependency -> isNonExternalCoreServiceType(dependency.getTargetClass()))
                                    .forEach(dependency -> events.add(SimpleConditionEvent.violated(controller, String.format(
                                            "%s depends on %s; a controller may reach a service only through its *ExternalService interface. "
                                                    + "Expose the needed method on the service's *ExternalService interface with exactly one "
                                                    + "authorization annotation (use @ExternalAuthorizationMissing if the posture is undetermined), "
                                                    + "and inject that interface.",
                                            controller.getName(), dependency.getTargetClass().getName()))));
                        }
                    });

    @ArchTest
    static void each_external_service_is_implemented_by_exactly_one_class(JavaClasses classes) {
        Map<String, List<JavaClass>> implementors = new TreeMap<>();

        for (JavaClass clazz : classes) {
            if (clazz.isInterface() && clazz.getSimpleName().endsWith("ExternalService")) {
                implementors.put(clazz.getName(), new ArrayList<>());
            }
        }

        for (JavaClass clazz : classes) {
            if (!clazz.isInterface()) {
                clazz.getAllRawInterfaces().stream()
                        .filter(ifc -> implementors.containsKey(ifc.getName()))
                        .forEach(ifc -> implementors.get(ifc.getName()).add(clazz));
            }
        }

        List<String> violations = implementors.entrySet().stream()
                .filter(e -> e.getValue().size() != 1)
                .map(e -> String.format("%s has %d implementations (expected 1): [%s]",
                        e.getKey(), e.getValue().size(),
                        e.getValue().stream().map(JavaClass::getName).collect(Collectors.joining(", "))))
                .toList();

        if (!violations.isEmpty()) {
            throw new AssertionError("Each *ExternalService must have exactly one implementation:\n"
                    + String.join("\n", violations));
        }
    }
}
