package com.otilm.core.architecture;

import com.otilm.core.auth.AuthEndpoint;
import com.otilm.core.service.ResourceExtensionService;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * A resource advertises object-level (per-object) permissions when a controller method carries
 * {@link AuthEndpoint}: {@code ContextRefreshListener} turns that into the resource's
 * {@code listObjectsEndpoint}, which the auth service exposes as {@code objectAccess=true}. The Role
 * permissions editor then calls {@code GET /api/v1/auth/resources/{resource}/objects}, which
 * {@code ResourceServiceImpl} serves by looking up a {@link ResourceExtensionService} bean keyed by the
 * resource code. A resource advertised via {@code @AuthEndpoint} but without a matching extension-service
 * bean fails that call with HTTP 501 (issue #1873, Signing Records and Trusted Certificates).
 *
 * <p>This rule fails the build when the two sets diverge, keeping the advertised-object-access contract and
 * the object-listing capability in lockstep.
 */
@AnalyzeClasses(packages = "com.otilm.core", importOptions = ImportOption.DoNotIncludeTests.class)
public class AuthEndpointResourceExtensionArchTest {

    @ArchTest
    static void every_auth_endpoint_resource_has_a_resource_extension_service(JavaClasses classes) {
        Set<String> advertised = new TreeSet<>();
        for (JavaClass clazz : classes) {
            for (JavaMethod method : clazz.getMethods()) {
                if (method.isAnnotatedWith(AuthEndpoint.class)) {
                    advertised.add(method.getAnnotationOfType(AuthEndpoint.class).resourceName().getCode());
                }
            }
        }

        Set<String> served = classes.stream()
                .filter(clazz -> !clazz.isInterface())
                .filter(clazz -> clazz.isAssignableTo(ResourceExtensionService.class))
                .filter(clazz -> clazz.isAnnotatedWith(Service.class))
                .map(clazz -> clazz.getAnnotationOfType(Service.class).value())
                .filter(beanName -> !beanName.isEmpty())
                .collect(Collectors.toCollection(TreeSet::new));

        List<String> missing = advertised.stream()
                .filter(code -> !served.contains(code))
                .toList();

        if (!missing.isEmpty()) {
            throw new AssertionError(
                    "Resources advertise object-level permissions via @AuthEndpoint but have no ResourceExtensionService "
                            + "bean to serve GET /api/v1/auth/resources/{resource}/objects (the call would fail with HTTP 501): "
                            + missing + ". Either register a @Service(<resource code>) bean implementing ResourceExtensionService, "
                            + "or remove @AuthEndpoint from the resource's controller if it must not expose per-object permissions.");
        }
    }
}
