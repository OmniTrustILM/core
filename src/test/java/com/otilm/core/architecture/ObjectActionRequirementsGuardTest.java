package com.otilm.core.architecture;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.ExternalAuthorizationDynamic;
import com.otilm.core.security.authz.ExternalAuthorizationProgrammatic;
import com.otilm.core.security.authz.ObjectActionRequirements;
import com.otilm.core.security.authz.ObjectActionRequirements.ResourceObjects;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.domain.JavaMethodCall;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.stereotype.Controller;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Keeps {@link ObjectActionRequirements} in step with the endpoints it describes. Every action the authorization
 * annotations declare on a tabled resource must be tabled or excluded, and a snapshot of how each method touching a
 * tabled resource is authorized fails on any change, so the entry it affects gets reviewed.
 */
class ObjectActionRequirementsGuardTest {

    private static final Path SNAPSHOT = Path.of("src/test/resources/authorization/object-action-requirements.txt");

    private static final String UPDATE_PROPERTY = "objectActionSnapshot.update";

    private static final Set<ResourceAction> NOT_ON_AN_OBJECT = Set
            .of(ResourceAction.NONE, ResourceAction.ANY, ResourceAction.CREATE, ResourceAction.LIST);

    /** Declared actions that do not act on an existing object of the resource, so the table leaves them out. */
    private static final Map<Resource, Set<ResourceAction>> EXCLUDED = Map
            .of(
                    // Members on attributes gates which attributes of a resource are listed, not one attribute.
                    Resource.ATTRIBUTE, Set.of(ResourceAction.MEMBERS),
                    // Register records a new certificate.
                    Resource.CERTIFICATE, Set.of(ResourceAction.REGISTER),
                    // Import creates a new key.
                    Resource.CRYPTOGRAPHIC_KEY, Set.of(ResourceAction.IMPORT_KEY));

    private static JavaClasses classes;

    @BeforeAll
    static void importClasses() {
        classes = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("com.otilm.core");
    }

    @Test
    void tablesOrExcludesEveryAction_whenItIsDeclaredOnATabledResource() {
        // given
        Map<Resource, Set<ResourceAction>> declared = declaredActions();

        // when
        Map<Resource, Set<ResourceAction>> untabled = untabledActions(declared);

        // then
        assertThat(untabled).as("actions declared on a tabled resource but neither tabled nor excluded").isEmpty();
    }

    @Test
    void tablesOnlyDeclaredActions_whenAResourceIsTabled() {
        // given
        Map<Resource, Set<ResourceAction>> declared = declaredActions();

        // when
        Map<Resource, Set<ResourceAction>> undeclared = undeclaredTabledActions(declared);

        // then
        assertThat(undeclared).as("actions tabled on a resource but declared by no annotation").isEmpty();
    }

    @Test
    void matchesTheSnapshot_whenAuthorizingMethodsThatTouchATabledResource() throws Exception {
        // given — the snapshot recorded at SNAPSHOT, rewritten first when -DobjectActionSnapshot.update=true

        // when
        String current = snapshot();

        // then
        assertThat(current)
                .as("""
                        The authorization of a method touching a tabled resource changed. Review the \
                        ObjectActionRequirements entry for it, then regenerate %s with -D%s=true.""", SNAPSHOT,
                        UPDATE_PROPERTY)
                .isEqualTo(recordedSnapshot(current));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static Map<Resource, Set<ResourceAction>> untabledActions(Map<Resource, Set<ResourceAction>> declared) {
        Map<Resource, Set<ResourceAction>> untabled = new EnumMap<>(Resource.class);
        tabled().forEach((resource, objects) -> {
            Set<ResourceAction> missing = new TreeSet<>(declared.getOrDefault(resource, Set.of()));
            missing.removeAll(NOT_ON_AN_OBJECT);
            missing.removeAll(EXCLUDED.getOrDefault(resource, Set.of()));
            missing.removeAll(objects.actions().keySet());
            if (!missing.isEmpty()) {
                untabled.put(resource, missing);
            }
        });
        return untabled;
    }

    private static Map<Resource, Set<ResourceAction>> undeclaredTabledActions(
            Map<Resource, Set<ResourceAction>> declared) {
        Map<Resource, Set<ResourceAction>> undeclared = new EnumMap<>(Resource.class);
        tabled().forEach((resource, objects) -> {
            Set<ResourceAction> extra = new TreeSet<>(objects.actions().keySet());
            extra.removeAll(declared.getOrDefault(resource, Set.of()));
            if (!extra.isEmpty()) {
                undeclared.put(resource, extra);
            }
        });
        return undeclared;
    }

    private static String recordedSnapshot(String current) throws IOException {
        if (Boolean.getBoolean(UPDATE_PROPERTY)) {
            Files.createDirectories(SNAPSHOT.getParent());
            Files.writeString(SNAPSHOT, current);
        }
        return Files.exists(SNAPSHOT) ? Files.readString(SNAPSHOT) : "";
    }

    private static Map<Resource, ResourceObjects> tabled() {
        Map<Resource, ResourceObjects> tabled = new EnumMap<>(Resource.class);
        for (Resource resource : Resource.values()) {
            ObjectActionRequirements.of(resource).ifPresent(objects -> tabled.put(resource, objects));
        }
        return tabled;
    }

    private static Map<Resource, Set<ResourceAction>> declaredActions() {
        Map<Resource, Set<ResourceAction>> declared = new EnumMap<>(Resource.class);
        for (JavaClass javaClass : classes) {
            for (JavaMethod method : javaClass.getMethods()) {
                method.tryGetAnnotationOfType(ExternalAuthorization.class).ifPresent(annotation -> {
                    declare(declared, annotation.resource(), annotation.action());
                    declare(declared, annotation.parentResource(), annotation.parentAction());
                });
                method.tryGetAnnotationOfType(ExternalAuthorizationProgrammatic.class).ifPresent(annotation -> {
                    declare(declared, annotation.resource(), annotation.action());
                    declare(declared, annotation.parentResource(), annotation.parentAction());
                });
            }
        }
        // Comment is authorized per host resource at runtime, as the auth-service sync registers it.
        Resource.getCommentableResources().forEach(resource -> declare(declared, resource, ResourceAction.COMMENT));
        return declared;
    }

    private static void declare(Map<Resource, Set<ResourceAction>> declared, Resource resource, ResourceAction action) {
        if (resource != Resource.NONE) {
            declared.computeIfAbsent(resource, key -> new TreeSet<>()).add(action);
        }
    }

    private static String snapshot() {
        Set<String> tabledCodes = tabled().keySet().stream().map(Resource::getCode).collect(Collectors.toSet());
        Set<String> tabledConstants = tabled().keySet().stream().map(Resource::name).collect(Collectors.toSet());
        Set<String> lines = new TreeSet<>();
        for (JavaClass javaClass : classes) {
            if (javaClass.isInterface() || javaClass.getPackageName().startsWith("com.otilm.core.security.authz")
                    || javaClass.isAnnotatedWith(Controller.class) || javaClass.isMetaAnnotatedWith(Controller.class)) {
                continue;
            }
            for (JavaMethod method : javaClass.getMethods()) {
                if (method.getModifiers().contains(JavaModifier.PRIVATE)
                        || method.getModifiers().contains(JavaModifier.SYNTHETIC)) {
                    continue;
                }
                String declaration = declaration(method);
                Set<String> checks = new TreeSet<>();
                Set<String> resources = new TreeSet<>();
                reach(method, checks, resources);
                boolean touchesTabled = tabledCodes.stream().anyMatch(declaration::contains)
                        || tabledCodes.stream().anyMatch(code -> checks.stream().anyMatch(c -> c.contains(code)))
                        || (resources.stream().anyMatch(tabledConstants::contains) && !checks.isEmpty());
                if (touchesTabled && (!declaration.equals("-") || !checks.isEmpty())) {
                    lines
                            .add("%s | %s.%s(%s) | checks %s | reads %s"
                                    .formatted(declaration, javaClass.getSimpleName(), method.getName(),
                                            method
                                                    .getRawParameterTypes()
                                                    .stream()
                                                    .map(JavaClass::getSimpleName)
                                                    .collect(Collectors.joining(", ")),
                                            checks, resources));
                }
            }
        }
        return String.join("\n", lines) + "\n";
    }

    /** Collects the checks a method reaches, following calls within its own class, which no proxy intercepts. */
    private static void reach(JavaMethod start, Set<String> checks, Set<String> resources) {
        Deque<JavaMethod> pending = new ArrayDeque<>(List.of(start));
        Set<JavaMethod> visited = new HashSet<>();
        while (!pending.isEmpty()) {
            JavaMethod method = pending.pop();
            if (!visited.add(method)) {
                continue;
            }
            method
                    .getFieldAccesses()
                    .stream()
                    .filter(access -> access.getTargetOwner().isEquivalentTo(Resource.class))
                    .forEach(access -> resources.add(access.getTarget().getName()));
            for (JavaMethodCall call : method.getMethodCallsFromSelf()) {
                JavaClass owner = call.getTargetOwner();
                String name = call.getTarget().getName();
                if (owner.isEquivalentTo(AuthorizationEnforcer.class)) {
                    checks.add("enforcer." + name);
                } else if (owner.equals(start.getOwner())) {
                    call.getTarget().resolveMember().ifPresent(pending::push);
                } else {
                    annotatedImplementation(call)
                            .ifPresent(annotation -> checks.add(owner.getSimpleName() + "." + name + " " + annotation));
                }
            }
        }
    }

    private static Optional<String> annotatedImplementation(JavaMethodCall call) {
        List<String> parameters = call.getTarget().getRawParameterTypes().stream().map(JavaClass::getName).toList();
        Set<JavaClass> candidates = new HashSet<>(call.getTargetOwner().getAllSubclasses());
        candidates.add(call.getTargetOwner());
        return candidates
                .stream()
                .flatMap(candidate -> candidate.getMethods().stream())
                .filter(method -> method.getName().equals(call.getTarget().getName())
                        && method.getRawParameterTypes().stream().map(JavaClass::getName).toList().equals(parameters))
                .map(ObjectActionRequirementsGuardTest::declaration)
                .filter(declaration -> !declaration.equals("-"))
                .sorted()
                .findFirst();
    }

    private static String declaration(JavaMethod method) {
        Optional<ExternalAuthorization> annotation = method.tryGetAnnotationOfType(ExternalAuthorization.class);
        if (annotation.isPresent()) {
            return pair(annotation.get().resource(), annotation.get().action(), annotation.get().parentResource(),
                    annotation.get().parentAction());
        }
        Optional<ExternalAuthorizationProgrammatic> programmatic = method
                .tryGetAnnotationOfType(ExternalAuthorizationProgrammatic.class);
        if (programmatic.isPresent()) {
            return "programmatic " + pair(programmatic.get().resource(), programmatic.get().action(),
                    programmatic.get().parentResource(), programmatic.get().parentAction());
        }
        return method
                .tryGetAnnotationOfType(ExternalAuthorizationDynamic.class)
                .map(dynamic -> "dynamic " + dynamic.action().getCode())
                .orElse("-");
    }

    private static String pair(Resource resource, ResourceAction action, Resource parent, ResourceAction parentAction) {
        String pair = resource.getCode() + ":" + action.getCode();
        return parent == Resource.NONE ? pair : pair + " under " + parent.getCode() + ":" + parentAction.getCode();
    }
}
