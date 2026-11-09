package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ObjectActionRequirements.OnAncestor;
import com.otilm.core.security.authz.ObjectActionRequirements.OnEachChild;
import com.otilm.core.security.authz.ObjectActionRequirements.OnLinked;
import com.otilm.core.security.authz.ObjectActionRequirements.OnLinkedThrough;
import com.otilm.core.security.authz.ObjectActionRequirements.OnObject;
import com.otilm.core.security.authz.ObjectActionRequirements.OnObjectUnder;
import com.otilm.core.security.authz.ObjectActionRequirements.OnResource;
import com.otilm.core.security.authz.ObjectActionRequirements.Requirement;
import com.otilm.core.security.authz.ObjectActionRequirements.ResourceObjects;
import com.otilm.core.security.authz.ObjectActionRequirements.WhenEmpty;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ObjectActionRequirementsTest {

    /** OID detail is addressed by the OID value, so no object of it is reported by UUID. */
    private static final Set<Resource> WITHOUT_OBJECTS_BY_UUID = Set.of(Resource.OID);

    private static final Map<Resource, ResourceObjects> TABLE = ObjectActionRequirements.all();

    @Test
    void coversResource_whenItsObjectsAreAuthorizedIndividually() {
        // given
        Set<Resource> individuallyAuthorized = Arrays
                .stream(Resource.values())
                .filter(resource -> resource.hasObjectAccess() || resource.hasOwner())
                .filter(resource -> !WITHOUT_OBJECTS_BY_UUID.contains(resource))
                .collect(Collectors.toSet());

        // when
        Set<Resource> tabled = TABLE.keySet();

        // then
        assertThat(tabled).containsExactlyInAnyOrderElementsOf(individuallyAuthorized);
    }

    @Test
    void reportsOnlyGrantableActions_whenTheyActOnAnExistingObject() {
        // given
        Set<ResourceAction> notOnAnExistingObject = Set
                .of(ResourceAction.CREATE, ResourceAction.LIST, ResourceAction.ANY);

        // when
        Map<Resource, Set<ResourceAction>> reported = reportedActions();

        // then
        reported
                .forEach((resource,
                        actions) -> assertThat(actions).as(resource.getCode()).isNotEmpty().allSatisfy(action -> {
                            assertThat(action.getAccessType()).isNotEqualTo(ResourceAction.AccessType.NOT_GRANTABLE);
                            assertThat(action).isNotIn(notOnAnExistingObject);
                        }));
    }

    @Test
    void reachesAncestor_whenARequirementNamesOne() {
        // given — the table as declared

        // when
        Map<Resource, Set<Resource>> ancestors = new EnumMap<>(Resource.class);
        TABLE
                .forEach((resource, objects) -> ancestors
                        .put(resource,
                                requirementsOf(objects)
                                        .filter(OnAncestor.class::isInstance)
                                        .map(requirement -> ((OnAncestor) requirement).ancestor())
                                        .collect(Collectors.toSet())));

        // then
        ancestors
                .forEach((resource, named) -> assertThat(chainOf(resource))
                        .as(resource.getCode() + " reaches its ancestors")
                        .containsAll(named));
    }

    @Test
    void namesParentAttribute_whenTheEntityHasIt() {
        // given — the table as declared

        // when
        Set<String> inconsistent = new TreeSet<>();
        TABLE.forEach((resource, objects) -> {
            if ((objects.parent() == Resource.NONE) != (objects.parentAttribute() == null)) {
                inconsistent.add(resource.getCode() + " parent without attribute");
            } else if (objects.parentAttribute() != null) {
                requireField(resource, objects.entity(), objects.parentAttribute(), inconsistent);
            }
        });

        // then
        assertThat(inconsistent).isEmpty();
    }

    @Test
    void namesLinkedAttribute_whenTheEntityItIsReadFromHasIt() {
        // given — the table as declared

        // when
        Set<String> missing = new TreeSet<>();
        TABLE
                .forEach((resource, objects) -> requirementsOf(objects)
                        .forEach(requirement -> collectMissingAttributes(resource, requirement, missing)));

        // then
        assertThat(missing).isEmpty();
    }

    @Test
    void admitsObjectToTheList_whenListOrAListUnderItsParentIsAllowed() {
        // given
        Set<ResourceAction> listedBy = Set.of(ResourceAction.LIST);

        // when
        Map<Resource, Set<ResourceAction>> listingActions = new EnumMap<>(Resource.class);
        TABLE
                .forEach((resource, objects) -> listingActions
                        .put(resource,
                                objects
                                        .listing()
                                        .stream()
                                        .map(ObjectActionRequirementsTest::ownAction)
                                        .flatMap(Optional::stream)
                                        .collect(Collectors.toSet())));

        // then
        listingActions.forEach((resource, actions) -> assertThat(actions).as(resource.getCode()).isEqualTo(listedBy));
    }

    @Test
    void requiresASubsetOfDetail_whenViewingAnObject() {
        // given — the table as declared

        // when
        Map<Resource, ResourceObjects> tabled = TABLE;

        // then
        tabled.forEach((resource, objects) -> {
            assertThat(objects.viewing()).as(resource.getCode()).isNotEmpty();
            assertThat(objects.actions().get(ResourceAction.DETAIL))
                    .as(resource.getCode())
                    .containsAll(objects.viewing());
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Map<Resource, Set<ResourceAction>> reportedActions() {
        Map<Resource, Set<ResourceAction>> reported = new EnumMap<>(Resource.class);
        TABLE.forEach((resource, objects) -> reported.put(resource, objects.actions().keySet()));
        return reported;
    }

    private static Stream<Requirement> requirementsOf(ResourceObjects objects) {
        return Stream
                .of(objects.listing().stream(), objects.viewing().stream(),
                        objects.actions().values().stream().flatMap(List::stream))
                .flatMap(requirements -> requirements);
    }

    private static Optional<ResourceAction> ownAction(Requirement requirement) {
        return switch (requirement) {
            case OnObject onObject -> Optional.of(onObject.action());
            case OnObjectUnder under -> Optional.of(under.action());
            case OnResource onResource ->
                Optional.ofNullable(onResource.resource() == null ? onResource.action() : null);
            default -> Optional.empty();
        };
    }

    private static void collectMissingAttributes(Resource resource, Requirement requirement, Set<String> missing) {
        Class<?> entity = TABLE.get(resource).entity();
        if (requirement instanceof OnLinked onLinked) {
            requireField(resource, entity, onLinked.attribute(), missing);
        } else if (requirement instanceof OnObjectUnder under) {
            requireField(resource, entity, under.parentAttribute(), missing);
        } else if (requirement instanceof OnLinkedThrough through) {
            requireField(resource, entity, through.attribute(), missing);
            collectMissingOnTabled(resource, through.through(), List.of(through.requirement()), missing);
        } else if (requirement instanceof WhenEmpty whenEmpty) {
            requireField(resource, entity, whenEmpty.attribute(), missing);
            collectMissingAttributes(resource, whenEmpty.requirement(), missing);
        } else if (requirement instanceof OnEachChild onEachChild) {
            collectMissingOnTabled(resource, onEachChild.child(), onEachChild.requirements(), missing);
            onEachChild.whenNone().forEach(whenNone -> collectMissingAttributes(resource, whenNone, missing));
            if (TABLE.containsKey(onEachChild.child())) {
                requireField(onEachChild.child(), TABLE.get(onEachChild.child()).entity(), onEachChild.childAttribute(),
                        missing);
            }
        }
    }

    private static void collectMissingOnTabled(Resource resource, Resource other, List<Requirement> requirements,
            Set<String> missing) {
        if (!TABLE.containsKey(other)) {
            missing.add(resource.getCode() + " through untabled " + other.getCode());
        } else {
            requirements.forEach(requirement -> collectMissingAttributes(other, requirement, missing));
        }
    }

    private static void requireField(Resource resource, Class<?> entity, String attribute, Set<String> missing) {
        if (!hasField(entity, attribute)) {
            missing.add(resource.getCode() + "." + attribute);
        }
    }

    private static Set<Resource> chainOf(Resource resource) {
        Set<Resource> chain = new LinkedHashSet<>();
        Resource current = TABLE.get(resource).parent();
        while (current != Resource.NONE && chain.add(current)) {
            current = TABLE.containsKey(current) ? TABLE.get(current).parent() : Resource.NONE;
        }
        return chain;
    }

    private static boolean hasField(Class<?> type, String name) {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            if (Arrays.stream(current.getDeclaredFields()).anyMatch(field -> field.getName().equals(name))) {
                return true;
            }
        }
        return false;
    }
}
