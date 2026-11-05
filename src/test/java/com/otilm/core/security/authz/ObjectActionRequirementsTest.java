package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ObjectActionRequirements.OnAncestor;
import com.otilm.core.security.authz.ObjectActionRequirements.ResourceObjects;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ObjectActionRequirementsTest {

    /** OID detail is addressed by the OID value, so no object of it is reported by UUID. */
    private static final Set<Resource> WITHOUT_OBJECTS_BY_UUID = Set.of(Resource.OID);

    private static final Map<Resource, ResourceObjects> TABLE = ObjectActionRequirements.all();

    @Test
    void coversEveryResourceWhoseObjectsAreAuthorizedIndividually() {
        Set<Resource> expected = Arrays
                .stream(Resource.values())
                .filter(resource -> resource.hasObjectAccess() || resource.hasOwner())
                .filter(resource -> !WITHOUT_OBJECTS_BY_UUID.contains(resource))
                .collect(Collectors.toSet());

        assertThat(TABLE.keySet()).containsExactlyInAnyOrderElementsOf(expected);
    }

    @Test
    void reportsOnlyGrantableActionsThatActOnAnExistingObject() {
        TABLE
                .forEach((resource, objects) -> assertThat(objects.actions().keySet())
                        .as(resource.getCode())
                        .isNotEmpty()
                        .allSatisfy(action -> {
                            assertThat(action.getAccessType()).isNotEqualTo(ResourceAction.AccessType.NOT_GRANTABLE);
                            assertThat(action).isNotIn(ResourceAction.CREATE, ResourceAction.LIST, ResourceAction.ANY);
                        }));
    }

    @Test
    void reachesEveryAncestorThroughTheParentChain() {
        TABLE
                .forEach((resource, objects) -> objects
                        .actions()
                        .values()
                        .stream()
                        .flatMap(List::stream)
                        .filter(OnAncestor.class::isInstance)
                        .map(OnAncestor.class::cast)
                        .forEach(requirement -> assertThat(chainOf(resource))
                                .as(resource.getCode() + " reaches " + requirement.ancestor().getCode())
                                .contains(requirement.ancestor())));
    }

    @Test
    void namesAParentAttributeTheEntityHas() {
        TABLE.forEach((resource, objects) -> {
            assertThat(objects.parent() == Resource.NONE).isEqualTo(objects.parentAttribute() == null);
            if (objects.parentAttribute() != null) {
                assertThat(hasField(objects.entity(), objects.parentAttribute()))
                        .as(resource.getCode() + "." + objects.parentAttribute())
                        .isTrue();
            }
        });
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
