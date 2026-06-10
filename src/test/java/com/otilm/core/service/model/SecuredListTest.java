package com.otilm.core.service.model;

import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.SecurityResourceFilter;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SecuredListTest {

    @Test
    void createsSecuredListGivenOnlySpecificObjectsAllowed() {
        // given
        SecurableTestItem A = new SecurableTestItem("abfbc322-29e1-11ed-a261-0242ac120002", "A");
        SecurableTestItem B = new SecurableTestItem("abfbc322-29e1-11ed-a261-0242ac120003", "B");
        SecurableTestItem C = new SecurableTestItem("abfbc322-29e1-11ed-a261-0242ac120004", "C");
        SecurableTestItem D = new SecurableTestItem("abfbc322-29e1-11ed-a261-0242ac120005", "D");
        SecurableTestItem E = new SecurableTestItem("abfbc322-29e1-11ed-a261-0242ac120006", "E");
        List<SecurableTestItem> items = List.of(A, B, C, D, E);

        SecurityFilter filter = SecurityFilter.create();
        filter.setResourceFilter(SecurityResourceFilter.create());
        filter.getResourceFilter().setAreOnlySpecificObjectsAllowed(true);
        filter.getResourceFilter().addAllowedObjects(List.of("abfbc322-29e1-11ed-a261-0242ac120002", "abfbc322-29e1-11ed-a261-0242ac120004"));

        // when
        SecuredList<SecurableTestItem> list = SecuredList.fromFilter(filter, items);

        // then
        assertEquals(List.of(A, C), list.getAllowed());
    }

    @Test
    void createsSecuredListGivenAccessIsAllowedToGroupOfObjects() {
        // given
        SecurableTestItem A = new SecurableTestItem("abfbc322-29e1-11ed-a261-0242ac120002", "A");
        SecurableTestItem B = new SecurableTestItem("abfbc322-29e1-11ed-a261-0242ac120003", "B");
        SecurableTestItem C = new SecurableTestItem("abfbc322-29e1-11ed-a261-0242ac120004", "C");
        SecurableTestItem D = new SecurableTestItem("abfbc322-29e1-11ed-a261-0242ac120005", "D");
        SecurableTestItem E = new SecurableTestItem("abfbc322-29e1-11ed-a261-0242ac120006", "E");
        List<SecurableTestItem> items = List.of(A, B, C, D, E);

        SecurityFilter filter = SecurityFilter.create();
        filter.setResourceFilter(SecurityResourceFilter.create());
        filter.getResourceFilter().setAreOnlySpecificObjectsAllowed(false);
        filter.getResourceFilter().addDeniedObjects(List.of("abfbc322-29e1-11ed-a261-0242ac120002", "abfbc322-29e1-11ed-a261-0242ac120004"));

        // when
        SecuredList<SecurableTestItem> list = SecuredList.fromFilter(filter, items);

        // then
        assertEquals(List.of(B, D, E), list.getAllowed());
    }

    static class SecurableTestItem implements Securable {

        private final UUID uuid;
        private final String name;

        public SecurableTestItem(UUID uuid, String name) {
            this.uuid = uuid;
            this.name = name;
        }

        public SecurableTestItem(String uuid, String name) {
            this.uuid = UUID.fromString(uuid);
            this.name = name;
        }

        @Override
        public UUID getUuid() {
            return uuid;
        }

        @Override
        public String getName() {
            return name;
        }
    }

}
