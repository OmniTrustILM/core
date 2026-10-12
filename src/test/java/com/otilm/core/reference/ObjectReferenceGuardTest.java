package com.otilm.core.reference;

import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ObjectReferenceGuardTest {

    @Test
    void namesEveryVisibleUser() {
        assertThat(ObjectReferenceGuard.usedBy(List.of("Token 'a' (attribute 'PIN')", "ACME Profile 'b' (key)"), 0))
                .isEqualTo("Token 'a' (attribute 'PIN'); ACME Profile 'b' (key)");
    }

    @Test
    void countsUsersTheCallerMayNotSee() {
        assertThat(ObjectReferenceGuard.usedBy(List.of("Token 'a' (attribute 'PIN')"), 1))
                .isEqualTo("Token 'a' (attribute 'PIN'); 1 object you are not allowed to see");
        assertThat(ObjectReferenceGuard.usedBy(List.of(), 3)).isEqualTo("3 objects you are not allowed to see");
    }
}
