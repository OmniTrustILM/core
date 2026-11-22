package com.otilm.core.service.est;

import com.otilm.core.dao.entity.RaProfile;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;

class EstRouteTest {

    @Test
    void usesTheLabelAsRealm_whenRouteWasNamed() {
        // given
        var label = "devices";
        EstRoute route = new EstRoute(anEstProfile().build(), new RaProfile(), false, label);

        // when
        String realm = route.realm();

        // then
        assertThat(realm).isEqualTo(label);
    }

    @Test
    void usesTheDefaultRealm_whenRouteHasNoLabel() {
        // given
        String noLabel = null;
        EstRoute route = new EstRoute(anEstProfile().build(), new RaProfile(), false, noLabel);

        // when
        String realm = route.realm();

        // then
        assertThat(realm).isEqualTo("est");
    }
}
