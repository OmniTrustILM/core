package com.otilm.core.service.handler;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import java.util.UUID;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.TokenInstanceFullModelBuilder.aTokenSnapshot;
import static com.otilm.core.util.builders.TokenProfileFullModelBuilder.aTokenProfileSnapshot;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KeyListGatesTest {

    private final KeyImportGates keyImportGates = mock(KeyImportGates.class);
    private final KeyListGates gates = new KeyListGates(keyImportGates, new ConnectorCapabilityService());

    // ── IsAvailable ───────────────────────────────────────────────────────────

    @Nested
    class IsAvailable {

        @Test
        void offersListing_whenTheConnectorListsKeys() {
            // given
            var profile = aTokenProfileSnapshot()
                    .withTokenInstance(aTokenSnapshot().withConnectorFeatures(FeatureFlag.KEY_LIST).build())
                    .build();

            // when
            boolean available = gates.isAvailable(profile);

            // then
            assertThat(available).isTrue();
        }

        @Test
        void withholdsListing_whenTheV2ConnectorLacksKeyListing() {
            // given
            var profile = aTokenProfileSnapshot()
                    .withTokenInstance(aTokenSnapshot().withConnectorFeatures(FeatureFlag.KEY_IMPORT).build())
                    .build();

            // when
            boolean available = gates.isAvailable(profile);

            // then
            assertThat(available).isFalse();
        }

        @Test
        void withholdsListing_whenTheConnectorIsV1() {
            // given
            var profile = aTokenProfileSnapshot()
                    .withTokenInstance(aTokenSnapshot().withoutConnectorInterface().build())
                    .build();

            // when
            boolean available = gates.isAvailable(profile);

            // then
            assertThat(available).isFalse();
        }
    }

    // ── RequireListable ───────────────────────────────────────────────────────

    @Nested
    class RequireListable {

        @Test
        void refusesListing_whenTheConnectorLacksKeyListing() throws Exception {
            // given
            var profile = aTokenProfileSnapshot().build();
            when(keyImportGates.requireAccess(profile.tokenInstanceReferenceUuid(), profile.uuid()))
                    .thenReturn(profile);
            UUID tokenInstanceUuid = profile.tokenInstanceReferenceUuid();
            UUID tokenProfileUuid = profile.uuid();

            // when / then
            assertThatThrownBy(() -> gates.requireListable(tokenInstanceUuid, tokenProfileUuid))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("cannot list the keys in its key storage");
        }

        @Test
        void refusesListing_whenTheProfileIsDisabled() throws Exception {
            // given
            var profile = aTokenProfileSnapshot()
                    .withTokenInstance(aTokenSnapshot().withConnectorFeatures(FeatureFlag.KEY_LIST).build())
                    .withEnabled(false)
                    .build();
            when(keyImportGates.requireAccess(profile.tokenInstanceReferenceUuid(), profile.uuid()))
                    .thenReturn(profile);
            UUID tokenInstanceUuid = profile.tokenInstanceReferenceUuid();
            UUID tokenProfileUuid = profile.uuid();

            // when / then
            assertThatThrownBy(() -> gates.requireListable(tokenInstanceUuid, tokenProfileUuid))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("is disabled");
        }
    }
}
