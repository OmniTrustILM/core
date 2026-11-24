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
        void offersListing_whenTheV2ConnectorDeclaresNoRestriction() {
            // given
            var profile = aTokenProfileSnapshot()
                    .withTokenInstance(aTokenSnapshot().withConnectorFeatures(FeatureFlag.KEY_IMPORT).build())
                    .build();

            // when
            boolean available = gates.isAvailable(profile);

            // then
            assertThat(available).isTrue();
        }

        @Test
        void withholdsListing_whenTheConnectorDeclaresAnUnlistableToken() {
            // given
            var profile = aTokenProfileSnapshot()
                    .withTokenInstance(aTokenSnapshot()
                            .withConnectorFeatures(FeatureFlag.KEY_IMPORT, FeatureFlag.UNLISTABLE_TOKEN)
                            .build())
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
        void refusesListing_whenTheConnectorDeclaresAnUnlistableToken() throws Exception {
            // given
            var profile = aTokenProfileSnapshot()
                    .withTokenInstance(aTokenSnapshot().withConnectorFeatures(FeatureFlag.UNLISTABLE_TOKEN).build())
                    .build();
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
            var profile = aTokenProfileSnapshot().withEnabled(false).build();
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
