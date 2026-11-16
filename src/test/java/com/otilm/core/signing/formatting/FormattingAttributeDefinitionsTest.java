package com.otilm.core.signing.formatting;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.interfaces.client.v2.AttributesSyncApiClient;
import com.otilm.api.model.client.connector.v2.attribute.AttributeDefinitionsDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.core.connector.AuthType;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.events.ConnectorChangedEvent;
import com.otilm.core.model.connector.ImmutableConnectorInfo;
import com.otilm.core.model.signing.workflow.ManagedContentSigningWorkflow;
import com.otilm.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.otilm.core.signing.contentsigning.formatting.ContentSigningFormattingAttributes;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.util.cache.CacheManagerFixtures;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cache.CacheManager;

import static com.otilm.core.model.signing.workflow.ManagedTimestampingWorkflowBuilder.aManagedTimestampingWorkflow;
import static com.otilm.core.util.builders.DataAttributeV3Builder.aDataAttribute;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FormattingAttributeDefinitionsTest {

    private static final Duration TTL = Duration.ofMinutes(5);

    @Mock
    private ConnectorApiFactory connectorApiFactory;

    @Mock
    private AttributesSyncApiClient attributesClient;

    @Mock
    private ContentSigningFormattingAttributes contentSigningFormattingAttributes;

    @Mock
    private AttributeEngine attributeEngine;

    private FormattingAttributeDefinitions definitions;
    private final UUID connectorUuid = UUID.randomUUID();
    private final ApiClientConnectorInfo formatter = connectorAt("http://formatter.test");
    private final ManagedTimestampingWorkflow timestampingWorkflow = aManagedTimestampingWorkflow().build();

    @BeforeEach
    void wireDefinitionsCache() {
        CacheManager cacheManager = CacheManagerFixtures
                .readThrough(Caffeine.newBuilder().expireAfterWrite(TTL),
                        CacheConfig.FORMATTING_ATTRIBUTE_DEFINITIONS_CACHE);
        CacheEvictor cacheEvictor = new CacheEvictor();
        cacheEvictor.setCacheManager(cacheManager);
        definitions = new FormattingAttributeDefinitions(connectorApiFactory, contentSigningFormattingAttributes,
                attributeEngine, cacheManager, cacheEvictor);
    }

    // ── ConnectorIdentity ─────────────────────────────────────────────────────

    @Nested
    class ConnectorIdentity {

        @Test
        void asksTheTimestampFormatterAgain_whenTheConnectorIsReloadedAfterAnEdit() throws Exception {
            // given — a timestamp that captured the connector before an edit loads after the edit cleared the cache
            stubPublishedRegistry();
            definitions.forTimestamping(connectorAt("http://before-edit.test"), timestampingWorkflow);

            // when
            definitions.forTimestamping(connectorAt("http://after-edit.test"), timestampingWorkflow);

            // then
            verify(attributesClient, times(2)).listDefinitions(any(), any());
        }

        @Test
        void asksTheContentSigningFormatterAgain_whenTheConnectorIsReloadedAfterAnEdit() throws Exception {
            // given — a signature that captured the connector before an edit loads after the edit cleared the cache
            var workflow = contentSigningWorkflowAt(SignatureLevel.SIGNED);
            when(contentSigningFormattingAttributes.aggregate(any(), any())).thenReturn(List.of());
            definitions.forContentSigning(connectorAt("http://before-edit.test"), workflow);

            // when
            definitions.forContentSigning(connectorAt("http://after-edit.test"), workflow);

            // then
            verify(contentSigningFormattingAttributes, times(2)).aggregate(any(), any());
        }

        @Test
        void asksTheFormatterAgain_whenTheConnectorChanges() throws Exception {
            // given — a cached answer, then a change to the same connector
            stubPublishedRegistry();
            definitions.forTimestamping(formatter, timestampingWorkflow);
            definitions.forgetConnector(new ConnectorChangedEvent(connectorUuid));

            // when
            definitions.forTimestamping(formatter, timestampingWorkflow);

            // then
            verify(attributesClient, times(2)).listDefinitions(any(), any());
        }
    }

    // ── ProfileLoad ───────────────────────────────────────────────────────────

    @Nested
    class ProfileLoad {

        @Test
        void asksTheFormatterAgain_whenTheProfileIsReloaded() throws Exception {
            // given — each load of a profile builds its workflow afresh
            stubPublishedRegistry();
            definitions.forTimestamping(formatter, aManagedTimestampingWorkflow().build());
            var reloadedWorkflow = aManagedTimestampingWorkflow().build();

            // when
            definitions.forTimestamping(formatter, reloadedWorkflow);

            // then
            verify(attributesClient, times(2)).listDefinitions(any(), any());
        }

        @Test
        void readsTheOperationsUpToTheMaximumLevel_whenTheProfileSignsContent() throws Exception {
            // given
            var maxLevel = SignatureLevel.TIMESTAMPED;
            when(contentSigningFormattingAttributes.aggregate(any(), any())).thenReturn(List.of());

            // when
            definitions.forContentSigning(formatter, contentSigningWorkflowAt(maxLevel));

            // then
            verify(contentSigningFormattingAttributes).aggregate(formatter, maxLevel);
        }
    }

    // ── StoreRefusal ──────────────────────────────────────────────────────────

    @Nested
    class StoreRefusal {

        @Test
        void returnsThePublishedDefinitions_whenTheStoreRefusesThem() throws Exception {
            // given — the formatter changed an attribute's content type since Core stored it
            List<BaseAttribute> published = stubPublishedRegistry();
            refuseToStore();

            // when
            List<BaseAttribute> read = definitions.forTimestamping(formatter, timestampingWorkflow);

            // then
            assertThat(read).containsExactlyElementsOf(published);
        }

        @Test
        void cachesThePublishedDefinitions_whenTheStoreRefusesThem() throws Exception {
            // given
            stubPublishedRegistry();
            refuseToStore();
            definitions.forTimestamping(formatter, timestampingWorkflow);

            // when
            definitions.forTimestamping(formatter, timestampingWorkflow);

            // then
            verify(attributesClient).listDefinitions(any(), any());
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void refuseToStore() throws Exception {
            doThrow(new AttributeException("content type changed"))
                    .when(attributeEngine)
                    .updateDataAttributeDefinitions(any(), any(), any());
        }
    }

    // ── FillFailure ───────────────────────────────────────────────────────────

    @Nested
    class FillFailure {

        @Test
        void throwsConnectorFault_whenTheFormatterCannotListItsDefinitions() throws Exception {
            // given
            when(connectorApiFactory.getAttributesApiClientV2(formatter)).thenReturn(attributesClient);
            when(attributesClient.listDefinitions(any(), any())).thenThrow(new ConnectorException("unreachable"));

            // when
            ThrowingCallable read = () -> definitions.forTimestamping(formatter, timestampingWorkflow);

            // then
            assertRefusedAsConnectorFault(read);
        }

        @ParameterizedTest
        @MethodSource("answersWithoutDefinitions")
        void throwsConnectorFault_whenTheFormatterAnswersWithoutDefinitions(AttributeDefinitionsDto answer)
                throws Exception {
            // given
            when(connectorApiFactory.getAttributesApiClientV2(formatter)).thenReturn(attributesClient);
            when(attributesClient.listDefinitions(any(), any())).thenReturn(answer);

            // when
            ThrowingCallable read = () -> definitions.forTimestamping(formatter, timestampingWorkflow);

            // then
            assertRefusedAsConnectorFault(read);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static Stream<Named<AttributeDefinitionsDto>> answersWithoutDefinitions() {
            return Stream
                    .of(named("an empty body", null),
                            named("a registry missing its definitions", new AttributeDefinitionsDto()));
        }

        private static void assertRefusedAsConnectorFault(ThrowingCallable read) {
            assertThatThrownBy(read).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
                assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
                assertThat(refusal.clientMessage()).isEqualTo("Internal error during signature formatting");
            });
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private List<BaseAttribute> stubPublishedRegistry() throws Exception {
        BaseAttribute policyDefinition = aDataAttribute().withName("data_formattingPolicy").build();
        AttributeDefinitionsDto registry = new AttributeDefinitionsDto();
        registry.setDefinitions(List.of(policyDefinition));
        when(connectorApiFactory.getAttributesApiClientV2(any())).thenReturn(attributesClient);
        when(attributesClient.listDefinitions(any(), any())).thenReturn(registry);
        return registry.getDefinitions();
    }

    private ApiClientConnectorInfo connectorAt(String url) {
        return new ImmutableConnectorInfo(connectorUuid.toString(), "formatter", url, ConnectorStatus.CONNECTED,
                AuthType.NONE, List.of(), null);
    }

    private ManagedContentSigningWorkflow contentSigningWorkflowAt(SignatureLevel maxLevel) {
        return new ManagedContentSigningWorkflow(connectorUuid, List.of(), null, maxLevel, null, null, null);
    }
}
