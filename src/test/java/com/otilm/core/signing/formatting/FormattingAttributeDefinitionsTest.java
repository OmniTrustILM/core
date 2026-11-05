package com.otilm.core.signing.formatting;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.interfaces.client.v2.AttributesSyncApiClient;
import com.otilm.api.model.client.connector.v2.attribute.AttributeDefinitionsDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.core.connector.AuthType;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.events.ConnectorChangedEvent;
import com.otilm.core.model.connector.ImmutableConnectorInfo;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
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
            definitions.forTimestamping(connectorAt("http://before-edit.test"));

            // when
            definitions.forTimestamping(connectorAt("http://after-edit.test"));

            // then
            verify(attributesClient, times(2)).listDefinitions(any(), any());
        }

        @Test
        void asksTheContentSigningFormatterAgain_whenTheConnectorIsReloadedAfterAnEdit() throws Exception {
            // given — a signature that captured the connector before an edit loads after the edit cleared the cache
            var level = SignatureLevel.SIGNED;
            when(contentSigningFormattingAttributes.aggregate(any(), any())).thenReturn(List.of());
            definitions.forContentSigning(connectorAt("http://before-edit.test"), level);

            // when
            definitions.forContentSigning(connectorAt("http://after-edit.test"), level);

            // then
            verify(contentSigningFormattingAttributes, times(2)).aggregate(any(), any());
        }

        @Test
        void asksTheFormatterAgain_whenTheConnectorChanges() throws Exception {
            // given — a cached answer, then a change to the same connector
            stubPublishedRegistry();
            definitions.forTimestamping(formatter);
            definitions.forgetConnector(new ConnectorChangedEvent(connectorUuid));

            // when
            definitions.forTimestamping(formatter);

            // then
            verify(attributesClient, times(2)).listDefinitions(any(), any());
        }
    }

    // ── ContentSigningOperations ──────────────────────────────────────────────

    @Nested
    class ContentSigningOperations {

        @Test
        void asksTheFormatterAgain_whenTheLevelReachesMoreOperations() throws Exception {
            // given
            var reachingMoreOperations = SignatureLevel.TIMESTAMPED;
            when(contentSigningFormattingAttributes.aggregate(any(), any())).thenReturn(List.of());
            definitions.forContentSigning(formatter, SignatureLevel.SIGNED);

            // when
            definitions.forContentSigning(formatter, reachingMoreOperations);

            // then
            verify(contentSigningFormattingAttributes).aggregate(formatter, reachingMoreOperations);
        }

        @Test
        void reusesTheDefinitions_whenTheLevelReachesTheSameOperations() throws Exception {
            // given
            var reachingTheSameOperations = SignatureLevel.ARCHIVAL;
            when(contentSigningFormattingAttributes.aggregate(any(), any())).thenReturn(List.of());
            definitions.forContentSigning(formatter, SignatureLevel.TIMESTAMPED);

            // when
            definitions.forContentSigning(formatter, reachingTheSameOperations);

            // then
            verify(contentSigningFormattingAttributes, never()).aggregate(formatter, reachingTheSameOperations);
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
            ThrowingCallable read = () -> definitions.forTimestamping(formatter);

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
            ThrowingCallable read = () -> definitions.forTimestamping(formatter);

            // then
            assertRefusedAsConnectorFault(read);
        }

        @Test
        void throwsConnectorFault_whenTheStoreRefusesTheDefinitions() throws Exception {
            // given — the formatter changed an attribute's content type since Core stored it
            stubPublishedRegistry();
            doThrow(new AttributeException("content type changed"))
                    .when(attributeEngine)
                    .updateDataAttributeDefinitions(any(), any(), any());

            // when
            ThrowingCallable read = () -> definitions.forTimestamping(formatter);

            // then
            assertRefusedAsConnectorFault(read);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static Stream<Named<AttributeDefinitionsDto>> answersWithoutDefinitions() {
            return Stream
                    .of(named("an empty body", null),
                            named("a registry missing its definitions", new AttributeDefinitionsDto()));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubPublishedRegistry() throws Exception {
        AttributeDefinitionsDto registry = new AttributeDefinitionsDto();
        registry.setDefinitions(List.<BaseAttribute>of(policyDefinition()));
        when(connectorApiFactory.getAttributesApiClientV2(any())).thenReturn(attributesClient);
        when(attributesClient.listDefinitions(any(), any())).thenReturn(registry);
    }

    private ApiClientConnectorInfo connectorAt(String url) {
        return new ImmutableConnectorInfo(connectorUuid.toString(), "formatter", url, ConnectorStatus.CONNECTED,
                AuthType.NONE, List.of(), null);
    }

    private static DataAttributeV2 policyDefinition() {
        DataAttributeV2 definition = new DataAttributeV2();
        definition.setUuid(UUID.randomUUID().toString());
        definition.setName("data_formattingPolicy");
        definition.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("Formatting policy");
        definition.setProperties(properties);
        return definition;
    }

    private static void assertRefusedAsConnectorFault(ThrowingCallable read) {
        assertThatThrownBy(read).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
            assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
            assertThat(refusal.clientMessage()).isEqualTo("Internal error during signature formatting");
        });
    }
}
