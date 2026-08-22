package com.otilm.core.signing.contentsigning.formatting;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v1.signing.contentsigning.ContentSigningFormattingSyncApiClient;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.common.ContentSigningFormattingOperation;
import com.otilm.core.client.ConnectorApiFactory;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ContentSigningFormattingAttributesTest {

    @Mock
    ConnectorApiFactory connectorApiFactory;
    @Mock
    ContentSigningFormattingSyncApiClient apiClient;
    @Mock
    ApiClientConnectorInfo connector;

    ContentSigningFormattingAttributes attributes;

    @BeforeEach
    void createAggregator() {
        attributes = new ContentSigningFormattingAttributes(connectorApiFactory);
    }

    @Nested
    class ReachableOperations {

        @Test
        void signedReachesOnlyTheComputeAndEmbedPair() {
            // given / when
            List<ContentSigningFormattingOperation> reached = ContentSigningFormattingAttributes
                    .reachableOperations(SignatureLevel.SIGNED);

            // then
            assertThat(reached)
                    .containsExactly(ContentSigningFormattingOperation.COMPUTE_DTBS,
                            ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE);
        }

        @Test
        void timestampedAddsTheSignatureTimestampTwins() {
            // given / when
            List<ContentSigningFormattingOperation> reached = ContentSigningFormattingAttributes
                    .reachableOperations(SignatureLevel.TIMESTAMPED);

            // then
            assertThat(reached)
                    .containsExactly(ContentSigningFormattingOperation.COMPUTE_DTBS,
                            ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE,
                            ContentSigningFormattingOperation.COMPUTE_SIGNATURE_TIMESTAMP_IMPRINT,
                            ContentSigningFormattingOperation.EMBED_SIGNATURE_TIMESTAMP);
        }

        @Test
        void aNullMaxLevelReachesOnlyTheComputeAndEmbedPair() {
            // given: defensive default when the ceiling is unknown -- fail closed to the smallest set
            // when
            List<ContentSigningFormattingOperation> reached = ContentSigningFormattingAttributes
                    .reachableOperations(null);

            // then
            assertThat(reached)
                    .containsExactly(ContentSigningFormattingOperation.COMPUTE_DTBS,
                            ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE);
        }
    }

    @Nested
    class Aggregate {

        @Test
        void aggregatesTheReachableSchemasIntoOneFlatSet() throws ConnectorException {
            // given
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.COMPUTE_DTBS))
                    .thenReturn(List.of(attribute("reason")));
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE))
                    .thenReturn(List.of(attribute("padding")));

            // when
            List<BaseAttribute> aggregated = attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then
            assertThat(aggregated).extracting(BaseAttribute::getName).containsExactlyInAnyOrder("reason", "padding");
            verify(apiClient, never())
                    .listFormattingAttributes(connector, ContentSigningFormattingOperation.EMBED_SIGNATURE_TIMESTAMP);
        }

        @Test
        void fetchesTheTimestampTwinsTooWhenMaxLevelIsTimestamped() throws ConnectorException {
            // given
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(any(), any())).thenReturn(List.of());

            // when
            attributes.aggregate(connector, SignatureLevel.TIMESTAMPED);

            // then
            verify(apiClient)
                    .listFormattingAttributes(connector,
                            ContentSigningFormattingOperation.COMPUTE_SIGNATURE_TIMESTAMP_IMPRINT);
            verify(apiClient)
                    .listFormattingAttributes(connector, ContentSigningFormattingOperation.EMBED_SIGNATURE_TIMESTAMP);
        }

        @Test
        void keepsOneCopyOfANameTwoOperationsDeclareIdentically() throws ConnectorException {
            // given: the very same declaration object is handed back for every operation
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(any(), any())).thenReturn(List.of(attribute("reason")));

            // when
            List<BaseAttribute> aggregated = attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then
            assertThat(aggregated).hasSize(1);
        }

        @Test
        void treatsTwoIndependentlyBuiltButFieldIdenticalDeclarationsAsConsistent() throws ConnectorException {
            // given: two operations each return their OWN freshly built instance -- as a real connector would after
            // deserializing two separate HTTP responses -- but the fields describe the identical attribute
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.COMPUTE_DTBS))
                    .thenReturn(List.of(attribute("reason")));
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE))
                    .thenReturn(List.of(attribute("reason")));

            // when
            List<BaseAttribute> aggregated = attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then: no rejection, and only one copy survives the merge
            assertThat(aggregated).extracting(BaseAttribute::getName).containsExactly("reason");
        }

        @Test
        void rejectsTheConnectorWhenTwoOperationsDeclareTheSameNameDifferently() throws ConnectorException {
            // given: same name, different content type -- a shared name must mean one shared value
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.COMPUTE_DTBS))
                    .thenReturn(List.of(attribute("reason")));
            DataAttributeV2 divergent = attribute("reason");
            divergent.setContentType(AttributeContentType.INTEGER);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE))
                    .thenReturn(List.of(divergent));

            // when / then
            assertThatThrownBy(() -> attributes.aggregate(connector, SignatureLevel.SIGNED))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("reason");
        }

        @Test
        void rejectsTheConnectorWhenTwoOperationsDeclareTheSamePropertiesDifferently() throws ConnectorException {
            // given: same name and content type, but one operation marks it required and the other does not
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.COMPUTE_DTBS))
                    .thenReturn(List.of(attribute("reason")));
            DataAttributeV2 divergent = attribute("reason");
            divergent.getProperties().setRequired(true);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE))
                    .thenReturn(List.of(divergent));

            // when / then
            assertThatThrownBy(() -> attributes.aggregate(connector, SignatureLevel.SIGNED))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("reason");
        }

        @Test
        void treatsANullAttributeListFromAnOperationAsNoAttributes() throws ConnectorException {
            // given: one operation declares nothing at all, signalled by a null list rather than an empty one
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.COMPUTE_DTBS))
                    .thenReturn(null);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE))
                    .thenReturn(List.of(attribute("padding")));

            // when
            List<BaseAttribute> aggregated = attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then
            assertThat(aggregated).extracting(BaseAttribute::getName).containsExactly("padding");
        }

        @Test
        void anEmptyConnectorReplyAggregatesToNoAttributes() throws ConnectorException {
            // given
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(any(), any())).thenReturn(List.of());

            // when / then
            assertThatCode(() -> assertThat(attributes.aggregate(connector, SignatureLevel.SIGNED)).isEmpty())
                    .doesNotThrowAnyException();
        }
    }

    private static DataAttributeV2 attribute(String name) {
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(UUID.nameUUIDFromBytes(name.getBytes()).toString());
        attribute.setName(name);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel(name);
        attribute.setProperties(properties);
        return attribute;
    }
}
