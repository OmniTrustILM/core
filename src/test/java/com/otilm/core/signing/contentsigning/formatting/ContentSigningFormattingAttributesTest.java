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
import com.otilm.api.model.common.attribute.v2.InfoAttributeV2;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.common.ContentSigningFormattingAttributesDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ContentSigningFormattingOperation;
import com.otilm.core.client.ConnectorApiFactory;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
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
        void aggregatesTheReachableSchemasIntoOneFlatSet_whenMaxLevelIsSigned() throws Exception {
            // given
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.COMPUTE_DTBS))
                    .thenReturn(profileListing(attribute("reason")));
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE))
                    .thenReturn(profileListing(attribute("padding")));

            // when
            ContentSigningFormattingDefinitions aggregated = attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then
            assertThat(aggregated.profileAttributes())
                    .extracting(BaseAttribute::getName)
                    .containsExactlyInAnyOrder("reason", "padding");
            verify(apiClient, never())
                    .listFormattingAttributes(connector, ContentSigningFormattingOperation.EMBED_SIGNATURE_TIMESTAMP);
        }

        @Test
        void returnsRequestAttributesApart_whenComputeDtbsListsThem() throws Exception {
            // given
            var requestAttribute = attribute("reason");
            var profileAttribute = attribute("padding");
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.COMPUTE_DTBS))
                    .thenReturn(new ContentSigningFormattingAttributesDto(List.of(profileAttribute),
                            List.of(requestAttribute)));
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE))
                    .thenReturn(profileListing());

            // when
            ContentSigningFormattingDefinitions aggregated = attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then
            assertThat(aggregated.requestAttributes()).containsExactly(requestAttribute);
            assertThat(aggregated.profileAttributes()).containsExactly(profileAttribute);
        }

        @Test
        void fetchesTheTimestampTwinsToo_whenMaxLevelIsTimestamped() throws Exception {
            // given
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(any(), any())).thenReturn(profileListing());

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
        void keepsOneCopyOfAName_whenTwoOperationsDeclareItIdentically() throws Exception {
            // given: the very same declaration object is handed back for every operation
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(any(), any())).thenReturn(profileListing(attribute("reason")));

            // when
            ContentSigningFormattingDefinitions aggregated = attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then
            assertThat(aggregated.profileAttributes()).hasSize(1);
        }

        @Test
        void treatsTwoDeclarationsAsConsistent_whenTheyAreBuiltApartButFieldIdentical() throws Exception {
            // given: two operations each return their OWN freshly built instance -- as a real connector would after
            // deserializing two separate HTTP responses -- but the fields describe the identical attribute
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.COMPUTE_DTBS))
                    .thenReturn(profileListing(attribute("reason")));
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE))
                    .thenReturn(profileListing(attribute("reason")));

            // when
            ContentSigningFormattingDefinitions aggregated = attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then: no rejection, and only one copy survives the merge
            assertThat(aggregated.profileAttributes()).extracting(BaseAttribute::getName).containsExactly("reason");
        }

        @Test
        void rejectsTheConnector_whenTwoOperationsDeclareTheSameNameWithDifferentContentTypes() throws Exception {
            // given: same name, different content type -- a shared name must mean one shared value
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.COMPUTE_DTBS))
                    .thenReturn(profileListing(attribute("reason")));
            DataAttributeV2 divergent = attribute("reason");
            divergent.setContentType(AttributeContentType.INTEGER);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE))
                    .thenReturn(profileListing(divergent));

            // when
            ThrowingCallable aggregate = () -> attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then
            assertThatThrownBy(aggregate).isInstanceOf(ValidationException.class).hasMessageContaining("reason");
        }

        @Test
        void rejectsTheConnector_whenTwoOperationsDeclareTheSameNameWithDifferentProperties() throws Exception {
            // given: same name and content type, but one operation marks it required and the other does not
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.COMPUTE_DTBS))
                    .thenReturn(profileListing(attribute("reason")));
            DataAttributeV2 divergent = attribute("reason");
            divergent.getProperties().setRequired(true);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE))
                    .thenReturn(profileListing(divergent));

            // when
            ThrowingCallable aggregate = () -> attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then
            assertThatThrownBy(aggregate).isInstanceOf(ValidationException.class).hasMessageContaining("reason");
        }

        @Test
        void treatsAnOperationAsListingNothing_whenItsAttributeListsAreNull() throws Exception {
            // given: one operation declares nothing at all, signalled by a null list rather than an empty one
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.COMPUTE_DTBS))
                    .thenReturn(new ContentSigningFormattingAttributesDto(null, null));
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE))
                    .thenReturn(profileListing(attribute("padding")));

            // when
            ContentSigningFormattingDefinitions aggregated = attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then
            assertThat(aggregated.profileAttributes()).extracting(BaseAttribute::getName).containsExactly("padding");
        }

        @Test
        void returnsNoAttributes_whenEveryListingIsEmpty() throws Exception {
            // given
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(any(), any())).thenReturn(profileListing());

            // when
            ContentSigningFormattingDefinitions aggregated = attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then
            assertThat(aggregated.all()).isEmpty();
        }
    }

    @Nested
    class RequestAttributeRules {

        @Test
        void rejectsTheListing_whenAnOperationOtherThanComputeDtbsListsRequestAttributes() throws Exception {
            // given
            var listedOnEmbed = requestListing(attribute("reason"));
            stubListings(profileListing(), listedOnEmbed);

            // when
            ThrowingCallable aggregate = () -> attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then
            assertThatThrownBy(aggregate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE.getCode())
                    .hasMessageContaining("only computeDtbs lists request attributes");
        }

        @Test
        void rejectsTheListing_whenARequestAttributeIsNotADataAttribute() throws Exception {
            // given
            var infoAttribute = new InfoAttributeV2();
            infoAttribute.setName("notice");
            stubListings(requestListing(infoAttribute), profileListing());

            // when
            ThrowingCallable aggregate = () -> attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then
            assertThatThrownBy(aggregate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(infoAttribute.getName())
                    .hasMessageContaining("a request attribute must be a data attribute");
        }

        @Test
        void rejectsTheListing_whenANameIsBothAProfileAndARequestAttribute() throws Exception {
            // given
            var sharedName = "reason";
            stubListings(requestListing(attribute(sharedName)), profileListing(attribute(sharedName)));

            // when
            ThrowingCallable aggregate = () -> attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then
            assertThatThrownBy(aggregate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'%s'".formatted(sharedName))
                    .hasMessageContaining("a name belongs to one list only");
        }

        @Test
        void rejectsTheListing_whenAGroupSharesARequestAttributesName() throws Exception {
            // given
            var sharedName = "reason";
            var grouped = attribute("location");
            grouped.getProperties().setGroup(sharedName);
            stubListings(requestListing(attribute(sharedName), grouped), profileListing());

            // when
            ThrowingCallable aggregate = () -> attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then
            assertThatThrownBy(aggregate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'%s'".formatted(sharedName))
                    .hasMessageContaining("a group and a request attribute need distinct names");
        }

        @Test
        void rejectsTheListing_whenAGroupSharesAGroupedRequestAttributesName() throws Exception {
            // given
            var sharedName = "reason";
            var groupedUnderAnother = attribute(sharedName);
            groupedUnderAnother.getProperties().setGroup("visibleSignature");
            var groupedUnderTheSharedName = attribute("location");
            groupedUnderTheSharedName.getProperties().setGroup(sharedName);
            stubListings(requestListing(groupedUnderAnother, groupedUnderTheSharedName), profileListing());

            // when
            ThrowingCallable aggregate = () -> attributes.aggregate(connector, SignatureLevel.SIGNED);

            // then
            assertThatThrownBy(aggregate)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'%s'".formatted(sharedName))
                    .hasMessageContaining("a group and a request attribute need distinct names");
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void stubListings(ContentSigningFormattingAttributesDto computeDtbs,
                ContentSigningFormattingAttributesDto embedSignatureValue) throws ConnectorException {
            when(connectorApiFactory.getContentSigningFormattingApiClient(connector)).thenReturn(apiClient);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.COMPUTE_DTBS))
                    .thenReturn(computeDtbs);
            when(apiClient.listFormattingAttributes(connector, ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE))
                    .thenReturn(embedSignatureValue);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ContentSigningFormattingAttributesDto requestListing(BaseAttribute... requestAttributes) {
        return new ContentSigningFormattingAttributesDto(List.of(), List.of(requestAttributes));
    }

    private static ContentSigningFormattingAttributesDto profileListing(BaseAttribute... profileAttributes) {
        return new ContentSigningFormattingAttributesDto(List.of(profileAttributes), List.of());
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
