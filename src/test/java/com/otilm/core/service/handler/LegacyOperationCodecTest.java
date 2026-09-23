package com.otilm.core.service.handler;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

class LegacyOperationCodecTest {

    @Test
    void randomRequest_copiesLengthAndAttributes() {
        // given
        List<RequestAttribute> attributes = List.of(new RequestAttributeV2());

        // when
        var request = LegacyOperationCodec.randomRequest(16, attributes);

        // then
        assertEquals(16, request.getLength());
        assertSame(attributes, request.getAttributes());
    }

    @Test
    void signRequest_decodesBase64_andKeepsIdentifiers() {
        // given
        List<OperationDataItem> items = List
                .of(new OperationDataItem(Base64.getEncoder().encodeToString(new byte[]{1, 2}), "a"));
        List<RequestAttribute> attributes = List.of(new RequestAttributeV2());

        // when
        var request = LegacyOperationCodec.signRequest(items, attributes);

        // then
        assertArrayEquals(new byte[]{1, 2}, request.getData().get(0).getData());
        assertEquals("a", request.getData().get(0).getIdentifier());
        assertSame(attributes, request.getSignatureAttributes());
    }

    @Test
    void verifyRequest_allowsMissingData_andMapsSignatures() {
        // given
        List<OperationDataItem> signatures = List.of(new OperationDataItem("AQ==", "s"));

        // when
        var request = LegacyOperationCodec.verifyRequest(null, signatures, List.of());

        // then
        assertNull(request.getData());
        assertEquals("s", request.getSignatures().get(0).getIdentifier());
    }

    @Test
    void cipherResults_encodeBase64_andPreserveDetails() {
        // given
        var item = LegacyOperationFixtures.cipherResponseItem(new byte[]{9}, "c", "detail");

        // when
        List<OperationResultItem> results = LegacyOperationCodec.cipherResults(List.of(item));

        // then
        assertEquals(Base64.getEncoder().encodeToString(new byte[]{9}), results.get(0).data());
        assertEquals("c", results.get(0).identifier());
        assertEquals("detail", results.get(0).details());
    }
}
