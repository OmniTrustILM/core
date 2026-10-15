package com.otilm.core.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ValidationException;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CbomUtilTest {

    @Test
    void testMustGetSerialNumber_Success() throws ValidationException {
        Map<String, Object> content = new HashMap<>();
        content.put("serialNumber", "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79");

        String result = CbomUtil.mustGetSerialNumber(content);

        assertEquals("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", result);
    }

    @Test
    void testMustGetSerialNumber_EmptyString_ThrowsException() {
        Map<String, Object> content = new HashMap<>();
        content.put("serialNumber", "");

        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetSerialNumber(content);
        });

        assertEquals("serialNumber must not be empty", exception.getMessage());
    }

    @Test
    void testMustGetSerialNumber_BlankString_ThrowsException() {
        Map<String, Object> content = new HashMap<>();
        content.put("serialNumber", "   ");

        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetSerialNumber(content);
        });

        assertEquals("serialNumber must not be empty", exception.getMessage());
    }

    @Test
    void testMustGetSerialNumber_Null_ThrowsException() {
        Map<String, Object> content = new HashMap<>();
        content.put("serialNumber", null);

        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetSerialNumber(content);
        });

        assertEquals("serialNumber must not be empty", exception.getMessage());
    }

    @Test
    void testMustGetSerialNumber_Missing_ThrowsException() {
        Map<String, Object> content = new HashMap<>();

        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetSerialNumber(content);
        });

        assertEquals("serialNumber must not be empty", exception.getMessage());
    }

    @Test
    void mustGetVersionReturnsAPositiveInteger() throws JsonProcessingException {
        assertEquals(42, CbomUtil.mustGetVersion(parseDocument("{\"version\": 42}")));
    }

    @Test
    void mustGetVersionRefusesADocumentWithoutAVersion() throws JsonProcessingException {
        Map<String, Object> content = parseDocument("{}");

        ValidationException refusal = assertThrows(ValidationException.class, () -> CbomUtil.mustGetVersion(content));

        assertEquals("version is required", refusal.getMessage());
    }

    @Test
    void testGetMetadata_Success() throws ValidationException {
        Map<String, Object> content = new HashMap<>();
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("key", "value");
        content.put("metadata", metadata);

        Map<String, Object> result = CbomUtil.getMetadata(content);

        assertNotNull(result);
        assertEquals("value", result.get("key"));
    }

    @Test
    void testGetMetadata_Missing() {
        Map<String, Object> content = new HashMap<>();

        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.getMetadata(content);
        });

        assertEquals("metadata must be present", exception.getMessage());
    }

    @Test
    void testGetMetadata_NotMap() {
        Map<String, Object> content = new HashMap<>();
        content.put("metadata", "not a map");

        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.getMetadata(content);
        });

        assertEquals("metadata must be JSON object", exception.getMessage());
    }

    @Test
    void testGetMetadataComponentName_Success() {
        Map<String, Object> content = new HashMap<>();
        Map<String, Object> metadata = new HashMap<>();
        Map<String, Object> component = new HashMap<>();
        component.put("name", "test-component");
        metadata.put("component", component);
        content.put("metadata", metadata);

        Optional<String> result = CbomUtil.getMetadataComponentName(content);

        assertTrue(result.isPresent());
        assertEquals("test-component", result.get());
    }

    @Test
    void testGetMetadataComponentName_NoMetadata() {
        Map<String, Object> content = new HashMap<>();

        Optional<String> result = CbomUtil.getMetadataComponentName(content);

        assertFalse(result.isPresent());
    }

    @Test
    void testGetMetadataComponentName_NoComponent() {
        Map<String, Object> content = new HashMap<>();
        Map<String, Object> metadata = new HashMap<>();
        content.put("metadata", metadata);

        Optional<String> result = CbomUtil.getMetadataComponentName(content);

        assertFalse(result.isPresent());
    }

    @Test
    void testGetMetadataComponentName_ComponentNotMap() {
        Map<String, Object> content = new HashMap<>();
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("component", "not a map");
        content.put("metadata", metadata);

        Optional<String> result = CbomUtil.getMetadataComponentName(content);

        assertFalse(result.isPresent());
    }

    @Test
    void testGetMetadataComponentName_NoName() {
        Map<String, Object> content = new HashMap<>();
        Map<String, Object> metadata = new HashMap<>();
        Map<String, Object> component = new HashMap<>();
        metadata.put("component", component);
        content.put("metadata", metadata);

        Optional<String> result = CbomUtil.getMetadataComponentName(content);

        assertFalse(result.isPresent());
    }

    @Test
    void testGetMetadataComponentName_NameNull() {
        Map<String, Object> content = new HashMap<>();
        Map<String, Object> metadata = new HashMap<>();
        Map<String, Object> component = new HashMap<>();
        component.put("name", null);
        metadata.put("component", component);
        content.put("metadata", metadata);

        Optional<String> result = CbomUtil.getMetadataComponentName(content);

        assertFalse(result.isPresent());
    }

    @Test
    void testGetMetadataTimestamp_Success() {
        Map<String, Object> content = new HashMap<>();
        Map<String, Object> metadata = new HashMap<>();
        String timestampStr = "2024-01-15T10:30:00Z";
        metadata.put("timestamp", timestampStr);
        content.put("metadata", metadata);

        Optional<OffsetDateTime> result = CbomUtil.getMetadataTimestamp(content);

        assertTrue(result.isPresent());
        assertEquals(OffsetDateTime.parse(timestampStr), result.get());
    }

    @Test
    void testGetMetadataTimestamp_NoMetadata() {
        Map<String, Object> content = new HashMap<>();

        Optional<OffsetDateTime> result = CbomUtil.getMetadataTimestamp(content);

        assertFalse(result.isPresent());
    }

    @Test
    void testGetMetadataTimestamp_NoTimestamp() {
        Map<String, Object> content = new HashMap<>();
        Map<String, Object> metadata = new HashMap<>();
        content.put("metadata", metadata);

        Optional<OffsetDateTime> result = CbomUtil.getMetadataTimestamp(content);

        assertFalse(result.isPresent());
    }

    @Test
    void testGetMetadataTimestamp_InvalidFormat() {
        Map<String, Object> content = new HashMap<>();
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("timestamp", "invalid-date");
        content.put("metadata", metadata);

        Optional<OffsetDateTime> result = CbomUtil.getMetadataTimestamp(content);

        assertFalse(result.isPresent());
    }

    @Test
    void testGetString_Success() {
        Map<String, Object> content = new HashMap<>();
        content.put("key", "value");

        Optional<String> result = CbomUtil.getString(content, "key");

        assertTrue(result.isPresent());
        assertEquals("value", result.get());
    }

    @Test
    void testGetString_Missing() {
        Map<String, Object> content = new HashMap<>();

        Optional<String> result = CbomUtil.getString(content, "key");

        assertFalse(result.isPresent());
    }

    @Test
    void testGetString_Null() {
        Map<String, Object> content = new HashMap<>();
        content.put("key", null);

        Optional<String> result = CbomUtil.getString(content, "key");

        assertFalse(result.isPresent());
    }

    @Test
    void testGetString_NonStringValue() {
        Map<String, Object> content = new HashMap<>();
        content.put("key", 123);

        Optional<String> result = CbomUtil.getString(content, "key");

        assertTrue(result.isPresent());
        assertEquals("123", result.get());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseDocument(String json) throws JsonProcessingException {
        return new ObjectMapper().readValue(json, Map.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "10.2",
            "10.0",
            "1e1",
            "0",
            "-1",
            "\"10\"",
            "\"abc\"",
            "null",
            "true",
            "{}",
            "[1]",
            "2147483648"})
    void versionReadersRefuseWhatCycloneDxDoesNotAllow(String version) throws JsonProcessingException {
        Map<String, Object> content = parseDocument("{\"version\": " + version + "}");

        ValidationException refusal = assertThrows(ValidationException.class, () -> CbomUtil.validateVersion(content));
        ValidationException mustGetRefusal = assertThrows(ValidationException.class,
                () -> CbomUtil.mustGetVersion(content));

        assertEquals(CbomUtil.INVALID_VERSION_MESSAGE, refusal.getMessage());
        assertEquals(CbomUtil.INVALID_VERSION_MESSAGE, mustGetRefusal.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"version\": 1}", "{\"version\": 42}", "{\"version\": 2147483647}", "{}"})
    void validateVersionAcceptsAPositiveIntegerOrNoVersion(String json) throws JsonProcessingException {
        Map<String, Object> content = parseDocument(json);

        assertDoesNotThrow(() -> CbomUtil.validateVersion(content));
    }
}
