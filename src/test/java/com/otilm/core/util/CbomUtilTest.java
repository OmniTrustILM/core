package com.otilm.core.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.otilm.api.exception.ValidationException;

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
    void testMustGetVersion_WithValidInteger_ShouldReturnVersion() throws ValidationException {
        Map<String, Object> content = new HashMap<>();
        content.put("version", 1);
        
        int result = CbomUtil.mustGetVersion(content);
        
        assertEquals(1, result);
    }

    @Test
    void testMustGetVersion_WithValidIntegerZero_ShouldReturnZero() throws ValidationException {
        Map<String, Object> content = new HashMap<>();
        content.put("version", 0);
        
        int result = CbomUtil.mustGetVersion(content);
        
        assertEquals(0, result);
    }

    @Test
    void testMustGetVersion_WithNegativeInteger_ShouldReturnNegativeValue() throws ValidationException {
        Map<String, Object> content = new HashMap<>();
        content.put("version", -1);
        
        int result = CbomUtil.mustGetVersion(content);
        
        assertEquals(-1, result);
    }

    @Test
    void testMustGetVersion_WithValidStringNumber_ShouldReturnParsedInteger() throws ValidationException {
        Map<String, Object> content = new HashMap<>();
        content.put("version", "42");
        
        int result = CbomUtil.mustGetVersion(content);
        
        assertEquals(42, result);
    }

    @Test
    void testMustGetVersion_WithStringNumberWithLeadingWhitespace_ShouldReturnParsedInteger() throws ValidationException {
        Map<String, Object> content = new HashMap<>();
        content.put("version", "  123");
        
        int result = CbomUtil.mustGetVersion(content);
        
        assertEquals(123, result);
    }

    @Test
    void testMustGetVersion_WithStringNumberWithTrailingWhitespace_ShouldReturnParsedInteger() throws ValidationException {
        Map<String, Object> content = new HashMap<>();
        content.put("version", "456  ");
        
        int result = CbomUtil.mustGetVersion(content);
        
        assertEquals(456, result);
    }

    @Test
    void testMustGetVersion_WithStringNumberWithSurroundingWhitespace_ShouldReturnParsedInteger() throws ValidationException {
        Map<String, Object> content = new HashMap<>();
        content.put("version", "  789  ");
        
        int result = CbomUtil.mustGetVersion(content);
        
        assertEquals(789, result);
    }

    @Test
    void testMustGetVersion_WithNegativeStringNumber_ShouldReturnNegativeInteger() throws ValidationException {
        Map<String, Object> content = new HashMap<>();
        content.put("version", "-99");
        
        int result = CbomUtil.mustGetVersion(content);
        
        assertEquals(-99, result);
    }

    @Test
    void testMustGetVersion_WithMissingKey_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertEquals("version is required", exception.getMessage());
    }

    @Test
    void testMustGetVersion_WithNullValue_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        content.put("version", null);
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertEquals("version must not be null", exception.getMessage());
    }

    @Test
    void testMustGetVersion_WithEmptyString_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        content.put("version", "");
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertEquals("version must not be empty or blank", exception.getMessage());
    }

    @Test
    void testMustGetVersion_WithBlankString_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        content.put("version", "   ");
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertEquals("version must not be empty or blank", exception.getMessage());
    }

    @Test
    void testMustGetVersion_WithTabsAndSpaces_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        content.put("version", "\t  \n  ");
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertEquals("version must not be empty or blank", exception.getMessage());
    }

    @Test
    void testMustGetVersion_WithInvalidStringFormat_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        content.put("version", "abc");
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertEquals("version must be a valid integer, got: 'abc'", exception.getMessage());
    }

    @Test
    void testMustGetVersion_WithDecimalString_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        content.put("version", "1.5");
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertEquals("version must be a valid integer, got: '1.5'", exception.getMessage());
    }

    @Test
    void testMustGetVersion_WithAlphanumericString_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        content.put("version", "v1");
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertEquals("version must be a valid integer, got: 'v1'", exception.getMessage());
    }

    @Test
    void testMustGetVersion_WithSpecialCharacters_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        content.put("version", "1!2@3");
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertEquals("version must be a valid integer, got: '1!2@3'", exception.getMessage());
    }

    @Test
    void testMustGetVersion_WithDoubleType_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        content.put("version", 1.5);
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertEquals("version must be an integer or a numeric string, got type: Double", exception.getMessage());
    }

    @Test
    void testMustGetVersion_WithLongType_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        content.put("version", 100L);
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertEquals("version must be an integer or a numeric string, got type: Long", exception.getMessage());
    }

    @Test
    void testMustGetVersion_WithBooleanType_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        content.put("version", true);
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertEquals("version must be an integer or a numeric string, got type: Boolean", exception.getMessage());
    }

    @Test
    void testMustGetVersion_WithArrayType_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        content.put("version", new int[]{1, 2, 3});
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertTrue(exception.getMessage().contains("version must be an integer or a numeric string, got type:"));
    }

    @Test
    void testMustGetVersion_WithMapType_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        content.put("version", new HashMap<>());
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertEquals("version must be an integer or a numeric string, got type: HashMap", exception.getMessage());
    }

    @Test
    void testMustGetVersion_WithObjectType_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        content.put("version", new Object());
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertEquals("version must be an integer or a numeric string, got type: Object", exception.getMessage());
    }

    @Test
    void testMustGetVersion_WithIntegerOverflow_ShouldThrowValidationException() {
        Map<String, Object> content = new HashMap<>();
        content.put("version", "9999999999999999999");
        
        ValidationException exception = assertThrows(ValidationException.class, () -> {
            CbomUtil.mustGetVersion(content);
        });
        
        assertEquals("version must be a valid integer, got: '9999999999999999999'", exception.getMessage());
    }

    @Test
    void testMustGetVersion_WithMaxInteger_ShouldReturnMaxValue() throws ValidationException {
        Map<String, Object> content = new HashMap<>();
        content.put("version", String.valueOf(Integer.MAX_VALUE));
        
        int result = CbomUtil.mustGetVersion(content);
        
        assertEquals(Integer.MAX_VALUE, result);
    }

    @Test
    void testMustGetVersion_WithMinInteger_ShouldReturnMinValue() throws ValidationException {
        Map<String, Object> content = new HashMap<>();
        content.put("version", String.valueOf(Integer.MIN_VALUE));

        int result = CbomUtil.mustGetVersion(content);

        assertEquals(Integer.MIN_VALUE, result);
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
}
