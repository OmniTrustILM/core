package com.czertainly.core.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ProxyCodeHelper}.
 * Tests cover critical functionality including validation, normalization,
 * diacritics removal, special character handling, and length limits.
 */
@DisplayName("ProxyCodeHelper Unit Tests")
class ProxyCodeHelperTest {

    // VALIDATION

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", "\t", "\n", "   \t\n  "})
    @DisplayName("Should throw IllegalArgumentException for blank or null names")
    void testCalculateCode_BlankOrNull_ThrowsException(String name) {
        ProxyCodeHelper helper = new ProxyCodeHelper("proxy-");

        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> helper.calculateCode(name)
        );

        assertEquals("Proxy name must not be blank", exception.getMessage());
    }

    // BASIC NORMALIZATION

    @Test
    @DisplayName("Should normalize simple name with spaces")
    void testCalculateCode_SimpleNameWithSpaces() {
        ProxyCodeHelper helper = new ProxyCodeHelper("proxy-");

        String result = helper.calculateCode("Test Proxy");

        assertEquals("proxy-test-proxy", result);
    }

    @Test
    @DisplayName("Should handle mixed case and convert to lowercase")
    void testCalculateCode_MixedCase() {
        ProxyCodeHelper helper = new ProxyCodeHelper("proxy-");

        String result = helper.calculateCode("TeSt PrOxY NaMe");

        assertEquals("proxy-test-proxy-name", result);
    }

    // DIACRITICS REMOVAL

    @ParameterizedTest
    @CsvSource({
        "'Příliš žluťoučký kůň', 'proxy-prilis-zlutoucky-kun'",
        "'Müller Straße', 'proxy-muller-strae'",
        "'Łódź Świętokrzyska', 'proxy-lodz-swietokrzyska'",
        "'São Paulo', 'proxy-sao-paulo'"
    })
    @DisplayName("Should remove diacritics from various languages")
    void testCalculateCode_DiacriticsRemoval(String input, String expected) {
        ProxyCodeHelper helper = new ProxyCodeHelper("proxy-");

        String result = helper.calculateCode(input);

        assertEquals(expected, result);
    }

    // WHITESPACE HANDLING

    @Test
    @DisplayName("Should replace and deduplicate whitespace to single hyphens")
    void testCalculateCode_MultipleSpaces() {
        ProxyCodeHelper helper = new ProxyCodeHelper("proxy-");

        String result = helper.calculateCode("Test     Proxy     Name");

        assertEquals("proxy-test-proxy-name", result);
    }

    // SPECIAL CHARACTERS

    @ParameterizedTest
    @CsvSource({
        "'Test@Proxy#123', 'proxy-testproxy123'",
        "'Test(Proxy)Name', 'proxy-testproxyname'",
        "'Test/Proxy\\Name', 'proxy-testproxyname'",
        "'Test.Proxy_Name', 'proxy-testproxyname'"
    })
    @DisplayName("Should remove special characters")
    void testCalculateCode_SpecialCharactersRemoval(String input, String expected) {
        ProxyCodeHelper helper = new ProxyCodeHelper("proxy-");

        String result = helper.calculateCode(input);

        assertEquals(expected, result);
    }

    // NUMERIC HANDLING

    @Test
    @DisplayName("Should handle numeric values correctly")
    void testCalculateCode_NumericOnly() {
        ProxyCodeHelper helper = new ProxyCodeHelper("proxy-");

        String result = helper.calculateCode("12345");

        assertEquals("proxy-12345", result);
    }

    // PREFIX CONFIGURATION

    @Test
    @DisplayName("Should use default prefix 'proxy-'")
    void testCalculateCode_DefaultPrefix() {
        ProxyCodeHelper helper = new ProxyCodeHelper("proxy-");

        String result = helper.calculateCode("Test");

        assertTrue(result.startsWith("proxy-"));
        assertEquals("proxy-test", result);
    }

    @Test
    @DisplayName("Should use custom prefix")
    void testCalculateCode_CustomPrefix() {
        ProxyCodeHelper helper = new ProxyCodeHelper("custom-");

        String result = helper.calculateCode("Test");

        assertTrue(result.startsWith("custom-"));
        assertEquals("custom-test", result);
    }

    // LENGTH LIMIT

    @Test
    @DisplayName("Should abbreviate names exceeding 30 characters")
    void testCalculateCode_LongName() {
        ProxyCodeHelper helper = new ProxyCodeHelper("proxy-");

        String result = helper.calculateCode("Very Long Proxy Name That Definitely Exceeds The Maximum Length");

        assertEquals(30, result.length());
        assertTrue(result.startsWith("proxy-"));
        assertTrue(result.contains("-"));
    }

    // INTEGRATION TESTS

    @Test
    @DisplayName("Should handle complex name with all transformations")
    void testCalculateCode_ComplexName() {
        ProxyCodeHelper helper = new ProxyCodeHelper("proxy-");

        String result = helper.calculateCode("  Café-Test@123_Proxy!  ");

        assertEquals("proxy-cafe-test123proxy", result);
    }

    @Test
    @DisplayName("Should handle real-world proxy name example")
    void testCalculateCode_RealWorldExample() {
        ProxyCodeHelper helper = new ProxyCodeHelper("proxy-");

        String result = helper.calculateCode("Production API Gateway (v2.0)");

        assertEquals("proxy-productio-pi-gateway-v20", result);
    }

    @Test
    @DisplayName("Should handle Czech company name")
    void testCalculateCode_CzechCompanyName() {
        ProxyCodeHelper helper = new ProxyCodeHelper("proxy-");

        String result = helper.calculateCode("ČZERTAINLY s.r.o.");

        assertEquals("proxy-czertainly-sro", result);
    }
}