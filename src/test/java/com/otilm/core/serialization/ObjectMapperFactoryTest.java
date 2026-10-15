package com.otilm.core.serialization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidDefinitionException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pins the recipes whose behaviour is not obvious from the factory method alone.
 */
class ObjectMapperFactoryTest {

    /**
     * The exported columns are open-typed, so a producer anywhere may hand the export a JDK8 value.
     */
    @Test
    void auditLogExportSerializesJdk8TypesThroughTheirDiscoveredModule() throws JsonProcessingException {
        Map<String, Object> additionalData = new LinkedHashMap<>();
        additionalData.put("present", Optional.of("value"));
        additionalData.put("count", OptionalInt.of(3));

        String json = ObjectMapperFactory.auditLogExport().writeValueAsString(additionalData);

        assertThat(json).isEqualTo("{\"present\":\"value\",\"count\":3}");
    }

    @Test
    void auditLogExportWritesAnEmptyOptionalWithoutFailing() {
        assertThatCode(() -> ObjectMapperFactory.auditLogExport().writeValueAsString(Optional.empty()))
                .doesNotThrowAnyException();
    }

    @Test
    void auditLogExportWritesDatesAsTextAndDropsNullMembers() throws JsonProcessingException {
        Map<String, Object> additionalData = new LinkedHashMap<>();
        additionalData.put("at", OffsetDateTime.of(2024, 5, 6, 7, 8, 9, 0, ZoneOffset.UTC));
        additionalData.put("absent", null);

        String json = ObjectMapperFactory.auditLogExport().writeValueAsString(additionalData);

        assertThat(json).isEqualTo("{\"at\":\"2024-05-06T07:08:09Z\"}");
    }

    /**
     * Keeps the null members Spring 6.2's {@code RestClient.builder()} wrote, which {@link ObjectMapperFactory#wire()}
     * leaves out.
     */
    @Test
    void restClientDefaultWritesNullMembers() throws JsonProcessingException {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("absent", null);

        String json = ObjectMapperFactory.restClientDefault().writeValueAsString(request);

        assertThat(json).isEqualTo("{\"absent\":null}");
    }

    /**
     * Guards the reason the export keeps its own recipe. An explicit module list suppresses discovery, and the export
     * would record {@code ERROR_SERIALIZATION} instead of data.
     */
    @Test
    void wireDoesNotRegisterTheDiscoveredJdk8Module() {
        ObjectMapper wire = ObjectMapperFactory.wire();

        assertThatThrownBy(() -> wire.writeValueAsString(Map.of("present", Optional.of("value"))))
                .isInstanceOf(InvalidDefinitionException.class);
    }

    @Test
    void storageWritesADateAsTextKeepingTheOffsetItWasGiven() throws JsonProcessingException {
        ZonedDateTime at = ZonedDateTime.of(2026, 8, 21, 17, 0, 0, 0, ZoneOffset.ofHours(2));

        String json = ObjectMapperFactory.storage().writeValueAsString(Map.of("at", at));

        assertThat(json).isEqualTo("{\"at\":\"2026-08-21T17:00:00+02:00\"}");
    }

    /**
     * Left at Jackson's default, a date read back through this recipe would carry the context zone instead, reporting a
     * different wall-clock time than was written.
     */
    @Test
    void storageRoundTripsADateWithoutReZoningIt() {
        ZonedDateTime at = ZonedDateTime.of(2026, 8, 21, 17, 0, 0, 0, ZoneOffset.ofHours(2));

        ZonedDateTime converted = ObjectMapperFactory.storage().convertValue(at, ZonedDateTime.class);

        assertThat(converted).hasToString(at.toString());
        assertThat(converted.getOffset()).isEqualTo(ZoneOffset.ofHours(2));
    }

    /**
     * Discovery would unwrap {@code Optional} for every caller of {@link ObjectMapperFactory#storage()}, so the time
     * module is registered on its own.
     */
    @Test
    void storageDoesNotRegisterTheDiscoveredJdk8Module() {
        ObjectMapper storage = ObjectMapperFactory.storage();

        assertThatThrownBy(() -> storage.writeValueAsString(Map.of("present", Optional.of("value"))))
                .isInstanceOf(InvalidDefinitionException.class);
    }
}
