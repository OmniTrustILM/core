package com.otilm.core.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.nimbusds.jose.JWSObject;
import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.core.acme.Problem;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.Map;
import org.springframework.http.HttpStatus;

/**
 * Class contains the static method for processing the JSON entities from ACME request.
 */
public class AcmeJsonProcessor {

    private static final ObjectMapper OBJECT_MAPPER = ObjectMapperFactory.acmeRequest();

    private static final ObjectReader REQUEST_READER = strictReader(OBJECT_MAPPER);

    private static final ObjectReader PAYLOAD_READER = strictReader(ObjectMapperFactory.acmePayload());

    private static final TypeReference<Map<String, Object>> JSON_OBJECT = new TypeReference<>() {
    };

    private static final String MALFORMED_PAYLOAD = "Request payload is malformed";

    /**
     * Class to parse the information from source JSON to the requested format
     *
     * @param sourceJson Source JSON
     * @param <T> Generic Type
     * @return JSON Objected mapped to the class required
     */
    public static <T> T generalBodyJsonParser(String sourceJson, Class<T> tClass) throws JsonProcessingException {
        return REQUEST_READER.forType(tClass).readValue(sourceJson);
    }

    /**
     * The payload of the JWS as the request of the given type. A payload that is not a JSON object, or whose members
     * have the wrong JSON types, is refused as malformed, with a fixed detail.
     */
    public static <T> T getPayloadAsRequestObject(JWSObject jwsObject, Class<T> returnType)
            throws AcmeProblemDocumentException {
        return readPayload(jwsObject, PAYLOAD_READER.forType(returnType));
    }

    /** The payload of the JWS as a JSON object. Any other payload is refused as malformed, with a fixed detail. */
    public static Map<String, Object> getPayloadAsJsonObject(JWSObject jwsObject) throws AcmeProblemDocumentException {
        return readPayload(jwsObject, PAYLOAD_READER.forType(JSON_OBJECT));
    }

    /** The refusal of a payload that is not what the endpoint reads. Its detail names nothing the client sent. */
    public static AcmeProblemDocumentException malformedPayload() {
        return new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED, MALFORMED_PAYLOAD);
    }

    /**
     * Trailing text and duplicate members are refused: text after the JSON value would be discarded, and a member
     * stated twice would collapse to its last value.
     */
    private static ObjectReader strictReader(ObjectMapper mapper) {
        return mapper
                .reader()
                .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }

    private static <T> T readPayload(JWSObject jwsObject, ObjectReader reader) throws AcmeProblemDocumentException {
        T value;
        try {
            value = reader.readValue(jwsObject.getPayload().toString());
        } catch (JsonProcessingException e) {
            throw malformedPayload();
        }
        if (value == null) {
            throw malformedPayload();
        }
        return value;
    }

}
