package com.otilm.core.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

public class RawJsonDeserializer extends JsonDeserializer<String> {

    @Override
    public String deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
        //MODIFICATION - Changed the implementation to work with com.fasterxml.jackson.databind.JsonNode instead of org.json.JSONObject
        ObjectMapper mapper = (ObjectMapper) jp.getCodec();
        JsonNode node = mapper.readTree(jp);
        return mapper.writeValueAsString(node);
    }
}

