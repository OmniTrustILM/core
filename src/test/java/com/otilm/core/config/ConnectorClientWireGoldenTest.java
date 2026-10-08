package com.otilm.core.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.clients.ApiClientCodecs;
import com.otilm.core.util.WireGolden;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.springframework.http.codec.DecoderHttpMessageReader;
import org.springframework.http.codec.json.Jackson2JsonDecoder;
import org.springframework.web.reactive.function.client.ExchangeStrategies;

/**
 * The connector and OPA clients read and write JSON with the mapper {@link ApiClientCodecs} builds on core's classpath,
 * which can register more modules than it does on interfaces' own.
 */
class ConnectorClientWireGoldenTest {

    @Test
    void connectorClientMapperIsConfiguredAsOnThe35Line() throws IOException {
        WireGolden.assertMatches("connector-client-mapper.txt", WireGolden.fingerprint(connectorClientMapper()));
    }

    private static ObjectMapper connectorClientMapper() {
        ExchangeStrategies strategies = ExchangeStrategies
                .builder()
                .codecs(ApiClientCodecs::configureJsonCodecs)
                .build();
        return strategies
                .messageReaders()
                .stream()
                .filter(DecoderHttpMessageReader.class::isInstance)
                .map(reader -> ((DecoderHttpMessageReader<?>) reader).getDecoder())
                .filter(Jackson2JsonDecoder.class::isInstance)
                .map(decoder -> ((Jackson2JsonDecoder) decoder).getObjectMapper())
                .findFirst()
                .orElseThrow();
    }
}
