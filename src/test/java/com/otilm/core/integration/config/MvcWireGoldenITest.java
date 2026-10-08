package com.otilm.core.integration.config;

import com.otilm.core.serialization.golden.WireGolden;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class MvcWireGoldenITest extends BaseSpringBootTest {

    @Autowired
    private RequestMappingHandlerAdapter handlerAdapter;

    @Test
    void jsonResponsesUseTheJackson2MapperOfThe35Line() {
        HttpMessageConverter<?> json = handlerAdapter
                .getMessageConverters()
                .stream()
                .filter(converter -> converter.canWrite(Map.class, MediaType.APPLICATION_JSON))
                .findFirst()
                .orElseThrow();
        MappingJackson2HttpMessageConverter jackson2 = assertInstanceOf(MappingJackson2HttpMessageConverter.class,
                json);
        WireGolden.assertFingerprintMatches("mvc-mapper.txt", jackson2.getObjectMapper());
    }
}
