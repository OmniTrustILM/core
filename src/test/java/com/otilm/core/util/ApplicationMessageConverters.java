package com.otilm.core.util;

import com.otilm.core.config.WebAppConfig;
import java.util.ArrayList;
import java.util.List;
import org.springframework.http.converter.HttpMessageConverter;

/**
 * The message converters {@link WebAppConfig} gives the application, for a standalone MockMvc. Spring 7's standalone
 * default reads JSON with Jackson 3, which ignores the DTOs' Jackson 2 annotations.
 */
public final class ApplicationMessageConverters {

    private ApplicationMessageConverters() {
    }

    public static HttpMessageConverter<?>[] get() {
        List<HttpMessageConverter<?>> converters = new ArrayList<>();
        new WebAppConfig().configureMessageConverters(converters);
        return converters.toArray(new HttpMessageConverter<?>[0]);
    }
}
