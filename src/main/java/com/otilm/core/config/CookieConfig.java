package com.otilm.core.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

@Configuration
public class CookieConfig {

    public static final String COOKIE_NAME = "ilm-session";

    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setCookieName(COOKIE_NAME);
        serializer.setCookiePath("/");
        return serializer;
    }

}
