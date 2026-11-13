package com.otilm.core.config;

import com.otilm.api.model.core.est.EstPaths;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.orm.jpa.support.OpenEntityManagerInViewInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Keeps the EntityManager of a request open until its response is written, as {@code spring.jpa.open-in-view} does, for
 * every endpoint except those of EST. The interceptor and its registration are those that Spring Boot makes for that
 * property, which is off, and Spring Boot makes none while this interceptor exists. An EST enrolment can wait for its
 * certificate, and an EntityManager that a request keeps open holds the connection that its first read took until the
 * response is written.
 */
@Configuration(proxyBeanMethods = false)
public class OpenEntityManagerInViewConfig {

    private static final String EST_PATHS = EstPaths.BASE + "/**";

    @Bean
    public OpenEntityManagerInViewInterceptor openEntityManagerInViewInterceptor() {
        return new OpenEntityManagerInViewInterceptor();
    }

    @Bean
    public WebMvcConfigurer openEntityManagerInViewInterceptorConfigurer(
            OpenEntityManagerInViewInterceptor interceptor) {
        return new WebMvcConfigurer() {

            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                registry.addWebRequestInterceptor(interceptor).excludePathPatterns(EST_PATHS);
            }
        };
    }
}
