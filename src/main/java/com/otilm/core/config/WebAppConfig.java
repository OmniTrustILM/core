package com.otilm.core.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.dashboard.SigningRecordStatisticsPeriod;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.auth.oauth2.AuthenticationSnapshotRequestFilter;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.data.web.SortHandlerMethodArgumentResolver;
import org.springframework.format.FormatterRegistry;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.ResourceHttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebMvc
@ComponentScan("com.otilm.core.api")
public class WebAppConfig implements WebMvcConfigurer {

    @Bean(name = "jacksonObjectMapper")
    public ObjectMapper jsonObjectMapper() {
        return ObjectMapperFactory.wire();
    }

    @Override
    public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
        converters.add(new StringHttpMessageConverter());
        converters.add(new MappingJackson2HttpMessageConverter(jsonObjectMapper()));
        converters.add(new ResourceHttpMessageConverter());
        converters.add(new ScepHttpMessageConverter<>());
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
        SortHandlerMethodArgumentResolver sortResolver = new SortHandlerMethodArgumentResolver();
        sortResolver.setFallbackSort(Sort.by("id"));
        argumentResolvers.add(sortResolver);

        PageableHandlerMethodArgumentResolver pageableResolver = new PageableHandlerMethodArgumentResolver(
                sortResolver);
        pageableResolver.setMaxPageSize(100);
        pageableResolver.setFallbackPageable(PageRequest.of(0, 10));
        argumentResolvers.add(pageableResolver);
    }

    @Override
    public void addFormatters(FormatterRegistry registry) {
        registry.addConverter(new Converter<String, LocalDate>() {
            @Override
            public LocalDate convert(String source) {
                if (StringUtils.isBlank(source)) {
                    return null;
                }
                return LocalDate.parse(source);
            }
        });
        registry.addConverter(new Converter<String, LocalDateTime>() {
            @Override
            public LocalDateTime convert(String source) {
                if (StringUtils.isBlank(source)) {
                    return null;
                }
                return LocalDateTime.parse(source);
            }
        });
        registry.addConverter(new Converter<String, ZonedDateTime>() {
            @Override
            public ZonedDateTime convert(String source) {
                if (StringUtils.isBlank(source)) {
                    return null;
                }
                return ZonedDateTime.parse(source);
            }
        });
        registry.addConverter(new Converter<String, KeyAlgorithm>() {
            @Override
            public KeyAlgorithm convert(String source) {
                return KeyAlgorithm.findByCode(source);
            }
        });
        registry.addConverter(new Converter<String, SigningRecordStatisticsPeriod>() {
            @Override
            public SigningRecordStatisticsPeriod convert(String source) {
                return SigningRecordStatisticsPeriod.findByCode(source);
            }
        });
        registry
                .addConverter(String.class, OidCategory.class,
                        source -> StringUtils.isBlank(source) ? null : OidCategory.fromCode(source));
        registry
                .addConverter(String.class, SortDirection.class,
                        source -> StringUtils.isBlank(source) ? SortDirection.ASC : SortDirection.fromCode(source));
    }

    /**
     * Registered ahead of every other filter, including the Spring Security chains, so that no component can observe an
     * authentication-settings snapshot published by an earlier request on the same pooled thread.
     */
    @Bean
    public FilterRegistrationBean<AuthenticationSnapshotRequestFilter> authenticationSnapshotRequestFilter() {
        FilterRegistrationBean<AuthenticationSnapshotRequestFilter> registrationBean = new FilterRegistrationBean<>();

        registrationBean.setFilter(new AuthenticationSnapshotRequestFilter());
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(Ordered.HIGHEST_PRECEDENCE);

        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean<ApprovalExpirationFilter> approvalExpirationFilter() {
        FilterRegistrationBean<ApprovalExpirationFilter> registrationBean = new FilterRegistrationBean<>();

        registrationBean.setFilter(new ApprovalExpirationFilter());
        registrationBean.addUrlPatterns("/v1/approvals/*");
        registrationBean.setOrder(1);

        return registrationBean;
    }
}
