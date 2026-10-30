package com.otilm.core.config;

import com.otilm.core.util.AuthHelper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Lets a client cache the anonymous branding response. Branding is the one anonymous response that can be large: two
 * logos are carried inline, each bounded by the upload cap, so a fully branded instance answers every caller with a
 * couple of megabytes. Serving it from the browser cache keeps a page reload, a second tab and a back-navigation off
 * the server entirely. Caching it publicly is safe because the response is identical for every caller and carries no
 * identity.
 *
 * <p>
 * This bounds what honest traffic costs, not what a determined caller can ask for. Deliberate repetition is a matter
 * for rate limiting at the gateway, which is where the platform's other anonymous endpoints are protected too.
 */
@Configuration
public class BrandingCacheControlConfig implements WebMvcConfigurer {

    /** Short enough that an operator who changes the branding sees it on the login page within the minute. */
    private static final String BRANDING_CACHE_CONTROL = CacheControl
            .maxAge(Duration.ofMinutes(1))
            .cachePublic()
            .getHeaderValue();

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new CacheControlInterceptor()).addPathPatterns(AuthHelper.BRANDING_ENDPOINT);
    }

    private static final class CacheControlInterceptor implements HandlerInterceptor {

        @Override
        public boolean preHandle(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                @NonNull Object handler) {
            response.setHeader(HttpHeaders.CACHE_CONTROL, BRANDING_CACHE_CONTROL);
            return true;
        }
    }
}
