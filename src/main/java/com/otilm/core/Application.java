package com.otilm.core;

import java.util.Map;
import org.slf4j.MDC;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.quartz.QuartzAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.core.task.TaskDecorator;
import org.springframework.lang.NonNull;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * {@code QuartzAutoConfiguration} is excluded because the Quartz jar is on the classpath for its cron parser alone
 * ({@code CronExpressionUtil}); the scheduler service owns the running Quartz instance. Left in, Boot would start an
 * empty in-memory scheduler here: {@code spring-context-support} (via the cache starter) and {@code spring-tx} satisfy
 * its other class conditions.
 */
@SpringBootApplication(exclude = QuartzAutoConfiguration.class)
public class Application extends SpringBootServletInitializer {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(Application.class);
    }

    static class ContextCopyingDecorator implements TaskDecorator {
        @NonNull
        @Override
        public Runnable decorate(@NonNull Runnable runnable) {
            RequestAttributes context = RequestContextHolder.currentRequestAttributes();
            Map<String, String> contextMap = MDC.getCopyOfContextMap();
            return () -> {
                try {
                    RequestContextHolder.setRequestAttributes(context);
                    MDC.setContextMap(contextMap);
                    runnable.run();
                } finally {
                    MDC.clear();
                    RequestContextHolder.resetRequestAttributes();
                }
            };
        }
    }
}
