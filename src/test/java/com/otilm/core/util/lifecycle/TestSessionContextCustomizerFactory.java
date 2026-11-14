package com.otilm.core.util.lifecycle;

import java.util.List;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.test.context.ContextConfigurationAttributes;
import org.springframework.test.context.ContextCustomizer;
import org.springframework.test.context.ContextCustomizerFactory;
import org.springframework.test.context.MergedContextConfiguration;

/** Registers contexts before refresh while retaining one stable cache-key contribution. */
public final class TestSessionContextCustomizerFactory implements ContextCustomizerFactory {
    @Override
    public ContextCustomizer createContextCustomizer(Class<?> testClass,
            List<ContextConfigurationAttributes> attributes) {
        return TestSessionContextOwner.isEnabled() ? Registration.INSTANCE : null;
    }

    private enum Registration implements ContextCustomizer {
        INSTANCE;

        @Override
        public void customizeContext(ConfigurableApplicationContext context, MergedContextConfiguration configuration) {
            TestSessionContextOwner.register(context);
        }
    }
}
