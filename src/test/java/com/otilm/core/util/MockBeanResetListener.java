package com.otilm.core.util;

import org.mockito.Mockito;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.TestExecutionListener;

/**
 * Resets every already-instantiated singleton mock in the test context before each test method.
 *
 * <p>Spring's standard reset lifecycle only covers {@code @MockitoBean}/{@code @MockitoSpyBean}
 * discovered by walking the test class, its superclasses, and enclosing classes — NOT mocks declared
 * on an {@code @Import}ed {@code @TestConfiguration}. Without this, a composed mock leaks stubbings
 * and interactions across tests that share a cached context. Runs before {@code @BeforeEach}, so
 * stubs set up there survive; touches only created singletons, so no lazy bean is forced.
 */
public class MockBeanResetListener implements TestExecutionListener {

    @Override
    public void beforeTestMethod(TestContext testContext) {
        if (!(testContext.getApplicationContext() instanceof ConfigurableApplicationContext ctx)) {
            return;
        }
        ConfigurableListableBeanFactory beanFactory = ctx.getBeanFactory();
        for (String name : beanFactory.getBeanDefinitionNames()) {
            if (!beanFactory.containsSingleton(name)) {
                continue;
            }
            Object bean = beanFactory.getSingleton(name);
            if (bean != null && Mockito.mockingDetails(bean).isMock()) {
                Mockito.reset(bean);
            }
        }
    }
}
