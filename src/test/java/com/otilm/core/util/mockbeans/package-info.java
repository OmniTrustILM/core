/**
 * Composable mock modules: {@code @TestConfiguration} classes that a test imports to mock an external boundary.
 * <p>
 * Every module here declares its mocks as {@code @Bean @Primary} context singletons, so they are shared by every test
 * sharing the cached context. Spring's own reset lifecycle does not cover them — it only walks the test class, its
 * superclasses and its enclosing classes for {@code @MockitoBean}/{@code @MockitoSpyBean}, and finds nothing on an
 * {@code @Import}ed configuration. {@code MockBeanResetListener} closes that gap, and {@code BaseSpringBootTest} is the
 * only place that registers it.
 * <p>
 * <b>An importer must therefore extend {@code BaseSpringBootTest}</b> (directly or transitively), or stubbings and
 * interactions leak between tests. {@code BaseSpringBootTestNoAuth} is a separate root that does <em>not</em> extend it
 * and so carries no listener; importing a module from there would silently lose the reset.
 * {@code MockBeanModuleResetArchTest} fails the build on either mistake.
 * <p>
 * Adding a mock here is cheap only while it reuses an existing import set — each new combination of modules is a new
 * Spring context to boot. Prefer composing the sets that tests already use.
 */
package com.otilm.core.util.mockbeans;
