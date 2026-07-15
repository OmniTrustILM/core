# Integration tests

Every test under `com.otilm.core.integration.**` loads a Spring context and runs in one of the
CI integration jobs. Naming: `*ITest.java`. Do not place pure-unit tests here.

A test "loads a Spring context" if — walking its superclass chain — any ancestor extends
`BaseSpringBootTest` or is annotated `@SpringBootTest` (including the annotation-only
`BaseSpringBootTestNoAuth`). Pure-logic tests belong in a `*Test.java` unit class outside
this package, even when extracted from a formerly context-loading class.

Guarded by `com.otilm.core.architecture.CiTestSplitTest`.
