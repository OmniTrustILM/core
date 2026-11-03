# Test style

New and changed test methods follow this style, even in a file whose other tests do not. Restyle the rest of a file only when the task asks for it, so a diff stays about its change.

`TestStyleArchTest` enforces the mechanical part of this style with freezing rules: a departure recorded in its store passes, and a new one, including one in a renamed or moved test, fails the build.

## Shape of a test

```java
@Test
void returnsPolicy_whenRequestNamesOne() throws Exception {
    // given
    var requestedPolicyOid = "1.2.3.4.5";
    var body = aRawTspRequest().withPolicyOid(requestedPolicyOid).build();

    // when
    TspRequest parsed = TspRequestParser.parse(body);

    // then
    assertThat(parsed.policy().orElseThrow()).isEqualTo(requestedPolicyOid);
}

@Test
void throwsUnsupported_whenListingTheWholeToken() {
    // given
    var token = mock(TokenInstanceBasicModel.class);

    // when
    ThrowingCallable listKeys = () -> adapter.listKeys(token);

    // then
    assertThatThrownBy(listKeys).isInstanceOf(UnsupportedOperationException.class);
    verifyNoInteractions(client, token);
}
```

- A test body has `// given`, `// when` and `// then` blocks separated by blank lines. With nothing to arrange, `// given — <the state that exists or is absent>` names what the test relies on.
- An exception test binds the call to a `ThrowingCallable` named after it in `// when` and asserts it with `assertThatThrownBy` in `// then`, which may go on to check interactions or state.
- Assertions use AssertJ through static imports of `assertThat` and `assertThatThrownBy`. A message check uses `hasMessageContaining`, and other exception state, such as an error code, is checked inside `isInstanceOfSatisfying(...)`, which hands the check the exception as its own type.
- The result under test keeps its explicit type; arrange-side locals may use `var` where the right-hand side shows the type.
- The value that drives the scenario is bound to a local named for why it matters (`tooShortForSha256`, `unknownDigestOid`), and `// then` asserts against that local. A multi-KB literal (base64, PEM) becomes a `private static final` constant.
- A test method declares `throws Exception` when its body makes checked calls and omits the clause otherwise.

## One behaviour per test

- A test checks one behaviour. A second `// when`, or a name joining two behaviours with "And", means a second test. Many assertions on one action, or a long arrangement, are still one behaviour.
- A sequence stays in one test only when a step depends on an earlier step's effect, such as a rejection that turns into acceptance after a state change. An outcome that is a pure function of its inputs is arranged directly, in separate tests or one `@ParameterizedTest`.
- Splitting an existing test carries over every assertion that relied on an earlier step: a rejection still asserts the state is unchanged, and a "replace" or "clear" test arranges the existing state first. Derive the preconditions from the production code and run the suite, since a wrong precondition still compiles.

## Names

- Test methods are named for the behaviour they check, starting with what the system does: `throwsNotFound_whenTspProfileDoesNotExist`, `returnsGrantedToken_whenAllDependenciesSucceed`, `asksAgain_afterTheLoaderFailed`. The usual shape is `verb_outcome_whenCondition`, whose condition opens with whatever word reads best and drops out when the enclosing `@Nested` class already says it.
- Tests sharing a method-under-test prefix such as `listKeys_throws…` usually form a group: a `@Nested` class named after the method, where each name starts with the verb.
- Lifecycle methods are named for what they arrange or release: `createCertificate()`, `stubHappyPathCollaborators()`, `stopMockServer()`.

## Layout of a class

- `@Nested` classes are one level deep, named in PascalCase after what they group (`SigningCertificateGate`), and used only when a class has more than one group. A small class groups by method under test; a large one groups by theme once one group per method would leave many tiny groups. Each nested class may have its own `@BeforeEach`.
- Tests come first, and each helper sits at the bottom of the class whose tests use it; one that several nested classes share goes in the outer class, after the last of them. A separator line filled to about 80 characters opens the helpers block and each nested class, labelled `Helpers` or with the nested class's name:

  ```java
  // ── Helpers ───────────────────────────────────────────────────────────────
  ```

- A helper that touches only its parameters is `private static`, and one that calls injected beans is `private`. Helpers are named as verb phrases (`verifyRequest(...)`). A multi-line check that several tests share becomes a `private static void assertXxx(...)` named after the expected state.
- A `@MethodSource` factory sits with the helpers but is named for the cases it returns (`invalidSelections()`), and a case whose bare value leaves its purpose unclear is wrapped as `named("private key may be exported", KeyType.PRIVATE_KEY)`.

## Spring and Mockito

- A test that needs the application context extends `BaseSpringBootTest`, directly or through a base such as `BaseComplianceTest`, and takes its `@SpringBootTest` from there. Its `@Import` brings in modules from `util/mockbeans`; "The cost of a new test-context combination" in CLAUDE.md says when a module fits and when a `@MockitoBean` does.
- A test class without the context uses `@ExtendWith(MockitoExtension.class)` and `@Mock`; an existing class that builds its mocks with `mock()` switches only in a restyle of the whole class, since the extension's strict stubbing reaches every test in it.
- `@InjectMocks` is for a class whose collaborators are all mocks, since it passes null for any it cannot match. With real collaborators, a named `@BeforeEach` calls the constructor.

## Test data

- Domain objects come from builders, most in `util/builders` and some beside their package's tests: static-import the `aXxx()` entry point and override only the field the scenario is about, so the defaults carry the rest.
- Persisted setup and entity graphs come from seeders in `util/seeders`, ready material such as key pairs and DER envelopes from `XxxFixtures` classes, and connector doubles from `util/mocks`, chaining only the `stubXxx(...)` calls the scenario needs.
- Search those places before writing a new builder, seeder, fixture or mock, and follow `.claude/rules/test-support.md` when writing one.
