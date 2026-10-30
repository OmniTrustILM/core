package com.otilm.core.architecture;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.architecture.IdentityKeyExposureFence.AccessorCall;
import com.otilm.core.architecture.IdentityKeyExposureFence.MemberRef;
import com.otilm.core.architecture.IdentityKeyExposureFence.MethodShape;
import com.otilm.core.architecture.IdentityKeyExposureFence.TypedMember;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.CbomAssetExtractor;
import com.otilm.core.cbom.asset.identity.CryptoAssetIdentity;
import com.otilm.core.cbom.asset.identity.DocumentScope;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaField;
import com.tngtech.archunit.core.domain.JavaFieldAccess;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.domain.JavaMethodCall;
import com.tngtech.archunit.core.domain.JavaMethodReference;
import com.tngtech.archunit.core.domain.JavaType;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.core.importer.Location;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Fails the build if {@code crypto_asset.identity_key} can reach a client, a log or the search allowlist.
 *
 * <p>
 * The key is a hash over a low-entropy preimage — algorithm family, parameter set, curve. Handed the key, an attacker
 * recovers the material by dictionary attack, which is why the redaction ruling in core#2070 rests on the value never
 * leaving the database and on nothing else. Six rules, one kernel:
 *
 * <ol>
 * <li>no member naming the key may be declared in a client-facing package, the imported contract artifact
 * included;</li>
 * <li>{@code FilterField} — the search allowlist — must not name it;</li>
 * <li>no production source may name it outside persistence, and none may put it on a log line — a logger call, an MDC
 * binding, a span attribute or an exception message — not even the persistence sources that legitimately hold it;</li>
 * <li>no production class may read an accessor that returns the key or its pre-image unless its source is allowlisted
 * for that value — the rule that sees {@code extracted.key()}, which names nothing the three text rules can match;</li>
 * <li>no production method may read such an accessor and hand its value on — returned under a type that cannot register
 * a carrier, or stored in a field — unless it is itself registered as a carrier: the re-export that would make every
 * caller invisible to the rule above;</li>
 * <li>no client-facing declaration may be typed with a class that carries a carrier, directly, as a type argument, or
 * through the fields of a holder;</li>
 * <li>the MDC is written only through the registered logging façades, so the lexical rule's sink list stays the whole
 * set of places a binding can be made from.</li>
 * </ol>
 *
 * <p>
 * One pin rather than a rule: {@link #aCarriersPrintedFormOmitsWhatItCarries} prints a real instance of every type that
 * declares a carrier and checks the value is not in the output. The hand-written {@code toString} overrides on the
 * carrier records are what keeps a logged {@code Extraction} from spelling out every key and pre-image in it, and no
 * call-site rule can see a value that reaches the appender through {@code toString}.
 *
 * <p>
 * The decision procedure lives in {@link IdentityKeyExposureFence}, so {@link IdentityKeyExposureFenceSelfTest} can
 * feed it planted leaks and prove this fence is able to fail. A fence that has never been seen to fail is not evidence.
 */
@AnalyzeClasses(packages = {"com.otilm.core", "com.otilm.api"})
class IdentityKeyExposureFenceArchTest {

    private static final Path PRODUCTION_SOURCE_ROOT = Path.of("src/main/java");

    private static final Path SEARCH_ALLOWLIST = Path.of("src/main/java/com/otilm/core/enums/FilterField.java");

    @ArchTest
    static void noClientFacingDeclarationNamesTheIdentityKey(JavaClasses classes) {
        List<MemberRef> members = new ArrayList<>();
        for (JavaClass clazz : classes) {
            for (JavaField field : clazz.getFields()) {
                members.add(new MemberRef(clazz.getName(), clazz.getPackageName(), "field", field.getName()));
            }
            for (JavaMethod method : clazz.getMethods()) {
                members.add(new MemberRef(clazz.getName(), clazz.getPackageName(), "method", method.getName()));
            }
        }

        assertThat(IdentityKeyExposureFence.declaredMemberViolations(members))
                .describedAs("The crypto-asset identity key must not be declared in a model or API package: given the "
                        + "key, its low-entropy preimage falls to a dictionary attack. Keep it on the entity and its "
                        + "persistence path only.")
                .isEmpty();
    }

    @Test
    void theSearchAllowlistDoesNotOfferTheIdentityKey() throws IOException {
        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(SEARCH_ALLOWLIST, Files.readAllLines(SEARCH_ALLOWLIST, StandardCharsets.UTF_8)))
                .describedAs("FilterField is the search allowlist: an entry for the identity key would let a client "
                        + "confirm a guessed key one request at a time.")
                .isEmpty();
    }

    /**
     * An allowlist entry that names no existing file is a hole that looks like a fence: it silently stops exempting
     * anything, and — worse — hides that the source it meant to cover was moved or renamed out from under it. The
     * allowlist is a path list, so nothing but this check can tell the two apart.
     */
    @Test
    void everyAllowlistedSourceExists() {
        assertThat(IdentityKeyExposureFence.SOURCE_ALLOWLIST.keySet())
                .describedAs("each allowlisted source must still be where the allowlist says it is")
                .allSatisfy(path -> assertThat(Path.of(path)).exists());
    }

    /**
     * The text rules see words; this one sees calls. {@code Identity.key()} is named so that no regex matches it, and a
     * service reading it puts the value on a line that says nothing a text rule can catch. A method reference is a call
     * the byte code records differently -- {@code .map(ExtractedAsset::identityKey)} is how a stream would forward the
     * value -- so both are fed. Test classes are left out -- the conformance suite has to read the key to compare it --
     * through ArchUnit's own classification, the one every sibling arch test uses, so this fence and its siblings
     * cannot disagree about what is production.
     */
    @ArchTest
    static void noProductionClassReadsAKeyCarrierOutsideItsVocabulary(JavaClasses classes) {
        assertThat(IdentityKeyExposureFence.keyCarrierCallViolations(productionCalls(classes)))
                .describedAs("An accessor returning the identity key or its pre-image may be read only from the "
                        + "sources allowlisted for that value: the record component is named so that no text rule "
                        + "sees it, and a call site is the same disclosure whatever the line says.")
                .isEmpty();
    }

    /**
     * The lexical rule sees {@code MDC.put} and a call on a registered façade; it cannot see a binding made through a
     * wrapper written beside the disclosure. So the wrapper must not exist: every production {@code MDC.put} sits in a
     * registered façade, or this fails.
     */
    @ArchTest
    static void theMdcIsWrittenOnlyThroughARegisteredLoggingFacade(JavaClasses classes) {
        assertThat(IdentityKeyExposureFence.unregisteredMdcWriterViolations(productionCalls(classes)))
                .describedAs("An MDC binding is printed by every later log line of the request. The lexical rule "
                        + "treats the registered logging facades as sinks; a binding made anywhere else is a sink it "
                        + "cannot see.")
                .isEmpty();
    }

    private static List<AccessorCall> productionCalls(JavaClasses classes) {
        List<AccessorCall> calls = new ArrayList<>();
        for (JavaClass clazz : classes) {
            if (!isProductionClass(clazz)) {
                continue;
            }
            for (JavaMethodCall call : clazz.getMethodCallsFromSelf()) {
                calls.add(new AccessorCall(clazz.getName(), call.getTargetOwner().getName(), call.getName()));
            }
            for (JavaMethodReference reference : clazz.getMethodReferencesFromSelf()) {
                calls.add(new AccessorCall(clazz.getName(), reference.getTargetOwner().getName(), reference.getName()));
            }
        }
        return calls;
    }

    /**
     * The call-site rule judges who reads a carrier; this one judges what a reader does with it. A method that reads a
     * carrier and returns the value, or stores it in a field, has minted a carrier of its own under a name no text rule
     * sees, and every caller of it is then invisible to the rule above -- so it must be registered as a carrier or stop
     * handing the value on. Lambdas are methods the byte code names, so a stream forwarding the value is judged too.
     */
    @ArchTest
    static void noProductionMethodReExportsACarrierUnregistered(JavaClasses classes) {
        List<MethodShape> methods = new ArrayList<>();
        for (JavaClass clazz : classes) {
            if (!isProductionClass(clazz)) {
                continue;
            }
            for (JavaMethod method : clazz.getMethods()) {
                List<String> carriers = new ArrayList<>();
                for (JavaMethodCall call : method.getMethodCallsFromSelf()) {
                    carriers.add(call.getTargetOwner().getName() + "." + call.getName());
                }
                for (JavaMethodReference reference : method.getMethodReferencesFromSelf()) {
                    carriers.add(reference.getTargetOwner().getName() + "." + reference.getName());
                }
                List<String> written = new ArrayList<>();
                for (JavaFieldAccess access : method.getFieldAccesses()) {
                    if (access.getAccessType() == JavaFieldAccess.AccessType.SET) {
                        written.add(access.getTargetOwner().getName() + "." + access.getTarget().getName());
                    }
                }
                methods
                        .add(new MethodShape(clazz.getName(), method.getName(), method.getRawReturnType().getName(),
                                carriers, written));
            }
        }

        assertThat(IdentityKeyExposureFence.carrierReExportViolations(methods))
                .describedAs("A method handing on what a carrier gave it is a carrier: register it, so the "
                        + "call-site rule sees its readers, or do not hand the value on.")
                .isEmpty();
    }

    /**
     * The declaration rule judges member names; this one judges member types. A DTO component typed
     * {@code CryptoAssetIdentity.Identity} is called nothing fenced and is serialized by walking the record, pre-image
     * included -- and so is a DTO component typed with a holder record that has the {@code Identity} inside it, which
     * is why every scanned class's field types are handed to the kernel as a graph to follow.
     */
    @ArchTest
    static void noClientFacingDeclarationIsTypedWithACarrier(JavaClasses classes) {
        List<TypedMember> members = new ArrayList<>();
        Map<String, List<String>> fieldTypesByClass = new HashMap<>();
        for (JavaClass clazz : classes) {
            List<String> held = new ArrayList<>();
            for (JavaField field : clazz.getFields()) {
                List<String> fieldTypes = rawTypeNames(List.of(field.getType()));
                held.addAll(fieldTypes);
                members
                        .add(new TypedMember(clazz.getName(), clazz.getPackageName(), "field", field.getName(),
                                fieldTypes));
            }
            fieldTypesByClass.put(clazz.getName(), held);
            for (JavaMethod method : clazz.getMethods()) {
                List<JavaType> involved = new ArrayList<>(method.getParameterTypes());
                involved.add(method.getReturnType());
                members
                        .add(new TypedMember(clazz.getName(), clazz.getPackageName(), "method", method.getName(),
                                rawTypeNames(involved)));
            }
        }

        assertThat(IdentityKeyExposureFence.carrierTypedMemberViolations(members, fieldTypesByClass))
                .describedAs("A model or API declaration must not be typed with a class that carries the identity key "
                        + "or its pre-image, however deep: a serializer renders the record's components whatever the "
                        + "member is called.")
                .isEmpty();
    }

    private static List<String> rawTypeNames(List<JavaType> types) {
        List<String> names = new ArrayList<>();
        for (JavaType type : types) {
            for (JavaClass raw : type.getAllInvolvedRawTypes()) {
                names.add(raw.getName());
            }
        }
        return names;
    }

    /** A class with no known source is judged as production: the fence fails toward reporting, never toward silence. */
    private static boolean isProductionClass(JavaClass clazz) {
        return clazz
                .getSource()
                .map(source -> ImportOption.Predefined.DO_NOT_INCLUDE_TESTS.includes(Location.of(source.getUri())))
                .orElse(true);
    }

    /**
     * A carrier entry naming an accessor that no longer exists is the same hole as a stale allowlist path: it fences
     * nothing, reports nothing, and hides that the member it covered was renamed out from under it.
     */
    @Test
    void everyKeyCarrierAccessorExists() {
        assertThat(IdentityKeyExposureFence.KEY_CARRIER_ACCESSORS.keySet())
                .describedAs("each fenced accessor must still be declared where the carrier map says it is")
                .allSatisfy(accessor -> {
                    int dot = accessor.lastIndexOf('.');
                    Class<?> owner = Class.forName(accessor.substring(0, dot));
                    assertThat(owner.getMethod(accessor.substring(dot + 1))).isNotNull();
                });
    }

    /** A façade entry naming a class that no longer exists exempts nothing and fences nothing, silently. */
    @Test
    void everyLogSinkFacadeExists() {
        assertThat(IdentityKeyExposureFence.LOG_SINK_FACADES)
                .describedAs("each registered logging facade must still be a class")
                .allSatisfy(facade -> assertThat(Class.forName(facade)).isNotNull());
    }

    /**
     * The sink no call-site rule can see. A record prints every component, so {@code Identity} and
     * {@code ExtractedAsset} override {@code toString} by hand to leave the key and the pre-image out -- and with both
     * overrides deleted every rule above stays green while {@code LOG.info("{}", extraction)} prints
     * {@code key=6214e9…, preImage=ALG|RSA|2048||||} from a class allowlisted for nothing. So the printed form of a
     * real instance of every carrier-declaring type is checked against the values its registered carriers return, and
     * the values are required to be there to check, so the pin cannot pass on an instance that carries nothing.
     */
    @Test
    void aCarriersPrintedFormOmitsWhatItCarries() throws Exception {
        JsonNode document = new ObjectMapper()
                .readTree("{\"components\":[{\"type\":\"cryptographic-asset\",\"bom-ref\":\"fence-probe\","
                        + "\"name\":\"fence-probe-key\",\"cryptoProperties\":{\"assetType\":\"related-crypto-material\","
                        + "\"relatedCryptoMaterialProperties\":{\"type\":\"public-key\",\"value\":\"AAAA\"}}}]}");
        AssetNormalizer normalizer = new AssetNormalizer(IdentityTables.load());
        CryptoAssetIdentity identity = new CryptoAssetIdentity(normalizer);
        CryptoAssetIdentity.Identity keyed = identity
                .of(document.get("components").get(0), DocumentScope.of(document, normalizer), Set.of());
        CbomAssetExtractor.Extraction extraction = new CbomAssetExtractor(identity).extract(document);
        List<Object> instances = List
                .of(keyed, keyed.asset(), keyed.redaction(), extraction.assets().get(0), extraction);

        Set<String> reached = new LinkedHashSet<>();
        for (Object instance : instances) {
            List<String> carried = carriedValues(instance, reached);
            assertThat(carried).allSatisfy(value -> assertThat(value).isNotBlank());
            // An instance can carry nothing -- a carrier that answers an empty list contributes no value -- and that
            // is exactly why coverage below is judged on the accessors invoked rather than on the values returned.
            if (carried.isEmpty()) {
                continue;
            }
            // Each instance is compared only against what it carries: an aggregate would reject a printed form for
            // holding text a different instance happens to carry, which is not a disclosure.
            assertThat(String.valueOf(instance))
                    .describedAs("the printed form of %s must omit every value it carries",
                            instance.getClass().getName())
                    .doesNotContain(carried.toArray(String[]::new));
        }

        // Coverage is asserted over the accessors invoked, not over the values they returned: a carrier that answers
        // an empty list contributes no value, so a size check on the values passes while the accessor was never
        // reached -- and a new carrier on a type absent from `instances` would never be noticed at all.
        assertThat(reached)
                .describedAs("the probe must invoke every registered carrier, or the pin checks nothing")
                .containsExactlyInAnyOrderElementsOf(IdentityKeyExposureFence.KEY_CARRIER_ACCESSORS.keySet());
    }

    /**
     * Every value the registered carriers declared on the instance's class hand out, strings and string lists alike,
     * recording each accessor it invoked in {@code reached} so coverage is judged on the calls and not on the values.
     */
    private static List<String> carriedValues(Object instance, Set<String> reached) throws Exception {
        List<String> values = new ArrayList<>();
        String prefix = instance.getClass().getName() + ".";
        for (String accessor : IdentityKeyExposureFence.KEY_CARRIER_ACCESSORS.keySet()) {
            if (!accessor.startsWith(prefix)) {
                continue;
            }
            Method method = instance.getClass().getMethod(accessor.substring(prefix.length()));
            reached.add(accessor);
            Object value = method.invoke(instance);
            if (value instanceof Iterable<?> items) {
                items.forEach(item -> values.add(String.valueOf(item)));
            } else {
                values.add(String.valueOf(value));
            }
        }
        return values;
    }

    @Test
    void noProductionSourceNamesOrLogsTheIdentityKeyOutsidePersistence() throws IOException {
        assertThat(IdentityKeyExposureFence.sourceTreeViolations(PRODUCTION_SOURCE_ROOT))
                .describedAs("The identity key may be named only by the persistence sources that must, and may be "
                        + "logged by none of them: a bound parameter in a log line is the same disclosure as a "
                        + "response field.")
                .isEmpty();
    }
}
