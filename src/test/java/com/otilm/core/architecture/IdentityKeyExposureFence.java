package com.otilm.core.architecture;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The rule kernel behind the crypto-asset identity-key redaction fence.
 *
 * <p>
 * {@code crypto_asset.identity_key} is a hash over a low-entropy preimage: handed the key, an attacker recovers the
 * material by dictionary attack. The redaction ruling in core#2070 rests on the key never leaving the database, and on
 * nothing else. This class holds the decision procedure; {@link IdentityKeyExposureFenceArchTest} feeds it the real
 * code base and {@link IdentityKeyExposureFenceSelfTest} feeds it planted leaks, so the fence is proven able to fail.
 *
 * <p>
 * Every method is static and pure over its arguments — no classpath scanning, no file reads outside the explicit
 * {@link #sourceFileViolations(Path, List)} entry point — which is what lets the self-test exercise the same code the
 * real scan runs.
 */
final class IdentityKeyExposureFence {

    /**
     * The stored-value vocabulary: every spelling the code base can produce for a value that lives in a column.
     *
     * <p>
     * {@code identity_key} (SQL), {@code identityKey} (Java member), {@code IDENTITY_KEY} (constant),
     * {@code getIdentityKey} (accessor), {@code identity-key} (a JSON or header name). ASCII-only case folding, so the
     * verdict cannot depend on the platform locale.
     *
     * <p>
     * The alias vocabulary is fenced with it. {@code crypto_asset_alias.absorbed_key} and {@code canonical_key}
     * <em>hold identity-key values</em> — {@code canonical_key} is a foreign key onto {@code crypto_asset.identity_key}
     * — so a DTO exposing {@code canonicalKey}, a {@code FilterField} over {@code absorbedKey}, or a log line binding
     * either would ship exactly the hash whose low-entropy preimage falls to a dictionary attack, while passing a fence
     * that only knew the word "identity".
     */
    private static final String STORED_VALUE_VOCABULARY = "identity[_\\-\\s]?key|absorbed[_\\-\\s]?key"
            + "|canonical[_\\-\\s]?key";

    /**
     * The pre-image vocabulary: the spellings for the material itself, ahead of the key it hashes to.
     *
     * <p>
     * The key is one dictionary attack away from the material; the pre-image <em>is</em> the material, spelled out.
     * {@code keyedPayload} is here for the same reason: since core#2165 it is the node the material pre-image is built
     * from, and it deliberately keeps a producer's uncontracted members — which can be an inlined plaintext — because
     * R2 and R15 name the five reference fields as the whole of what may be stripped before a hash. The stored payload
     * is the one that drops them, so {@code storedPayload} is <b>not</b> fenced: naming it is the correct choice, and
     * fencing the safe spelling would train readers to reach for the unsafe one.
     *
     * <p>
     * {@code (?!slot)} excludes {@code PreImageSlot}, the type that renders a slot, from roughly forty call sites
     * across this package. The type name is not the value, and without the lookahead the fence would flag every one of
     * them and be turned off.
     *
     * <p>
     * A member called {@code key} or {@code value} alone still carries the same content past a lexical rule, and
     * fencing those spellings would flag every public key in the code base. That residual is closed for the carriers
     * this code base has by {@link #KEY_CARRIER_ACCESSORS}, which judges a call by what the accessor returns rather
     * than by the words on the line. A carrier not registered there is still outside every rule.
     */
    private static final String PRE_IMAGE_VOCABULARY = "pre[_\\-\\s]?image(?!slot)|keyed[_\\-\\s]?payload";

    /**
     * Every fenced spelling, composed from the two vocabularies so they cannot drift apart.
     *
     * <p>
     * A file's allowlist entry names the vocabulary it may use, and this pattern is what decides whether anything
     * <em>else</em> is left on the line after that vocabulary is discounted — see {@link #sourceFileViolations}.
     */
    private static final Pattern IDENTITY_KEY = Pattern
            .compile(STORED_VALUE_VOCABULARY + "|" + PRE_IMAGE_VOCABULARY, Pattern.CASE_INSENSITIVE);

    /**
     * The classes through which this code base writes the MDC. Every static method on one of them is a log sink to the
     * lexical rule, and {@link #unregisteredMdcWriterViolations} keeps the list complete by refusing an {@code MDC.put}
     * from anywhere else.
     *
     * <p>
     * The eighteen {@code MDC.put} sites in production all sit behind {@code LoggingHelper.putSourceInfo},
     * {@code putAuditLogOperation} and their siblings, so a value handed to one of those is bound into every later log
     * line of the request while the disclosing line says nothing that matches {@code MDC.put}. A one-line wrapper
     * written beside a disclosure would open the same hole again, which is what the byte-code rule closes: the wrapper
     * either registers here, and becomes a sink to the lexical rule, or it fails the build.
     */
    static final List<String> LOG_SINK_FACADES = List.of("com.otilm.core.logging.LoggingHelper");

    /**
     * {@code org.slf4j.MDC} methods that bind a value into every later log line of the thread. {@code setContextMap} is
     * not one: it restores a map that {@code put} already filled, on a thread hand-off, and binds nothing new.
     */
    private static final List<String> MDC_WRITES = List.of("org.slf4j.MDC.put", "org.slf4j.MDC.putCloseable");

    /**
     * Any call that puts a value on a log line. Deliberately loose — it matches {@code log.debug(},
     * {@code logger.warn(} and the wrapped {@code logger.getLogger().debug(} alike, because the point is to catch the
     * bound value reaching an appender, whatever the logger handle is called.
     *
     * <p>
     * An MDC or {@code ThreadContext} binding is a log line too, and the one this codebase actually writes: a value
     * bound there is printed by every log line until it is removed. So is any call on a {@link #LOG_SINK_FACADES
     * registered façade}, which is where the bindings actually happen. A span attribute or event is forwarded by the
     * tracing appender the same way. All of these were invisible to the level-name rule.
     */
    private static final Pattern LOGGING_CALL = Pattern
            .compile("\\.\\s*(trace|debug|info|warn|error|logEvent|log)\\s*\\("
                    + "|\\bSystem\\s*\\.\\s*(out|err)\\s*\\.\\s*(print|println|printf|format)\\s*\\("
                    + "|\\.\\s*printStackTrace\\s*\\("
                    + "|\\b(MDC|ThreadContext)\\s*\\.\\s*(put|putCloseable|putAll)\\s*\\(" + "|\\b("
                    + facadeSimpleNames() + ")\\s*\\.\\s*\\w+\\s*\\(" + "|\\.\\s*(setAttribute|addEvent)\\s*\\(",
                    Pattern.CASE_INSENSITIVE);

    private static String facadeSimpleNames() {
        return LOG_SINK_FACADES
                .stream()
                .map(name -> Pattern.quote(name.substring(name.lastIndexOf('.') + 1)))
                .reduce((left, right) -> left + "|" + right)
                .orElseThrow();
    }

    /**
     * The argument list of an exception's construction, or of whatever a {@code throw} statement throws. A message
     * travels to whatever catches the exception and is logged there, and {@code CryptoAssetConstraintTranslator} —
     * allowlisted for the stored value — exists to turn the unique constraint on that value into a message. Unlike a
     * logging call this is judged on the line with its literals blanked: {@code "identity key has invalid shape"} names
     * the column and states no value, where a bound variable beside it does.
     *
     * <p>
     * The construction is the sink, not the {@code throw}: an exception built into a local and thrown two lines later,
     * one handed to {@code initCause}, and one thrown through a factory — {@code throw failure(message)} — all carry
     * the message the same distance, and only the first of them puts {@code throw new} on the disclosing line. So a
     * {@code new} of anything named {@code *Exception}, {@code *Error} or {@code *Throwable} counts wherever it sits,
     * and a {@code throw} counts whatever expression follows it.
     */
    private static final Pattern EXCEPTION_MESSAGE = Pattern
            .compile(
                    "\\bthrow\\s+(?:new\\s+)?[\\w.$<>]+\\s*\\(|\\bnew\\s+[\\w.$]*(?:Exception|Error|Throwable)\\s*\\(");

    /**
     * A string or character literal, escapes included. Blanked out before parentheses are counted, so a parenthesis
     * inside a message template — {@code log.debug("(")} — cannot skew the depth that decides where a logging call
     * ends. Only the depth count sees the blanked form; the identity-key test still reads the raw line, because a key
     * named inside a string literal is exactly as disclosed as one named outside it.
     */
    private static final Pattern LITERAL = Pattern.compile("\"(\\\\.|[^\"\\\\])*\"|'(\\\\.|[^'\\\\])*'");

    /** Text-block delimiter. Checked on the raw line, before literals are blanked, which would eat it. */
    private static final String TEXT_BLOCK = "\"\"\"";

    /**
     * Packages whose declarations reach a client: the DTO/model layer, the API layer, and the imported contract
     * artifact. {@code com.otilm.api.model} is scanned too, so a future contract revision cannot land the leak in a
     * published DTO without failing this build.
     */
    private static final List<String> FENCED_PACKAGE_PREFIXES = List
            .of("com.otilm.core.model", "com.otilm.core.api", "com.otilm.api.model");

    /**
     * The production sources allowed to name a fenced value, each mapped to the <em>one vocabulary</em> it may name.
     *
     * <p>
     * <b>Scoped, not per file.</b> A bare path exemption is broader than any reason for granting it: allowlisting the
     * identity calculator so it may name the pre-image it builds would also let it name the {@code identity_key} it
     * produces, which is the single worst place in the code base to open that hole. This class said so before the entry
     * existed -- "it would have covered a future code-level mention in the one file best placed to leak the value it
     * computes" -- and the first attempt at core#2165 item 20 granted exactly that exemption anyway. A mention is
     * exempt only when the line names nothing outside its file's own vocabulary.
     *
     * <p>
     * Persistence has to name the stored value: the column, its query, its writer and the translator that recognises
     * its unique constraint by name. The identity layer has to name the pre-image: the record that carries it, and the
     * two classes that build and hash the keyed payload. Everything else naming either is a leak.
     *
     * <p>
     * The exemption covers <em>naming</em> only. The logging rule carries no allowlist, so none of these files may put
     * a fenced value in a log line.
     */
    static final Map<String, Pattern> SOURCE_ALLOWLIST = Map
            .ofEntries(storedValue("src/main/java/com/otilm/core/dao/entity/cbom/CryptoAsset.java"),
                    storedValue("src/main/java/com/otilm/core/dao/entity/cbom/CryptoAssetAlias.java"),
                    storedValue("src/main/java/com/otilm/core/dao/repository/cbom/CryptoAssetRepository.java"),
                    storedValue("src/main/java/com/otilm/core/dao/repository/cbom/CryptoAssetAliasRepository.java"),
                    storedValue("src/main/java/com/otilm/core/service/writer/cbom/CryptoAssetWriter.java"),
                    storedValue("src/main/java/com/otilm/core/service/writer/cbom/CryptoAssetAliasWriter.java"),
                    storedValue("src/main/java/com/otilm/core/dao/CryptoAssetConstraintTranslator.java"),
                    // The extractor hands the keyed asset to the persistence path, so it names the stored value
                    // for the same reason the entity does. Allowlisted rather than dodged: the record component was
                    // once called `key` purely so this regex would not see it, which is invisible to a reader where
                    // an entry is a reviewed record. Scoped, so a pre-image spelling here still fails.
                    storedValue("src/main/java/com/otilm/core/cbom/asset/identity/CbomAssetExtractor.java"),
                    preImage("src/main/java/com/otilm/core/cbom/asset/identity/CryptoAssetIdentity.java"),
                    preImage("src/main/java/com/otilm/core/cbom/asset/identity/MaterialRedaction.java"),
                    preImage("src/main/java/com/otilm/core/cbom/asset/identity/AssetNormalizer.java"));

    private static Map.Entry<String, Pattern> storedValue(String path) {
        return Map.entry(path, Pattern.compile(STORED_VALUE_VOCABULARY, Pattern.CASE_INSENSITIVE));
    }

    private static Map.Entry<String, Pattern> preImage(String path) {
        return Map.entry(path, Pattern.compile(PRE_IMAGE_VOCABULARY, Pattern.CASE_INSENSITIVE));
    }

    /**
     * The accessors that hand out a fenced value, each mapped to the vocabulary that value belongs to.
     *
     * <p>
     * Both lexical rules judge a line by the words on it, so a record component the identity chain calls {@code key}
     * carries the identity key past both: {@code extracted.key()} in a service, or bound into a log line, discloses the
     * value with nothing on the line for a regex to see. A call to one of these is therefore judged by what the
     * accessor <em>returns</em>. The caller needs the same allowlist entry it would need to write the word out -- the
     * extractor may read {@code Identity.key()} because its file is allowlisted for the stored value, and may not read
     * {@code Identity.preImage()} because it is not allowlisted for the material. {@code preImage} and
     * {@code identityKey} are lexically fenced already; they are registered so the two rules cannot disagree about
     * which members are carriers.
     *
     * <p>
     * Not the records' whole surface. {@code step()}, {@code guard()} and {@code asset()} carry nothing fenced, and
     * fencing them would flag every reader of a chain step. A new component holding either value belongs here whatever
     * it is called, and the self-test proves the map is consulted by the class and method names the byte code reports,
     * never by the caller's spelling.
     */
    static final Map<String, String> KEY_CARRIER_ACCESSORS = Map
            .of("com.otilm.core.cbom.asset.identity.CryptoAssetIdentity$Identity.key", STORED_VALUE_VOCABULARY,
                    "com.otilm.core.cbom.asset.identity.CryptoAssetIdentity$Identity.preImage", PRE_IMAGE_VOCABULARY,
                    "com.otilm.core.cbom.asset.identity.CbomAssetExtractor$ExtractedAsset.identityKey",
                    STORED_VALUE_VOCABULARY,
                    // Registered because the detector's input list now begins with the pre-image itself, so this
                    // accessor returns the dictionary-attackable string under a name no regex would read as one.
                    "com.otilm.core.cbom.asset.identity.NormalizedAsset.keyedCaseValues", PRE_IMAGE_VOCABULARY,
                    // The unsalted digest of a possibly low-entropy secret, whose own Javadoc says it must never
                    // reach a stored payload or a wire response -- and `identityDigest` matches neither vocabulary,
                    // so until it was registered any production class could read it into a DTO or a log line with
                    // nothing for either rule to see. Its sibling `publishedDigest` stays unfenced deliberately: it
                    // is the one that is safe to serve, the same split as `storedPayload` against `keyedPayload`.
                    "com.otilm.core.cbom.asset.identity.MaterialRedaction.identityDigest", PRE_IMAGE_VOCABULARY);

    private IdentityKeyExposureFence() {
    }

    /** One declared member, reduced to what the fence needs to judge it. */
    record MemberRef(String declaringClass, String packageName, String kind, String name) {

        @Override
        public String toString() {
            return declaringClass + "." + name + " (" + kind + ")";
        }
    }

    /**
     * One method call, reduced to what the fence needs to judge it. Class names are binary names -- {@code Outer$Inner}
     * -- which is how the byte code reports them.
     */
    record AccessorCall(String callerClass, String targetClass, String methodName) {

        String target() {
            return targetClass + "." + methodName;
        }
    }

    static boolean mentionsIdentityKey(String text) {
        return text != null && IDENTITY_KEY.matcher(text).find();
    }

    /**
     * Whether an allowlisted file's line names only the vocabulary that file is entitled to.
     *
     * <p>
     * The file's own vocabulary is discounted and the line re-tested, so a persistence source may say
     * {@code identityKey} and an identity source may say {@code preImage}, while either saying the other's is a
     * violation on the spot. That is what makes the entry an exemption for a reason rather than for a file.
     */
    private static boolean namesNothingBeyondItsVocabulary(Pattern exempt, String line) {
        return exempt != null && !mentionsIdentityKey(exempt.matcher(line).replaceAll(""));
    }

    static boolean isFencedPackage(String packageName) {
        return packageName != null
                && FENCED_PACKAGE_PREFIXES.stream().anyMatch(prefix -> isWithinPackage(packageName, prefix));
    }

    private static boolean isWithinPackage(String packageName, String prefix) {
        return packageName.equals(prefix) || packageName.startsWith(prefix + ".");
    }

    /**
     * Members declared in a fenced package whose name names the identity key. A getter is as much a leak as the field:
     * Jackson serialises from the getter.
     */
    static List<String> declaredMemberViolations(Collection<MemberRef> members) {
        return members
                .stream()
                .filter(member -> isFencedPackage(member.packageName()))
                .filter(member -> mentionsIdentityKey(member.name()))
                .map(member -> member + " declares the crypto-asset identity key in a client-facing package")
                .toList();
    }

    /**
     * Calls to a {@link #KEY_CARRIER_ACCESSORS key carrier} from a class whose source file is not allowlisted for the
     * vocabulary the accessor returns.
     *
     * <p>
     * The caller is judged by its source file rather than by its class so that this rule and the lexical one share a
     * single allowlist: one reviewed record says which files may hold the value, however they come to hold it.
     */
    static List<String> keyCarrierCallViolations(Collection<AccessorCall> calls) {
        return calls
                .stream()
                .filter(call -> KEY_CARRIER_ACCESSORS.containsKey(call.target()))
                .filter(call -> !mayReadCarrier(call))
                .map(call -> call.callerClass() + " reads " + call.target()
                        + "(), which hands out the crypto-asset identity key or its pre-image, from a source not "
                        + "allowlisted for that value")
                .toList();
    }

    private static boolean mayReadCarrier(AccessorCall call) {
        Pattern exempt = SOURCE_ALLOWLIST.get(sourcePathOf(call.callerClass()));
        return exempt != null && exempt.pattern().equals(KEY_CARRIER_ACCESSORS.get(call.target()));
    }

    /**
     * MDC writes from a class that is not a {@link #LOG_SINK_FACADES registered façade}.
     *
     * <p>
     * The lexical rule treats a façade's calls as log sinks, so the façade list has to be the whole set of places the
     * MDC is written from, or a wrapper beside a disclosure -- {@code bind("identity_key", identityKey)} in the writer
     * -- puts the value on every later log line and matches nothing. Registration is the reviewed record; this rule is
     * what makes the record complete.
     */
    static List<String> unregisteredMdcWriterViolations(Collection<AccessorCall> calls) {
        return calls
                .stream()
                .filter(call -> MDC_WRITES.contains(call.target()))
                .filter(call -> !LOG_SINK_FACADES.contains(outermostClass(call.callerClass())))
                .map(call -> call.callerClass() + " writes the MDC through " + call.target()
                        + "(); a binding made outside a registered logging facade is a log sink the lexical rule "
                        + "cannot see -- bind through one of " + LOG_SINK_FACADES + " or register the class there")
                .toList();
    }

    /**
     * One declared method, reduced to what the fence needs to judge a re-export: who declares it, what it returns,
     * which {@link #KEY_CARRIER_ACCESSORS carriers} it calls and which fields it writes. Class names are binary names,
     * as the byte code reports them; {@code carrierTargets} are in the {@code Outer$Inner.method} form the carrier map
     * is keyed by, and {@code writtenFields} in the same {@code Owner.field} form.
     */
    record MethodShape(String declaringClass, String name, String returnType, Collection<String> carrierTargets,
            Collection<String> writtenFields) {

        String target() {
            return declaringClass + "." + name;
        }
    }

    /**
     * One declared member and every raw type its declaration involves -- its own type or return type, its parameters,
     * and the type arguments of each -- reduced to binary class names.
     */
    record TypedMember(String declaringClass, String packageName, String kind, String name,
            Collection<String> involvedTypes) {

        @Override
        public String toString() {
            return declaringClass + "." + name + " (" + kind + ")";
        }
    }

    /**
     * Methods that read a carrier and hand its value on under a name no rule sees: through their return value, or by
     * storing it in a field.
     *
     * <p>
     * {@link #keyCarrierCallViolations} judges the call site, so one method in an allowlisted class returning
     * {@code asset.identityKey()} as {@code fingerprintOf(asset)} made every caller of {@code fingerprintOf} invisible
     * to all four rules: the allowlisted file read the carrier legitimately, and the service reading the re-export
     * named nothing fenced. A method that calls a registered carrier and returns a value is therefore itself a carrier,
     * and must be registered as one or stop returning the value -- registration is the reviewed record that the
     * re-export is deliberate, as {@code ExtractedAsset.identityKey} is.
     *
     * <p>
     * <b>This is a shape bound, not a depth bound.</b> The rule sees exactly two hand-offs, both direct: the value
     * returned, under any type that can hold a string and cannot register a carrier of its own -- {@code String},
     * {@code CharSequence}, {@code Object}, a builder, an {@code Optional}, a collection, a stream, an array, anything
     * outside this code base -- and the value written into a field, from which a second method returns it while calling
     * no carrier at all. A method returning one of this code base's own types is not judged here: that type registers
     * the accessor that carries the value, and {@link #carrierTypedMemberViolations} judges where the type may appear.
     * Nothing else is followed. A carrier value passed as an argument to another method or a constructor -- the
     * record-component shape -- needs dataflow the byte code does not hand out, so that residual is confined to methods
     * of the allowlisted classes and closed by review of those files rather than by this rule.
     */
    static List<String> carrierReExportViolations(Collection<MethodShape> methods) {
        List<String> violations = new ArrayList<>();
        for (MethodShape method : methods) {
            List<String> carriers = method
                    .carrierTargets()
                    .stream()
                    .filter(KEY_CARRIER_ACCESSORS::containsKey)
                    .sorted()
                    .toList();
            if (carriers.isEmpty() || KEY_CARRIER_ACCESSORS.containsKey(method.target())) {
                continue;
            }
            if (!method.writtenFields().isEmpty()) {
                violations
                        .add(method.target() + "() writes " + method.writtenFields().stream().sorted().toList()
                                + " after reading " + carriers + ": a carrier value stored in a field is handed out "
                                + "later by a method that reads no carrier and is invisible to every rule; keep it "
                                + "in a registered carrier's component or do not store it");
            }
            if (cannotRegisterACarrier(method.returnType())) {
                violations
                        .add(method.target() + "() returns " + method.returnType() + " after reading " + carriers
                                + ": a re-export of the crypto-asset identity key or its pre-image that no caller's "
                                + "line names; register it in KEY_CARRIER_ACCESSORS or stop returning the value");
            }
        }
        return violations;
    }

    /**
     * Whether a value of this return type could carry a fenced string without any accessor of it being registrable:
     * everything but {@code void}, a primitive, and this code base's own types.
     */
    private static boolean cannotRegisterACarrier(String returnType) {
        return !"void".equals(returnType) && !PRIMITIVE_TYPES.contains(returnType)
                && !returnType.startsWith("com.otilm.");
    }

    private static final List<String> PRIMITIVE_TYPES = List
            .of("boolean", "byte", "char", "short", "int", "long", "float", "double");

    /**
     * Members of a fenced package typed with a class that carries a carrier: one that declares a registered accessor,
     * or that holds -- through any depth of its own fields -- a class that does.
     *
     * <p>
     * {@link #declaredMemberViolations} judges member names, so {@code record Dto(String name, Identity detail)} in a
     * model package passed: nothing on it is called anything fenced. {@code Identity} and {@code ExtractedAsset} are
     * public records, and a serializer walks a record by its components and renders {@code preImage} and
     * {@code identityKey} verbatim -- the stock wire mapper refuses the empty beans behind them today, and one
     * {@code @JsonIgnoreProperties} would turn that refusal into the leak. A client-facing declaration has no business
     * being typed with the material's carrier, whatever the member is called, and wrapping the carrier in a holder
     * record moves the leak one field deeper without moving it off the wire -- which is why the member types are
     * followed through {@code fieldTypesByClass} rather than judged by their own raw type alone.
     *
     * @param fieldTypesByClass every scanned class, binary name, mapped to the raw types its fields involve; a class
     * absent from the map -- a JDK type, a third-party type -- holds nothing the fence knows about
     */
    static List<String> carrierTypedMemberViolations(Collection<TypedMember> members,
            Map<String, ? extends Collection<String>> fieldTypesByClass) {
        return members
                .stream()
                .filter(member -> isFencedPackage(member.packageName()))
                .filter(member -> member
                        .involvedTypes()
                        .stream()
                        .anyMatch(type -> carriesACarrier(type, fieldTypesByClass, new HashSet<>())))
                .map(member -> member + " is typed with a class that carries the crypto-asset identity key or its "
                        + "pre-image, in a client-facing package")
                .toList();
    }

    /** Whether the class, named in binary form, declares one of the registered carriers. */
    static boolean declaresACarrier(String className) {
        return KEY_CARRIER_ACCESSORS.keySet().stream().anyMatch(accessor -> accessor.startsWith(className + "."));
    }

    /**
     * {@link #declaresACarrier}, followed through the class's fields. {@code visited} bounds the walk: a class that
     * holds itself, directly or through a cycle, is asked once.
     */
    private static boolean carriesACarrier(String className,
            Map<String, ? extends Collection<String>> fieldTypesByClass, Set<String> visited) {
        if (!visited.add(className)) {
            return false;
        }
        if (declaresACarrier(className)) {
            return true;
        }
        Collection<String> held = fieldTypesByClass.get(className);
        return held != null && held.stream().anyMatch(type -> carriesACarrier(type, fieldTypesByClass, visited));
    }

    private static String outermostClass(String className) {
        int nested = className.indexOf('$');
        return nested < 0 ? className : className.substring(0, nested);
    }

    /**
     * The repository-relative source file a class was compiled from. The outermost class decides: a nested class, an
     * anonymous class and a lambda's synthetic host all live in the file of the class enclosing them, and the allowlist
     * is written in files.
     */
    static String sourcePathOf(String className) {
        return "src/main/java/" + outermostClass(className).replace('.', '/') + ".java";
    }

    /**
     * Violations in one production source file: the identity key named at all outside {@link #SOURCE_ALLOWLIST}, or
     * named anywhere inside a logging call in any file at all. The logging rule carries no allowlist — the files that
     * legitimately hold the value are exactly the files from which it could reach an appender.
     *
     * <p>
     * A logging call is tracked across lines by parenthesis depth, not matched line by line. A formatter is free to put
     * {@code logger.debug(} on one line and the bound argument on the next, and a rule that only looked at single lines
     * would let that formatting decide whether the leak is reported — which would make the acceptance criterion a
     * property of the code style rather than of the code.
     *
     * @param repoRelativePath the file's path relative to the repository root, with {@code /} separators
     * @param lines the file's lines, 1-based in the reported message
     */
    static List<String> sourceFileViolations(Path repoRelativePath, List<String> lines) {
        String path = repoRelativePath.toString().replace('\\', '/');
        Pattern exempt = SOURCE_ALLOWLIST.get(path);
        List<String> violations = new ArrayList<>();
        int openLoggingParens = 0;
        int openThrowParens = 0;
        boolean inTextBlock = false;
        boolean inBlockComment = false;
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            boolean documentation = isDocumentation(line, inBlockComment);
            inBlockComment = blockCommentStateAfter(line, inBlockComment);
            if (documentation) {
                continue;
            }
            // A text block spans lines, so its body is not a literal this line's regex can blank, and its prose can
            // carry an unbalanced ')' -- "steps: a) ... b) ..." -- which would close an open logging call early and
            // let the binding line through. Only the code outside the delimiters counts: the head of the line that
            // opens one (which is where `logger.debug(` sits) and the tail of the line that closes it (which is where
            // the bound argument sits).
            int delimiter = line.indexOf(TEXT_BLOCK);
            String countable;
            if (delimiter < 0) {
                countable = inTextBlock ? "" : line;
            } else if (inTextBlock) {
                inTextBlock = false;
                countable = line.substring(delimiter + TEXT_BLOCK.length());
            } else {
                inTextBlock = true;
                countable = line.substring(0, delimiter);
            }
            String code = LITERAL.matcher(countable).replaceAll("\"\"");
            boolean insideLoggingCall = openLoggingParens > 0 || LOGGING_CALL.matcher(code).find();
            boolean insideThrow = openThrowParens > 0 || EXCEPTION_MESSAGE.matcher(code).find();
            if (mentionsIdentityKey(line)) {
                if (insideLoggingCall) {
                    violations.add(path + ":" + (i + 1) + " logs the crypto-asset identity key: " + line.strip());
                } else if (insideThrow && mentionsIdentityKey(code)) {
                    violations
                            .add(path + ":" + (i + 1) + " puts the crypto-asset identity key in an exception message: "
                                    + line.strip());
                } else if (!namesNothingBeyondItsVocabulary(exempt, line)) {
                    violations
                            .add(path + ":" + (i + 1) + " names the crypto-asset identity key outside persistence: "
                                    + line.strip());
                }
            }
            openLoggingParens = remainingParens(LOGGING_CALL, code, openLoggingParens);
            openThrowParens = remainingParens(EXCEPTION_MESSAGE, code, openThrowParens);
        }
        return violations;
    }

    /**
     * How many parentheses of a sink call are still open at the end of this line, given how many were open at its
     * start. Counting begins at the {@code (} of the call and stops when that call closes, so ordinary parenthesised
     * code between two sink statements is never mistaken for an open call.
     *
     * <p>
     * A count that drifts can only drift toward reporting more, never less: an unbalanced line leaves the call open and
     * keeps the following lines under the sink's rule, which is the direction a fence should fail in.
     */
    private static int remainingParens(Pattern sink, String code, int carriedDepth) {
        Matcher call = sink.matcher(code);
        int depth = carriedDepth;
        int callOpensAt = call.find() ? call.end() - 1 : -1;
        for (int i = 0; i < code.length(); i++) {
            if (depth == 0) {
                if (callOpensAt < 0) {
                    return 0;
                }
                if (i < callOpensAt) {
                    continue;
                }
            }
            char character = code.charAt(i);
            if (character == '(') {
                depth++;
            } else if (character == ')') {
                depth--;
            }
            if (depth <= 0) {
                depth = 0;
                callOpensAt = call.find(i + 1) ? call.end() - 1 : -1;
            }
        }
        return depth;
    }

    /**
     * Whether the line is documentation rather than code. A comment cannot disclose a value, and the reason the key is
     * fenced is exactly what a comment must be free to explain -- a rule that forbade naming it in prose would forbid
     * documenting the rule. Only whole comment lines are exempt: a trailing comment shares its line with code, and a
     * string literal containing a double slash must not be able to hide the rest of its line.
     *
     * <p>
     * Whether a line continues a block comment is a fact about the lines before it, not about its own first character.
     * Reading a leading {@code *} as documentation exempted a legal continuation line whose first token is the
     * multiplication operator -- and this codebase's formatter puts operators at line starts, so
     * {@code * scale(identityKey));} as the argument line of a wrapped logging call scored nothing at all. That is the
     * dual of the leading-block-comment bypass, one token over, so the fix is the one that closes the family: carry the
     * state rather than infer it, as the text-block tracking above already does.
     */
    static boolean isDocumentation(String line, boolean inBlockComment) {
        String trimmed = line.strip();
        if (inBlockComment) {
            return closesWithNothingAfterIt(trimmed);
        }
        if (trimmed.startsWith("//")) {
            return true;
        }
        // A line opening a block comment is documentation only if nothing follows the comment's close. Treating any
        // /*-starting line as a comment exempted the whole line, so `/* re-keyed */ asset.getIdentityKey());` -- a
        // legal argument line of a wrapped logging call -- was reported as nothing at all.
        return trimmed.startsWith("/*") && closesWithNothingAfterIt(trimmed);
    }

    private static boolean closesWithNothingAfterIt(String trimmed) {
        int close = trimmed.indexOf("*/");
        return close < 0 || trimmed.substring(close + 2).isBlank();
    }

    /**
     * Whether a block comment is open at the end of this line, given whether one was open at its start.
     *
     * <p>
     * String literals are blanked first, so a literal containing the delimiters cannot open a comment that swallows the
     * lines after it. That direction matters more than the other: a falsely opened comment exempts what follows, and an
     * exemption is the one way this fence can fail without saying so.
     */
    static boolean blockCommentStateAfter(String line, boolean inBlockComment) {
        String code = LITERAL.matcher(line).replaceAll("\"\"");
        boolean open = inBlockComment;
        for (int i = 0; i < code.length() - 1; i++) {
            if (!open && code.startsWith("/*", i)) {
                open = true;
                i++;
            } else if (open && code.startsWith("*/", i)) {
                open = false;
                i++;
            }
        }
        return open;
    }

    /**
     * Every violation across a production source tree. {@code sourceRoot} is resolved against the working directory,
     * which Maven sets to the module root, so the walked paths are already the repository-relative form the allowlist
     * is written in.
     */
    static List<String> sourceTreeViolations(Path sourceRoot) throws IOException {
        if (!Files.isDirectory(sourceRoot)) {
            throw new IllegalStateException("Production source root not found: " + sourceRoot.toAbsolutePath());
        }
        List<String> violations = new ArrayList<>();
        try (Stream<Path> files = Files.walk(sourceRoot)) {
            for (Path file : files.filter(path -> path.toString().endsWith(".java")).sorted().toList()) {
                violations.addAll(sourceFileViolations(file, Files.readAllLines(file, StandardCharsets.UTF_8)));
            }
        }
        return violations;
    }
}
