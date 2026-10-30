package com.otilm.core.architecture;

import com.otilm.core.architecture.IdentityKeyExposureFence.AccessorCall;
import com.otilm.core.architecture.IdentityKeyExposureFence.MemberRef;
import com.otilm.core.architecture.IdentityKeyExposureFence.MethodShape;
import com.otilm.core.architecture.IdentityKeyExposureFence.TypedMember;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The planted-leak control for {@link IdentityKeyExposureFenceArchTest}.
 *
 * <p>
 * A green fence proves nothing unless the fence can go red. Each test here plants a leak the real scan would find and
 * asserts the kernel reports it, then plants the nearest legitimate neighbour and asserts the kernel stays silent — so
 * the fence is shown to discriminate, not merely to accept.
 *
 * <p>
 * The leaks are synthetic inputs to the kernel rather than real classes or files: a genuinely leaking DTO committed to
 * a fenced package would fail the real scan for everyone, which is not a control but a broken build.
 */
class IdentityKeyExposureFenceSelfTest {

    @Test
    void everySpellingOfTheIdentityKeyIsRecognised() {
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("identityKey")).isTrue();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("identity_key")).isTrue();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("IDENTITY_KEY")).isTrue();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("getIdentityKey")).isTrue();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("identity-key")).isTrue();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("uq_crypto_asset_identity_key")).isTrue();
    }

    /**
     * The pre-image vocabulary, which is fenced ahead of the key because the pre-image is the material itself.
     *
     * <p>
     * {@code keyedPayload} is in it for the same reason: it is the node the material pre-image is built from and it
     * keeps a producer's uncontracted members, which can be an inlined plaintext.
     */
    @Test
    void everySpellingOfThePreImageIsRecognised() {
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("preImage")).isTrue();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("pre_image")).isTrue();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("PRE_IMAGE")).isTrue();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("pre-image")).isTrue();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("getPreImage")).isTrue();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("dnPreImage")).isTrue();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("keyedPayload")).isTrue();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("keyed_payload")).isTrue();
    }

    @Test
    void unrelatedNamesAreNotRecognised() {
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("keyIdentity")).isFalse();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("identity")).isFalse();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("publicKey")).isFalse();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey(null)).isFalse();
    }

    /**
     * The two spellings the fence must <em>not</em> match, and the reason each exclusion is load-bearing.
     *
     * <p>
     * {@code PreImageSlot} is the type that renders a slot, named at roughly forty call sites: without the
     * {@code (?!slot)} lookahead the fence flags every one of them and gets turned off. {@code storedPayload} is the
     * payload that drops uncontracted members, so naming it is the correct choice — fencing the safe spelling would
     * train a reader to reach for the unsafe one.
     */
    @Test
    void theTypeNameAndTheSafePayloadAreNotTheValue() {
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("PreImageSlot")).isFalse();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("PreImageSlot.of(kind)")).isFalse();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("storedPayload")).isFalse();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("redaction.storedPayload()")).isFalse();
    }

    /**
     * An allowlist entry exempts one vocabulary, not one file.
     *
     * <p>
     * This is the hole the first attempt at core#2165 item 20 opened: allowlisting the identity calculator so it may
     * name the pre-image it builds also exempted the {@code identity_key} it produces, in the one file best placed to
     * leak that value. A persistence source naming a pre-image fails the same way in the other direction.
     */
    @Test
    void anAllowlistedFileMayNameOnlyItsOwnVocabulary() {
        Path calculator = Path.of("src/main/java/com/otilm/core/cbom/asset/identity/CryptoAssetIdentity.java");
        Path entity = Path.of("src/main/java/com/otilm/core/dao/entity/cbom/CryptoAsset.java");

        assertThat(IdentityKeyExposureFence.sourceFileViolations(calculator, List.of("String preImage = built[0];")))
                .describedAs("the identity layer builds the pre-image")
                .isEmpty();
        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(calculator, List.of("String identityKey = digest(preImage);")))
                .describedAs("and must not name the key it produces")
                .hasSize(1);
        assertThat(IdentityKeyExposureFence.sourceFileViolations(entity, List.of("private String identityKey;")))
                .describedAs("persistence holds the stored value")
                .isEmpty();
        assertThat(IdentityKeyExposureFence.sourceFileViolations(entity, List.of("private String preImage;")))
                .describedAs("and has no business holding the material")
                .hasSize(1);
    }

    /** The logging rule carries no allowlist, so an allowlisted file cannot log what it may legitimately name. */
    @Test
    void anAllowlistedFileStillMayNotLogItsOwnVocabulary() {
        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(
                        Path.of("src/main/java/com/otilm/core/cbom/asset/identity/MaterialRedaction.java"),
                        List.of("log.debug(\"keyed payload {}\", keyedPayload);")))
                .describedAs("naming it is allowed here; logging it is allowed nowhere")
                .hasSize(1);
    }

    @Test
    void aPlantedDtoFieldIsReported() {
        MemberRef planted = new MemberRef("com.otilm.core.model.cbom.CryptoAssetDto", "com.otilm.core.model.cbom",
                "field", "identityKey");

        assertThat(IdentityKeyExposureFence.declaredMemberViolations(List.of(planted)))
                .singleElement()
                .asString()
                .contains("CryptoAssetDto.identityKey");
    }

    @Test
    void aPlantedGetterInTheContractArtifactIsReported() {
        MemberRef planted = new MemberRef("com.otilm.api.model.core.cbom.CbomAssetDto", "com.otilm.api.model.core.cbom",
                "method", "getIdentityKey");

        assertThat(IdentityKeyExposureFence.declaredMemberViolations(List.of(planted))).hasSize(1);
    }

    @Test
    void theEntityMayDeclareTheIdentityKey() {
        MemberRef allowed = new MemberRef("com.otilm.core.dao.entity.cbom.CryptoAsset",
                "com.otilm.core.dao.entity.cbom", "field", "identityKey");

        assertThat(IdentityKeyExposureFence.declaredMemberViolations(List.of(allowed))).isEmpty();
    }

    @Test
    void aPlantedSearchAllowlistEntryIsReported() {
        Path searchAllowlist = Path.of("src/main/java/com/otilm/core/enums/FilterField.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(searchAllowlist, List
                        .of("    CRYPTO_ASSET_IDENTITY_KEY(Resource.CBOM, null, null, CryptoAsset_.identityKey,",
                                "            \"Identity\", SearchFieldTypeEnum.STRING),")))
                .hasSize(1);
    }

    @Test
    void aPlantedMentionInAnUnlistedSourceFileIsReported() {
        Path unlisted = Path.of("src/main/java/com/otilm/core/service/impl/CryptoAssetServiceImpl.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(unlisted, List.of("class X {", "  String identityKey = asset.key();", "}")))
                .singleElement()
                .asString()
                .contains("CryptoAssetServiceImpl.java:2")
                .contains("names the crypto-asset identity key outside persistence");
    }

    @Test
    void anAllowlistedSourceFileMayNameTheIdentityKeyButMayNotLogIt() {
        Path allowlisted = Path.of("src/main/java/com/otilm/core/service/writer/cbom/CryptoAssetWriter.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(allowlisted, List.of("  repository.upsertIdentity(identityKey);"))).isEmpty();

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(allowlisted, List.of("  logger.debug(\"keyed as {}\", identityKey);")))
                .singleElement()
                .asString()
                .contains("logs the crypto-asset identity key");
    }

    @Test
    void documentationMayExplainTheRuleButCodeMayNotNameTheKey() {
        Path unlisted = Path.of("src/main/java/com/otilm/core/enums/FilterField.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(unlisted,
                        List
                                .of("// No entry for identity_key, and there must never be one.", "/**",
                                        " * The identity key never leaves the database.", " */",
                                        "/* identityKey is fenced. */")))
                .describedAs("a comment cannot disclose a value, and the reason for the fence must be documentable; "
                        + "the block comment is opened rather than fed as a bare continuation, because a leading "
                        + "asterisk is only documentation when a block comment is actually open")
                .isEmpty();

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(unlisted, List.of("    private String identityKey; // the fenced column")))
                .describedAs("a trailing comment shares its line with code")
                .hasSize(1);
    }

    @Test
    void aWrappedLoggerCallIsAlsoReported() {
        Path allowlisted = Path.of("src/main/java/com/otilm/core/dao/entity/cbom/CryptoAsset.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(allowlisted,
                        List.of("  logger.getLogger().warn(\"identity_key={}\", this.identityKey);")))
                .hasSize(1);
    }

    /**
     * The leak a line-by-line rule cannot see: the logging call opens on one line and binds the key on another, so
     * neither line carries both halves. Reformatting must not decide whether a disclosure is reported.
     */
    @Test
    void aLoggingCallSplitAcrossLinesIsReported() {
        Path allowlisted = Path.of("src/main/java/com/otilm/core/service/writer/cbom/CryptoAssetWriter.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(allowlisted,
                        List
                                .of("  logger.debug(", "          \"keyed as {} under rule set {}\",",
                                        "          identityKey,", "          rulesetVersion);")))
                .singleElement()
                .asString()
                .contains("CryptoAssetWriter.java:3")
                .contains("logs the crypto-asset identity key");
    }

    /**
     * The converse: once a logging call has closed, an allowlisted file may go on naming the key. Without this the
     * multiline rule would swallow the rest of every file that ever logs.
     */
    @Test
    void aClosedLoggingCallDoesNotFenceTheLinesAfterIt() {
        Path allowlisted = Path.of("src/main/java/com/otilm/core/service/writer/cbom/CryptoAssetWriter.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(allowlisted,
                        List
                                .of("  logger.debug(", "          \"upserting {} assets\",", "          count);",
                                        "  repository.upsertIdentity(identityKey);")))
                .isEmpty();
    }

    /**
     * A parenthesis inside the message template must not close the call early — otherwise a leak on the next line
     * escapes by way of the punctuation in a log message.
     */
    @Test
    void aParenthesisInsideAMessageTemplateDoesNotCloseTheCall() {
        Path allowlisted = Path.of("src/main/java/com/otilm/core/service/writer/cbom/CryptoAssetWriter.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(allowlisted,
                        List.of("  logger.warn(\"merge (re-keyed) produced {}\",", "          identityKey);")))
                .singleElement()
                .asString()
                .contains("CryptoAssetWriter.java:2");
    }

    /**
     * Ordinary parenthesised code between two statements is not an open logging call. Without this the depth counter
     * would drift and fence a whole file after its first {@code if}.
     */
    @Test
    void ordinaryParenthesesAreNotMistakenForALoggingCall() {
        Path allowlisted = Path.of("src/main/java/com/otilm/core/service/writer/cbom/CryptoAssetWriter.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(allowlisted,
                        List.of("  if (asset.isPresent() && (count > 0)) {", "      apply(identityKey);", "  }")))
                .isEmpty();
    }

    /**
     * The alias table holds identity-key values -- {@code canonical_key} is a foreign key onto
     * {@code crypto_asset.identity_key} -- so the alias vocabulary is inside the fence, not beside it.
     */
    @Test
    void theAliasKeySpellingsAreRecognised() {
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("absorbedKey")).isTrue();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("canonical_key")).isTrue();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("getCanonicalKey")).isTrue();
        assertThat(IdentityKeyExposureFence.mentionsIdentityKey("CANONICAL_KEY")).isTrue();
    }

    @Test
    void aPlantedAliasKeyGetterInAClientFacingPackageIsReported() {
        MemberRef planted = new MemberRef("com.otilm.core.model.cbom.CryptoAssetAliasDto", "com.otilm.core.model.cbom",
                "method", "getCanonicalKey");

        assertThat(IdentityKeyExposureFence.declaredMemberViolations(List.of(planted))).hasSize(1);
    }

    /**
     * The dual of the leading-block-comment bypass. A continuation line whose first token is the multiplication
     * operator is not documentation, and this codebase's formatter is what puts it there.
     */
    @Test
    void aLeadingOperatorIsNotAJavadocContinuation() {
        Path allowlisted = Path.of("src/main/java/com/otilm/core/service/writer/cbom/CryptoAssetWriter.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(allowlisted,
                        List.of("  logger.debug(\"weight {}\", base", "          * scale(identityKey));")))
                .singleElement()
                .asString()
                .contains("CryptoAssetWriter.java:2");
    }

    @Test
    void aRealJavadocContinuationIsStillDocumentation() {
        Path allowlisted = Path.of("src/main/java/com/otilm/core/service/writer/cbom/CryptoAssetWriter.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(allowlisted,
                        List.of("  /**", "   * The identityKey column is set here.", "   */")))
                .describedAs("a continuation line inside an open block comment is documentation, as before")
                .isEmpty();
    }

    /**
     * A literal carrying the delimiters must not open a comment that exempts the lines after it: an exemption is the
     * one way this fence can fail without reporting anything.
     */
    @Test
    void aLiteralHoldingACommentDelimiterDoesNotOpenAComment() {
        Path allowlisted = Path.of("src/main/java/com/otilm/core/service/writer/cbom/CryptoAssetWriter.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(allowlisted,
                        List.of("  String glob = \"/*\";", "  logger.debug(\"keyed as {}\", identityKey);")))
                .singleElement()
                .asString()
                .contains("CryptoAssetWriter.java:2");
    }

    /**
     * A leading block comment used to exempt the whole line, so a commented argument line of a wrapped logging call
     * disclosed the key and reported nothing.
     */
    @Test
    void aLeadingBlockCommentDoesNotExemptTheCodeAfterIt() {
        Path allowlisted = Path.of("src/main/java/com/otilm/core/service/writer/cbom/CryptoAssetWriter.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(allowlisted, List
                        .of("  logger.debug(", "          \"keyed as {}\",", "          /* re-keyed */ identityKey);")))
                .singleElement()
                .asString()
                .contains("CryptoAssetWriter.java:3");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(allowlisted, List.of("  /* the fenced column is set below */")))
                .describedAs("a whole-line block comment is still documentation")
                .isEmpty();
    }

    /**
     * Prose in a text block can carry an unbalanced parenthesis, which used to close the depth counter early and let
     * the binding line through.
     */
    @Test
    void anUnbalancedParenthesisInATextBlockDoesNotCloseTheCall() {
        Path allowlisted = Path.of("src/main/java/com/otilm/core/service/writer/cbom/CryptoAssetWriter.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(allowlisted,
                        List
                                .of("  logger.debug(\"\"\"", "      merge steps: a) re-key b) re-elect",
                                        "      \"\"\", identityKey);")))
                .singleElement()
                .asString()
                .contains("logs the crypto-asset identity key");
    }

    /** An appender is not the only sink: stdout, a stack trace and the audit log disclose just as much. */
    @Test
    void sinksOtherThanTheLoggerAreReported() {
        Path allowlisted = Path.of("src/main/java/com/otilm/core/dao/entity/cbom/CryptoAsset.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(allowlisted, List.of("  System.out.println(identityKey);")))
                .describedAs("stdout")
                .hasSize(1);
        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(allowlisted, List.of("  auditLog.logEvent(\"keyed\", identityKey);")))
                .describedAs("the platform audit sink")
                .hasSize(1);
    }

    /**
     * The two ways a value actually reaches a log line in this codebase: an MDC binding, which every later statement of
     * the request prints, and an exception message, which whatever catches it logs. Both name only the vocabulary the
     * writer is allowlisted for, so the naming rule exempts them; neither matched the level-name pattern.
     */
    @Test
    void anMdcBindingOrAnExceptionMessageIsALogLine() {
        Path writer = Path.of("src/main/java/com/otilm/core/service/writer/cbom/CryptoAssetWriter.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(writer, List.of("  org.slf4j.MDC.put(\"identity_key\", identityKey);")))
                .describedAs("an MDC binding")
                .hasSize(1);
        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(writer, List.of("  span.setAttribute(\"asset.identity_key\", identityKey);")))
                .describedAs("a span attribute")
                .hasSize(1);
        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(writer,
                        List.of("  throw new IllegalStateException(\"duplicate identity_key \" + identityKey);")))
                .describedAs("an exception message")
                .singleElement()
                .asString()
                .contains("exception message");
        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(writer,
                        List.of("  throw new IllegalStateException(", "          \"duplicate \" + identityKey);")))
                .describedAs("wrapped across lines")
                .hasSize(1);
        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(writer, List
                        .of("  throw new ValidationException(ValidationError.create(\"identity key has invalid shape\"));")))
                .describedAs("a message naming the column and no value is the writer's own validation error")
                .isEmpty();
    }

    /**
     * The construction is the sink, not the {@code throw}. An exception built into a local, one handed to
     * {@code initCause}, and one thrown through a factory all carry the message to whatever logs it, and none of them
     * puts {@code throw new} on the disclosing line.
     */
    @Test
    void anExceptionMessageBuiltOffTheThrowLineIsALogLine() {
        Path writer = Path.of("src/main/java/com/otilm/core/service/writer/cbom/CryptoAssetWriter.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(writer, List
                        .of("  IllegalStateException failure = new IllegalStateException(\"duplicate \" + identityKey);",
                                "  throw failure;")))
                .describedAs("built into a local and thrown two lines later")
                .singleElement()
                .asString()
                .contains("CryptoAssetWriter.java:1")
                .contains("exception message");
        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(writer,
                        List.of("  throw duplicateIdentity(\"duplicate identity_key \" + identityKey);")))
                .describedAs("thrown through a factory")
                .singleElement()
                .asString()
                .contains("exception message");
        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(writer,
                        List.of("  failure.initCause(new IllegalArgumentException(identityKey));")))
                .describedAs("handed to initCause")
                .hasSize(1);
        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(writer,
                        List
                                .of("  Supplier<RuntimeException> onDuplicate = () -> new DuplicateKeyError(",
                                        "          identityKey);")))
                .describedAs("an Error, wrapped across lines")
                .singleElement()
                .asString()
                .contains("CryptoAssetWriter.java:2");
        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(writer, List.of("  repository.upsertIdentity(new IdentityKeyRow(identityKey));")))
                .describedAs("a constructed value type is not an exception")
                .isEmpty();
    }

    /**
     * The shape the code base actually uses: eighteen {@code MDC.put} sites sit behind {@code LoggingHelper}'s static
     * methods, so a value handed to one of them is bound into every later log line while the disclosing line names no
     * logger and no MDC.
     */
    @Test
    void aCallOnARegisteredLoggingFacadeIsALogLine() {
        Path writer = Path.of("src/main/java/com/otilm/core/service/writer/cbom/CryptoAssetWriter.java");

        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(writer,
                        List.of("  LoggingHelper.putLogResourceInfo(Resource.CBOM, false, identityKey, name);")))
                .singleElement()
                .asString()
                .contains("logs the crypto-asset identity key");
        assertThat(IdentityKeyExposureFence
                .sourceFileViolations(writer, List
                        .of("  com.otilm.core.logging.LoggingHelper.putAuditLogOperation(", "          identityKey);")))
                .describedAs("qualified, and wrapped across lines")
                .singleElement()
                .asString()
                .contains("CryptoAssetWriter.java:2");
    }

    /**
     * The façade list is only a sink list while it is the whole set of MDC writers, so a binding made from anywhere
     * else is refused -- a one-line {@code bind(key, value)} wrapper beside a disclosure would otherwise be the wrapper
     * shape reopened.
     */
    @Test
    void anMdcWriteOutsideARegisteredFacadeIsReported() {
        assertThat(IdentityKeyExposureFence
                .unregisteredMdcWriterViolations(List.of(new AccessorCall(WRITER, "org.slf4j.MDC", "put"))))
                .singleElement()
                .asString()
                .contains("CryptoAssetWriter")
                .contains("org.slf4j.MDC.put");
        assertThat(IdentityKeyExposureFence
                .unregisteredMdcWriterViolations(
                        List.of(new AccessorCall(WRITER + "$1", "org.slf4j.MDC", "putCloseable"))))
                .describedAs("from a nested class, judged by the class that encloses it")
                .hasSize(1);
        assertThat(IdentityKeyExposureFence
                .unregisteredMdcWriterViolations(List
                        .of(new AccessorCall("com.otilm.core.logging.LoggingHelper", "org.slf4j.MDC", "put"),
                                new AccessorCall(WRITER, "org.slf4j.MDC", "get"),
                                new AccessorCall(WRITER, "org.slf4j.MDC", "remove"))))
                .describedAs("the registered facade binds; reading or clearing the MDC binds nothing")
                .isEmpty();
    }

    // ---------------------------------------------------------------- key carriers

    private static final String IDENTITY = "com.otilm.core.cbom.asset.identity.CryptoAssetIdentity$Identity";

    private static final String EXTRACTED = "com.otilm.core.cbom.asset.identity.CbomAssetExtractor$ExtractedAsset";

    private static final String EXTRACTOR = "com.otilm.core.cbom.asset.identity.CbomAssetExtractor";

    private static final String CALCULATOR = "com.otilm.core.cbom.asset.identity.CryptoAssetIdentity";

    private static final String WRITER = "com.otilm.core.service.writer.cbom.CryptoAssetWriter";

    private static final String REDACTION = "com.otilm.core.cbom.asset.identity.MaterialRedaction";

    private static final String SERVICE = "com.otilm.core.service.impl.CryptoAssetServiceImpl";

    /**
     * The leak the text rules cannot see: {@code Identity.key()} is named so that no regex matches it, and a service
     * reading it puts the value on a line that says nothing a text rule can catch.
     */
    @Test
    void aServiceReadingAKeyCarrierIsReported() {
        assertThat(carrierViolations(SERVICE, IDENTITY, "key"))
                .singleElement()
                .asString()
                .contains("CryptoAssetServiceImpl")
                .contains("CryptoAssetIdentity$Identity.key");
        assertThat(carrierViolations(SERVICE, IDENTITY, "preImage"))
                .describedAs("the pre-image is the worse of the two")
                .hasSize(1);
        assertThat(carrierViolations(SERVICE, EXTRACTED, "identityKey"))
                .describedAs("the extracted record carries the same value on toward persistence")
                .hasSize(1);
    }

    /**
     * A call is exempt for the reason a mention is: the caller's file is allowlisted for what the accessor returns. The
     * same scoping as {@link #anAllowlistedFileMayNameOnlyItsOwnVocabulary}, applied to calls -- the extractor may take
     * the key it hands to persistence and not the material; the identity layer may read the pre-image it builds and not
     * the key it produces.
     */
    @Test
    void aCallerMayReadOnlyTheVocabularyItsFileIsAllowlistedFor() {
        assertThat(carrierViolations(EXTRACTOR, IDENTITY, "key"))
                .describedAs("the extractor hands the key to persistence")
                .isEmpty();
        assertThat(carrierViolations(EXTRACTOR, IDENTITY, "preImage"))
                .describedAs("and has no business reading the material")
                .hasSize(1);
        assertThat(carrierViolations(CALCULATOR, IDENTITY, "preImage"))
                .describedAs("the identity layer builds the pre-image")
                .isEmpty();
        assertThat(carrierViolations(CALCULATOR, IDENTITY, "key"))
                .describedAs("and must not read back the key it produces")
                .hasSize(1);
        assertThat(carrierViolations(WRITER, EXTRACTED, "identityKey"))
                .describedAs("persistence stores the value")
                .isEmpty();
        assertThat(carrierViolations(WRITER, IDENTITY, "preImage")).hasSize(1);
    }

    /**
     * The material's identity digest is a carrier under a name neither vocabulary matches.
     *
     * <p>
     * It is the unsalted SHA-256 of a possibly low-entropy secret, so a service reading it into a response has exposed
     * the material to a dictionary attack -- and {@code identityDigest} contains no fenced spelling, so before it was
     * registered nothing looked at the line at all. Its sibling {@code publishedDigest} is the safe one and stays
     * unfenced.
     */
    @Test
    void aServiceReadingTheMaterialIdentityDigestIsReported() {
        assertThat(carrierViolations(SERVICE, REDACTION, "identityDigest"))
                .singleElement()
                .asString()
                .contains("CryptoAssetServiceImpl")
                .contains("MaterialRedaction.identityDigest");
        assertThat(carrierViolations(CALCULATOR, REDACTION, "identityDigest"))
                .describedAs("the identity layer consumes it to build the material tier")
                .isEmpty();
        assertThat(carrierViolations(EXTRACTOR, REDACTION, "identityDigest"))
                .describedAs("the extractor is allowlisted for the stored value, not the material")
                .hasSize(1);
        assertThat(carrierViolations(SERVICE, REDACTION, "publishedDigest"))
                .describedAs("the withheld-or-published sibling is the one that may be served")
                .isEmpty();
    }

    /** A nested or anonymous class lives in its enclosing class's file, and the allowlist is written in files. */
    @Test
    void aNestedClassIsJudgedByTheFileThatEnclosesIt() {
        assertThat(carrierViolations(EXTRACTOR + "$Walk", IDENTITY, "key")).isEmpty();
        assertThat(carrierViolations(SERVICE + "$1", IDENTITY, "key")).hasSize(1);
        assertThat(IdentityKeyExposureFence.sourcePathOf(EXTRACTOR + "$ExtractedAsset"))
                .isEqualTo("src/main/java/com/otilm/core/cbom/asset/identity/CbomAssetExtractor.java");
    }

    /**
     * The rule is about the carrier, not about the word. An unrelated accessor called {@code key} is nobody's business,
     * and the carriers' harmless components -- the chain step, the guard -- are readable from anywhere.
     */
    @Test
    void anAccessorMerelyNamedKeyOnAnotherTypeIsNotACarrier() {
        assertThat(carrierViolations(SERVICE, "com.otilm.core.model.cbom.CipherSuiteDto", "key")).isEmpty();
        assertThat(carrierViolations(SERVICE, IDENTITY, "step")).isEmpty();
        assertThat(carrierViolations(SERVICE, EXTRACTED, "guard")).isEmpty();
    }

    private static List<String> carrierViolations(String caller, String target, String method) {
        return IdentityKeyExposureFence.keyCarrierCallViolations(List.of(new AccessorCall(caller, target, method)));
    }

    // ---------------------------------------------------------------- re-exports

    /**
     * The second hop the call-site rule cannot see: an allowlisted class reads a carrier legitimately and returns the
     * value under a name of its own, and every caller of that name is then invisible to all four rules.
     */
    @Test
    void aReExportOfACarrierFromAnAllowlistedClassIsReported() {
        assertThat(reExportViolations(EXTRACTOR, "fingerprintOf", "java.lang.String", EXTRACTED + ".identityKey"))
                .singleElement()
                .asString()
                .contains("CbomAssetExtractor.fingerprintOf")
                .contains("ExtractedAsset.identityKey");
        assertThat(reExportViolations(CALCULATOR, "describe", "java.lang.String", IDENTITY + ".preImage"))
                .describedAs("the pre-image is the worse of the two")
                .hasSize(1);
        assertThat(reExportViolations(WRITER, "lambda$store$0", "java.lang.String", EXTRACTED + ".identityKey"))
                .describedAs("a lambda forwarding the value is a method the byte code names")
                .hasSize(1);
    }

    /**
     * The rule is about a value that came from a carrier; a registered carrier, one of this code base's own types, or
     * another value is not it.
     */
    @Test
    void aMethodThatIsNotAReExportIsNotReported() {
        assertThat(reExportViolations(EXTRACTED, "identityKey", "java.lang.String", IDENTITY + ".key"))
                .describedAs("a registered carrier reading another carrier is the reviewed record of a deliberate "
                        + "hand-off -- this is the assertion that pins the registration filter")
                .isEmpty();
        assertThat(reExportViolations(EXTRACTOR, "extract", EXTRACTOR + "$Extraction", IDENTITY + ".key"))
                .describedAs(
                        "a value handed on inside a record is the extractor's contract, and its components are registered")
                .isEmpty();
        assertThat(reExportViolations(CALCULATOR, "material", CALCULATOR + "$Tier", REDACTION + ".identityDigest"))
                .describedAs("a type of this code base registers its own carriers and is judged where it appears")
                .isEmpty();
        assertThat(reExportViolations(SERVICE, "stepOf", "java.lang.String", IDENTITY + ".step"))
                .describedAs("the chain step carries nothing fenced")
                .isEmpty();
        assertThat(reExportViolations(CALCULATOR, "publicKeyDigest", "java.lang.String", CALCULATOR + "$Tier.preImage"))
                .describedAs("a private tier record is not a registered carrier")
                .isEmpty();
        assertThat(reExportViolations(WRITER, "hasKey", "boolean", EXTRACTED + ".identityKey"))
                .describedAs("a primitive cannot carry the value")
                .isEmpty();
        assertThat(reExportViolations(WRITER, "store", "void", EXTRACTED + ".identityKey"))
                .describedAs("a void method that writes no field handed nothing on")
                .isEmpty();
    }

    /**
     * The bound is the shape of the hand-off, not its depth. {@code String} was the only return type judged, so the
     * same re-export under {@code CharSequence}, {@code Object}, an {@code Optional} or a collection passed with no
     * second method needed.
     */
    @Test
    void aReExportUnderAnyTypeThatCanHoldTheValueIsReported() {
        for (String returnType : List
                .of("java.lang.CharSequence", "java.lang.Object", "java.lang.StringBuilder", "java.util.Optional",
                        "java.util.List", "java.util.Map", "java.util.stream.Stream", "[Ljava.lang.String;",
                        "com.fasterxml.jackson.databind.JsonNode")) {
            assertThat(reExportViolations(EXTRACTOR, "probe", returnType, EXTRACTED + ".identityKey"))
                    .describedAs("returned as %s", returnType)
                    .singleElement()
                    .asString()
                    .contains("CbomAssetExtractor.probe")
                    .contains(returnType);
        }
    }

    /**
     * One method split in two: a void method reads the carrier into a field, and a getter returns the field while
     * calling no carrier at all. Neither half is a {@code String}-returning re-export, so the pair passed.
     */
    @Test
    void aCarrierCapturedIntoAFieldIsReported() {
        assertThat(IdentityKeyExposureFence
                .carrierReExportViolations(List
                        .of(new MethodShape(EXTRACTOR, "probeCapture", "void", List.of(EXTRACTED + ".identityKey"),
                                List.of(EXTRACTOR + ".probeField")))))
                .singleElement()
                .asString()
                .contains("CbomAssetExtractor.probeCapture")
                .contains("CbomAssetExtractor.probeField")
                .contains("ExtractedAsset.identityKey");
        assertThat(IdentityKeyExposureFence
                .carrierReExportViolations(List
                        .of(new MethodShape(EXTRACTOR, "probeRead", "java.lang.String", List.of(),
                                List.of(EXTRACTOR + ".probeField")))))
                .describedAs("the getter half reads no carrier; the capture is what is judged")
                .isEmpty();
        assertThat(IdentityKeyExposureFence
                .carrierReExportViolations(List
                        .of(new MethodShape(EXTRACTOR, "probeBoth", "java.lang.CharSequence",
                                List.of(EXTRACTED + ".identityKey"), List.of(EXTRACTOR + ".probeField")))))
                .describedAs("a method that both stores and returns the value is reported for each")
                .hasSize(2);
    }

    /**
     * A fenced-package member typed with a carrier's class passes the name rule with nothing fenced on it, and a
     * serializer walking the record renders the component anyway.
     */
    @Test
    void aFencedMemberTypedWithACarrierIsReported() {
        String dto = "com.otilm.core.model.cbom.FencePlantDto";
        String fenced = "com.otilm.core.model.cbom";

        assertThat(typedMemberViolations(dto, fenced, "field", "detail", IDENTITY)).hasSize(1);
        assertThat(typedMemberViolations(dto, fenced, "method", "rows", "java.util.List", EXTRACTED))
                .describedAs("as a type argument")
                .hasSize(1);
        assertThat(typedMemberViolations(dto, fenced, "method", "redaction", REDACTION))
                .describedAs("the redaction carries the material's identity digest")
                .hasSize(1);
        assertThat(typedMemberViolations(dto, fenced, "field", "name", "java.lang.String")).isEmpty();
        assertThat(typedMemberViolations(dto, fenced, "field", "step", "java.util.List", "java.lang.String")).isEmpty();
        assertThat(typedMemberViolations(EXTRACTOR + "$Extraction", "com.otilm.core.cbom.asset.identity", "field",
                "assets", "java.util.List", EXTRACTED))
                .describedAs("outside a fenced package the carrier is where it belongs")
                .isEmpty();
    }

    /**
     * The one-hop ceiling: {@code record WrapDto(String name, Holder holder)} with the {@code Identity} inside
     * {@code Holder} passed, because only the member's own raw type was asked. The serializer walks the holder too.
     */
    @Test
    void aFencedMemberTypedWithAHolderOfACarrierIsReported() {
        String dto = "com.otilm.core.model.cbom.FencePlantWrapDto";
        String fenced = "com.otilm.core.model.cbom";
        String holder = "com.otilm.core.service.cbom.FencePlantHolder";
        String deeper = "com.otilm.core.service.cbom.FencePlantDeeperHolder";
        TypedMember member = new TypedMember(dto, fenced, "field", "holder", List.of(holder));

        assertThat(IdentityKeyExposureFence
                .carrierTypedMemberViolations(List.of(member), Map.of(holder, List.of("java.lang.String", IDENTITY))))
                .describedAs("one field deep")
                .hasSize(1);
        assertThat(IdentityKeyExposureFence
                .carrierTypedMemberViolations(List.of(member),
                        Map.of(holder, List.of(deeper), deeper, List.of("java.util.List", EXTRACTED))))
                .describedAs("two fields deep, through a type argument")
                .hasSize(1);
        assertThat(IdentityKeyExposureFence
                .carrierTypedMemberViolations(List.of(member),
                        Map.of(holder, List.of("java.lang.String", deeper, holder), deeper, List.of(holder))))
                .describedAs("a holder that holds itself, and nothing fenced, terminates and passes")
                .isEmpty();
        assertThat(IdentityKeyExposureFence.carrierTypedMemberViolations(List.of(member), Map.of()))
                .describedAs("a holder the scan knows nothing about holds nothing the fence knows about")
                .isEmpty();
    }

    private static List<String> reExportViolations(String owner, String method, String returnType, String... carriers) {
        return IdentityKeyExposureFence
                .carrierReExportViolations(
                        List.of(new MethodShape(owner, method, returnType, List.of(carriers), List.of())));
    }

    private static List<String> typedMemberViolations(String owner, String packageName, String kind, String name,
            String... involvedTypes) {
        return IdentityKeyExposureFence
                .carrierTypedMemberViolations(
                        List.of(new TypedMember(owner, packageName, kind, name, List.of(involvedTypes))), Map.of());
    }
}
