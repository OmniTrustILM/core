package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.signature.DocumentTransferMode;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.DocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.EmbedSignatureValueRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.EmbedTimestampRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.SignedDocumentRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.SignedDocumentResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.TimestampImprintResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.SignatureFamilyDeclarationDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.signing.contentsigning.acquisition.ContentSigningAcquisitions;
import com.otilm.core.signing.contentsigning.declaration.FamilyAlgorithms;
import com.otilm.core.signing.contentsigning.formatting.ContentSigningFormattingClient;
import com.otilm.core.signing.contentsigning.state.ContentSigningCursor;
import com.otilm.core.signing.contentsigning.state.ContentSigningTransitions;
import com.otilm.core.signing.engine.batch.BatchAdmission;
import com.otilm.core.signing.engine.batch.BatchRecordStager;
import com.otilm.core.signing.engine.certificate.SigningCertificateValidatorFactory;
import com.otilm.core.signing.engine.certificate.ValidationResult;
import com.otilm.core.signing.engine.error.ItemSigningException;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.record.SigningRecordInputSource;
import com.otilm.core.signing.record.TimestampTokenSerialNumbers;
import com.otilm.core.signing.tsa.messages.IssuedTimestamp;
import com.otilm.core.signing.tsa.messages.TimestampImprint;
import com.otilm.core.util.clocksource.ClockSource;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Drives a content-signing Signing Profile's level state machine. One forward-only run: the connector builds and
 * completes the signature, Core acquires what only Core can, and the target level picks the exit.
 */
@Component
public class ManagedContentSigningEngine {

    private static final Logger logger = LoggerFactory.getLogger(ManagedContentSigningEngine.class);

    private static final String CLIENT_MESSAGE = "Internal error during signing";

    private final ContentSigningFormattingClient formattingClient;
    private final ContentSigningAcquisitions acquisitions;
    private final SigningCertificateValidatorFactory signingCertificateValidatorFactory;
    private final ClockSource clockSource;
    private final ContentSigningRecordFactory recordFactory;
    private final BatchRecordStager recordStager;

    public ManagedContentSigningEngine(ContentSigningFormattingClient formattingClient,
            ContentSigningAcquisitions acquisitions,
            SigningCertificateValidatorFactory signingCertificateValidatorFactory, ClockSource clockSource,
            ContentSigningRecordFactory recordFactory, BatchRecordStager recordStager) {
        this.formattingClient = formattingClient;
        this.acquisitions = acquisitions;
        this.signingCertificateValidatorFactory = signingCertificateValidatorFactory;
        this.clockSource = clockSource;
        this.recordFactory = recordFactory;
        this.recordStager = recordStager;
    }

    /**
     * Signs every document of {@code request} to its target level with one call of the profile's key. It returns the
     * documents only after staging their signing records.
     *
     * @param protocol how the run was initiated, as its signing records carry it
     * @return one result per document, in request order
     */
    public List<SignedItem> sign(ContentSigningRequest request, SigningProfileModel<?, ?> signingProfile,
            ResolvedManagedContentSigningProfile profile, SigningProtocol protocol) throws SigningEngineException {
        List<BigInteger> serials = new ArrayList<>();
        try {
            return signToTargetLevel(request, signingProfile, profile, protocol, serials);
        } catch (Exception e) {
            throw loggedFailure(profile, request.targetLevel(), serials, e);
        }
    }

    private List<SignedItem> signToTargetLevel(ContentSigningRequest request, SigningProfileModel<?, ?> signingProfile,
            ResolvedManagedContentSigningProfile profile, SigningProtocol protocol, List<BigInteger> serials)
            throws SigningEngineException {
        requireSignableBatch(request, profile);
        SigningRun run = startRun(request, signingProfile, profile, protocol);
        List<ComputeDtbsResponseDto> dtbsResponses = boundDtbsResponses(run);

        List<byte[]> dtbsList = dtbsResponses.stream().map(ComputeDtbsResponseDto::getDtbs).toList();
        // The key signs only once the connector has committed to every authorized document.
        List<byte[]> signatureValues = signDtbs(run, dtbsList);

        List<CompletedDocument> documents = completeDocuments(run, dtbsResponses, signatureValues, serials);
        List<SigningRecordInputSource> recordSources = documents.stream().map(CompletedDocument::recordSource).toList();
        // Staging waits for every document to complete. A failed run thus leaves no content-signing record.
        List<UUID> recordUuids = recordStager.stage(signingProfile, recordSources);
        return signedItems(documents, recordUuids);
    }

    private void requireSignableBatch(ContentSigningRequest request, ResolvedManagedContentSigningProfile profile)
            throws SigningEngineException {
        BatchAdmission.admit(request.identifiers());
        requireReachableLevel(request.targetLevel(), profile);
        requireDeclaredCeiling(profile);
        requireAcceptedTransfer(profile.familyDeclaration(), request.transferMode());
        requireAcceptableSigningCertificate(profile);
    }

    /** Every document of the batch claims the same signing time, signature algorithm and signer chain. */
    private SigningRun startRun(ContentSigningRequest request, SigningProfileModel<?, ?> signingProfile,
            ResolvedManagedContentSigningProfile profile, SigningProtocol protocol) throws SigningEngineException {
        Instant signingTime = clockSource.wallTimeInstant();
        SignatureAlgorithm signatureAlgorithm = acquisitions.signatureAlgorithm(profile);
        requireFamilyAcceptsAlgorithm(signatureAlgorithm, profile);
        SignatureDigestCoherence.requireCoherent(signatureAlgorithm, request.digestAlgorithm());
        List<byte[]> signerChain = encodedChain(profile);
        return new SigningRun(request, signingProfile, profile, protocol, signingTime, signatureAlgorithm, signerChain);
    }

    private record SigningRun(ContentSigningRequest request, SigningProfileModel<?, ?> signingProfile,
            ResolvedManagedContentSigningProfile profile, SigningProtocol protocol, Instant signingTime,
            SignatureAlgorithm signatureAlgorithm, List<byte[]> signerChain) {
    }

    private List<ComputeDtbsResponseDto> boundDtbsResponses(SigningRun run) throws SigningEngineException {
        List<ComputeDtbsResponseDto> dtbsResponses = new ArrayList<>();
        for (ContentSigningItem item : run.request().items()) {
            dtbsResponses.add(attributingFailuresTo(item, () -> boundDtbsResponse(run, item)));
        }
        return dtbsResponses;
    }

    /** A provider failure of one item reaches the caller and the log naming its document. */
    private List<byte[]> signDtbs(SigningRun run, List<byte[]> dtbsList) throws SigningEngineException {
        try {
            return acquisitions.signDtbs(run.profile(), dtbsList);
        } catch (ItemSigningException e) {
            throw e.withItem(run.request().items().get(e.itemIndex()).identifier());
        }
    }

    private List<CompletedDocument> completeDocuments(SigningRun run, List<ComputeDtbsResponseDto> dtbsResponses,
            List<byte[]> signatureValues, List<BigInteger> serials) throws SigningEngineException {
        List<ContentSigningItem> items = run.request().items();
        List<CompletedDocument> documents = new ArrayList<>();
        for (int i = 0; i < items.size(); i++) {
            documents.add(completeDocument(run, items.get(i), dtbsResponses.get(i), signatureValues.get(i), serials));
        }
        return documents;
    }

    private CompletedDocument completeDocument(SigningRun run, ContentSigningItem item,
            ComputeDtbsResponseDto dtbsResponse, byte[] signatureValue, List<BigInteger> serials)
            throws SigningEngineException {
        SignedContent content = attributingFailuresTo(item,
                () -> completeSignature(run, item, dtbsResponse, signatureValue, serials));
        SigningRecordInputSource recordSource = recordFactory
                .source(run.signingProfile(), run.profile(), content, dtbsResponse.getDtbs(), signatureValue,
                        run.signingTime(), run.protocol());
        return new CompletedDocument(item, content, recordSource);
    }

    private record CompletedDocument(ContentSigningItem item, SignedContent content,
            SigningRecordInputSource recordSource) {
    }

    private static List<SignedItem> signedItems(List<CompletedDocument> documents, List<UUID> recordUuids) {
        boolean profileRecordsNothing = recordUuids.isEmpty();
        List<SignedItem> signed = new ArrayList<>();
        for (int i = 0; i < documents.size(); i++) {
            CompletedDocument document = documents.get(i);
            UUID recordUuid = profileRecordsNothing ? null : recordUuids.get(i);
            signed.add(new SignedItem(document.item().identifier(), document.content(), recordUuid));
        }
        return signed;
    }

    /** Lets the caller and the log name the document that broke the batch. */
    private static <T> T attributingFailuresTo(ContentSigningItem item, DocumentWork<T> work)
            throws SigningEngineException {
        try {
            return work.run();
        } catch (SigningEngineException | RuntimeException e) {
            throw asEngineFailure(e).withItem(item.identifier());
        }
    }

    @FunctionalInterface
    private interface DocumentWork<T> {
        T run() throws SigningEngineException;
    }

    private ComputeDtbsResponseDto boundDtbsResponse(SigningRun run, ContentSigningItem item)
            throws SigningEngineException {
        ComputeDtbsResponseDto dtbsResponse = requireCompleteDtbsResponse(computeDtbs(run, item));
        DtbsBindingVerifier.verify(run.request().authorizedDigestOf(item), dtbsResponse);
        return dtbsResponse;
    }

    /**
     * {@code serials} collects every timestamp serial the run issues, for the failure log. The result keeps only the
     * document's own.
     */
    private SignedContent completeSignature(SigningRun run, ContentSigningItem item,
            ComputeDtbsResponseDto dtbsResponse, byte[] signatureValue, List<BigInteger> serials)
            throws SigningEngineException {
        ContentSigningCursor cursor = advance(ContentSigningCursor.DTBS_COMPUTED,
                ContentSigningCursor.SIGNATURE_ACQUIRED);
        byte[] signedDocument = embedSignatureValue(run.profile(), dtbsResponse, signatureValue,
                run.signatureAlgorithm());
        cursor = advance(cursor, ContentSigningCursor.SIGNED);

        SignatureLevel targetLevel = run.request().targetLevel();
        int issuedBefore = serials.size();
        SignatureLevel reached = SignatureLevel.SIGNED;
        if (targetLevel != SignatureLevel.SIGNED) {
            signedDocument = applySignatureTimestamp(run.profile(), signedDocument,
                    detachedContentFor(run.request(), item), targetLevel, cursor, serials);
            reached = targetLevel;
        }
        List<BigInteger> documentSerials = List.copyOf(serials.subList(issuedBefore, serials.size()));
        return new SignedContent(signedDocument, reached, documentSerials);
    }

    /**
     * Raises a signature made elsewhere, entering the machine at the signature-timestamp imprint with {@code SIGNED} as
     * the given cursor.
     */
    public SignedContent augment(AugmentationRequest request, SigningProfileModel<?, ?> signingProfile,
            ResolvedManagedContentSigningProfile profile, SigningProtocol protocol) throws SigningEngineException {
        List<BigInteger> serials = new ArrayList<>();
        try {
            return augmentToTargetLevel(request, signingProfile, profile, protocol, serials);
        } catch (Exception e) {
            throw loggedFailure(profile, request.targetLevel(), serials, e);
        }
    }

    private SignedContent augmentToTargetLevel(AugmentationRequest request, SigningProfileModel<?, ?> signingProfile,
            ResolvedManagedContentSigningProfile profile, SigningProtocol protocol, List<BigInteger> serials)
            throws SigningEngineException {
        requireReachableLevel(request.targetLevel(), profile);
        requireDeclaredCeiling(profile);
        if (request.targetLevel() == SignatureLevel.SIGNED) {
            throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                    "augmentation to SIGNED was requested, but the document already carries a signature",
                    "The document is already signed; augmentation needs a level above SIGNED");
        }
        // No certificate or clock gate here: the profile's own key signs nothing on this path, which mints no
        // signingTime claim. The referenced TIMESTAMPING profile gates its own key and its own time.
        byte[] timestamped = applySignatureTimestamp(profile, request.signedDocument(), request.detachedContent(),
                request.targetLevel(), ContentSigningCursor.SIGNED, serials);

        SignedContent result = new SignedContent(timestamped, request.targetLevel(), serials);
        recordAugmentation(signingProfile, profile, result, protocol);
        return result;
    }

    /**
     * Both refusals name levels an operator configured, so both are safe to put on the wire. The ceiling
     * {@link ContentSigningTransitions#HIGHEST_EXECUTABLE_LEVEL} imposes is the one that moves as rungs gain steps.
     */
    private static void requireReachableLevel(SignatureLevel target, ResolvedManagedContentSigningProfile profile)
            throws SigningEngineException {
        if (!target.isWithin(profile.maxLevel())) {
            throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                    "level %s was requested but Signing Profile '%s' permits at most %s"
                            .formatted(target, profile.name(), profile.maxLevel()),
                    "Signature level %s exceeds the maximum this Signing Profile permits (%s)"
                            .formatted(target, profile.maxLevel()));
        }
        if (!target.isWithin(ContentSigningTransitions.HIGHEST_EXECUTABLE_LEVEL)) {
            throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                    "level %s was requested, which no step reaches yet".formatted(target),
                    "Signature level %s is not available yet".formatted(target));
        }
    }

    /**
     * A reconnect may have lowered the family's ceiling since the profile was saved. The declared levels have no gap,
     * so a declared ceiling covers every level beneath it.
     */
    private static void requireDeclaredCeiling(ResolvedManagedContentSigningProfile profile)
            throws SigningEngineException {
        SignatureFamilyDeclarationDto family = profile.familyDeclaration();
        boolean declared = family.getLevels().stream().anyMatch(level -> level.getLevel() == profile.maxLevel());
        if (!declared) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "Signing Profile '%s' permits up to %s, which its formatting connector no longer declares for %s"
                            .formatted(profile.name(), profile.maxLevel(), family.getLabel()),
                    CLIENT_MESSAGE);
        }
    }

    private static void requireAcceptedTransfer(SignatureFamilyDeclarationDto family, DocumentTransferMode mode)
            throws SigningEngineException {
        if (!family.getTransferModes().contains(mode)) {
            throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                    "a %s run was given transferMode %s, which %s signing does not accept"
                            .formatted(family.getLabel(), mode.getCode(), family.getLabel()),
                    clientRefusal(family.getLabel(), mode));
        }
    }

    /** States what the family needs in place of the refused mode, in the client's terms. */
    static String clientRefusal(String familyLabel, DocumentTransferMode refused) {
        String needed = switch (refused) {
            case DIGEST_ONLY -> "needs the document itself, not only its digest";
            case INLINE -> "needs only the document's digest, not the document itself";
        };
        return "%s signing %s".formatted(familyLabel, needed);
    }

    /** A reconnect may have narrowed the family's algorithms since the profile was saved. */
    private static void requireFamilyAcceptsAlgorithm(SignatureAlgorithm signatureAlgorithm,
            ResolvedManagedContentSigningProfile profile) throws SigningEngineException {
        SignatureFamilyDeclarationDto family = profile.familyDeclaration();
        if (!FamilyAlgorithms.accepts(family, signatureAlgorithm)) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "signature algorithm %s of Signing Profile '%s' is no longer accepted by the %s family"
                            .formatted(signatureAlgorithm.getCode(), profile.name(), family.getLabel()),
                    CLIENT_MESSAGE);
        }
    }

    /**
     * The Signing Profile model a run reads is cached, so a certificate revoked, expired or archived -- or a key
     * deactivated -- after profile save would otherwise still reach the key.
     */
    private void requireAcceptableSigningCertificate(ResolvedManagedContentSigningProfile profile)
            throws SigningEngineException {
        ResolvedManagedScheme signingScheme = profile.resolvedScheme();
        ValidationResult result = signingCertificateValidatorFactory
                .getValidator(signingScheme)
                .validate(signingScheme, SigningWorkflowType.CONTENT_SIGNING, false, profile.certificatePurpose());
        if (result instanceof ValidationResult.Nok nok) {
            throw new SigningEngineException(nok.failure(),
                    "signing certificate of Signing Profile '%s' is not acceptable: %s"
                            .formatted(profile.name(), nok.logMessage()),
                    CLIENT_MESSAGE);
        }
    }

    private ComputeDtbsResponseDto computeDtbs(SigningRun run, ContentSigningItem item) throws SigningEngineException {
        ResolvedManagedContentSigningProfile profile = run.profile();
        ComputeDtbsRequestDto dtbsRequest = new ComputeDtbsRequestDto();
        dtbsRequest.setFamily(profile.family());
        dtbsRequest.setSignatureParameters(run.request().signatureParameters());
        dtbsRequest.setDocument(run.request().transferOf(item));
        dtbsRequest.setFormattingAttributes(profile.signatureFormattingConnectorAttributes());
        dtbsRequest.setSignerCertificateChain(run.signerChain());
        dtbsRequest.setSigningTime(run.signingTime().atOffset(ZoneOffset.UTC));
        dtbsRequest.setSignatureAlgorithm(run.signatureAlgorithm());
        return formattingClient.computeDtbs(profile.signatureFormattingConnector(), dtbsRequest);
    }

    /**
     * Every call of the key makes a new signature, so a response the connector already left incomplete has to be
     * refused before the key signs. A missing {@code formattingContext} would otherwise surface only at
     * {@code embedSignatureValue}, by which point the signature has been made and cannot be completed.
     */
    private static ComputeDtbsResponseDto requireCompleteDtbsResponse(ComputeDtbsResponseDto response)
            throws SigningEngineException {
        if (response == null) {
            throw incompleteDtbsResponse("connector returned no computeDtbs response");
        }
        if (response.getDtbs() == null || response.getDtbs().length == 0) {
            throw incompleteDtbsResponse("connector returned no dtbs to sign");
        }
        if (response.getFormattingContext() == null) {
            throw incompleteDtbsResponse("connector returned no formattingContext to complete the signature with");
        }
        return response;
    }

    private static SigningEngineException incompleteDtbsResponse(String defect) {
        return SigningEngineException
                .stepFailed(SigningEngineFailure.CONNECTOR_FAULT, "computeDtbs", defect, null, CLIENT_MESSAGE);
    }

    /** The connector needs the CAs too: the signature embeds the chain a validator will walk. */
    private static List<byte[]> encodedChain(ResolvedManagedContentSigningProfile profile)
            throws SigningEngineException {
        List<byte[]> encoded = new ArrayList<>();
        try {
            for (X509Certificate certificate : profile.resolvedScheme().chain().chain()) {
                encoded.add(certificate.getEncoded());
            }
        } catch (CertificateEncodingException e) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "signing certificate chain of Signing Profile '%s' cannot be encoded".formatted(profile.name()), e,
                    CLIENT_MESSAGE);
        }
        return encoded;
    }

    /**
     * Replays the algorithm {@code computeDtbs} was given rather than resolving it again, so the pair cannot disagree.
     */
    private byte[] embedSignatureValue(ResolvedManagedContentSigningProfile profile,
            ComputeDtbsResponseDto dtbsResponse, byte[] signatureValue, SignatureAlgorithm signatureAlgorithm)
            throws SigningEngineException {
        EmbedSignatureValueRequestDto embed = new EmbedSignatureValueRequestDto();
        embed.setFamily(profile.family());
        embed.setFormattingAttributes(profile.signatureFormattingConnectorAttributes());
        embed.setSignatureValue(signatureValue);
        embed.setSignatureAlgorithm(signatureAlgorithm);
        embed.setFormattingContext(dtbsResponse.getFormattingContext());
        return requireSignedDocument(
                formattingClient.embedSignatureValue(profile.signatureFormattingConnector(), embed),
                "embedSignatureValue");
    }

    /**
     * Drives {@code computeSignatureTimestampImprint}, the in-process timestamp, and {@code embedSignatureTimestamp}.
     * The serial is collected because it is the only handle a completed operation has on its timestamp record.
     */
    private byte[] applySignatureTimestamp(ResolvedManagedContentSigningProfile profile, byte[] signedDocument,
            DocumentTransferDto detachedContent, SignatureLevel targetLevel, ContentSigningCursor cursor,
            List<BigInteger> serials) throws SigningEngineException {
        TimestampImprint imprint = requireImprint(
                formattingClient
                        .computeSignatureTimestampImprint(profile.signatureFormattingConnector(),
                                signedDocumentRequest(profile, signedDocument, detachedContent)),
                "computeSignatureTimestampImprint");

        IssuedTimestamp issued = acquisitions.timestampSignature(profile, imprint, "signatureTimestamp");
        serials.add(issued.serialNumber());
        ContentSigningCursor acquired = advance(cursor, ContentSigningCursor.SIG_TIMESTAMP_ACQUIRED);

        EmbedTimestampRequestDto embed = new EmbedTimestampRequestDto();
        embed.setFamily(profile.family());
        embed.setFormattingAttributes(profile.signatureFormattingConnectorAttributes());
        embed.setSignedDocument(signedDocument);
        embed.setDetachedContent(detachedContent);
        embed.setTimestampToken(issued.encoded());
        byte[] timestamped = requireSignedDocument(
                formattingClient.embedSignatureTimestamp(profile.signatureFormattingConnector(), embed),
                "embedSignatureTimestamp");
        advance(acquired, ContentSigningTransitions.exitCursorFor(targetLevel));
        return timestamped;
    }

    private static SignedDocumentRequestDto signedDocumentRequest(ResolvedManagedContentSigningProfile profile,
            byte[] signedDocument, DocumentTransferDto detachedContent) {
        SignedDocumentRequestDto request = new SignedDocumentRequestDto();
        request.setFamily(profile.family());
        request.setFormattingAttributes(profile.signatureFormattingConnectorAttributes());
        request.setSignedDocument(signedDocument);
        request.setDetachedContent(detachedContent);
        return request;
    }

    /**
     * A detached signature does not envelop what it signs, so the operation needs the content beside it — as the same
     * digest-only transfer the run started from, which is all Core ever holds for a detached format. An enveloped
     * document carries its own content, so it needs none.
     */
    private static DocumentTransferDto detachedContentFor(ContentSigningRequest request, ContentSigningItem item) {
        return request.transferMode() == DocumentTransferMode.DIGEST_ONLY ? request.transferOf(item) : null;
    }

    /**
     * A 200 carrying no imprint, or one that names no algorithm, cannot be stamped, since nothing says what to stamp or
     * what produced the digest. Caught here because {@link TimestampImprint} would otherwise fail as a bare NPE with no
     * step attribution.
     */
    private static TimestampImprint requireImprint(TimestampImprintResponseDto response, String step)
            throws SigningEngineException {
        if (response == null || response.getImprint() == null || response.getDigestAlgorithm() == null) {
            throw SigningEngineException
                    .stepFailed(SigningEngineFailure.CONNECTOR_FAULT, step, "connector returned no imprint to stamp",
                            null, CLIENT_MESSAGE);
        }
        return new TimestampImprint(response.getDigestAlgorithm(), response.getImprint());
    }

    private static byte[] requireSignedDocument(SignedDocumentResponseDto response, String step)
            throws SigningEngineException {
        if (response == null || response.getSignedDocument() == null) {
            throw SigningEngineException
                    .stepFailed(SigningEngineFailure.CONNECTOR_FAULT, step, "connector returned no signed document",
                            null, CLIENT_MESSAGE);
        }
        return response.getSignedDocument();
    }

    /**
     * Moves the run's own cursor and answers where it now is, so the caller threads the answer into the next move
     * rather than restating a constant. A move the ladder does not allow is an engine bug and fails loudly.
     */
    private static ContentSigningCursor advance(ContentSigningCursor from, ContentSigningCursor to) {
        ContentSigningTransitions.guard().requireTransition(from, to);
        return to;
    }

    /**
     * Every escape is logged, including an unchecked one from a datasource, a cache, a connector lookup or a guard:
     * without the funnel such a throw would take the run's only record of the serials it already issued with it.
     */
    private static SigningEngineException loggedFailure(ResolvedManagedContentSigningProfile profile,
            SignatureLevel targetLevel, List<BigInteger> serials, Exception e) {
        SigningEngineException failure = asEngineFailure(e);
        logFailure(profile, targetLevel, serials, failure);
        return failure;
    }

    /** The unchecked detail stays in the cause, which only the log reads; the caller gets the fixed client message. */
    private static SigningEngineException asEngineFailure(Exception e) {
        return e instanceof SigningEngineException engineFailure
                ? engineFailure
                : new SigningEngineException(SigningEngineFailure.STEP_FAILED,
                        "unexpected error during content signing", e, CLIENT_MESSAGE);
    }

    /**
     * A run that dies after the key has signed leaves no signing record, so the log line is the only trace it ever had.
     * Neither the document, the data-to-be-signed nor the signature value is log material.
     */
    private static void logFailure(ResolvedManagedContentSigningProfile profile, SignatureLevel targetLevel,
            List<BigInteger> serials, SigningEngineException e) {
        String step = e.step() != null ? e.step() : "none";
        String scope = failureScope(e);
        if (isPlatformFault(e.failure())) {
            logger
                    .error("Content signing failed for signing profile '{}' at step '{}' of {} targeting level {}, "
                            + "timestamp serials already issued {}: {}", profile.name(), step, scope, targetLevel,
                            TimestampTokenSerialNumbers.hex(serials), e.operatorMessage(), e);
        } else {
            logger
                    .warn("Refusing to sign content for signing profile '{}' at step '{}' of {} targeting level {}, "
                            + "timestamp serials already issued {}: {}", profile.name(), step, scope, targetLevel,
                            TimestampTokenSerialNumbers.hex(serials), e.operatorMessage());
        }
    }

    private static String failureScope(SigningEngineException e) {
        return e.itemIdentifier() != null ? "document '%s'".formatted(e.itemIdentifier()) : "the batch";
    }

    /** Exhaustive so that a new failure class has to choose its log level rather than inherit one. */
    private static boolean isPlatformFault(SigningEngineFailure failure) {
        return switch (failure) {
            case SIGNER_FAULT, STEP_FAILED, CONNECTOR_FAULT -> true;
            case INVALID_INPUT, MALFORMED_INPUT, MISCONFIGURED, TIME_UNAVAILABLE, BINDING_VIOLATION -> false;
        };
    }

    /**
     * An augmentation keeps its timestamped document when recording fails. A run that fails before this point leaves
     * its issued timestamp's record orphaned.
     */
    private void recordAugmentation(SigningProfileModel<?, ?> signingProfile,
            ResolvedManagedContentSigningProfile profile, SignedContent result, SigningProtocol protocol) {
        try {
            SigningRecordInputSource source = recordFactory
                    .source(signingProfile, profile, result, null, null, clockSource.wallTimeInstant(), protocol);
            recordStager.stage(signingProfile, List.of(source));
        } catch (Exception e) {
            logger
                    .error("Failed to record augmentation for signing profile '{}'; the document was timestamped "
                            + "regardless", signingProfile.name(), e);
        }
    }
}
