package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.DigestOnlyDocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.DocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.EmbedSignatureValueRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.EmbedTimestampRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.SignedDocumentRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.SignedDocumentResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.TimestampImprintResponseDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.signing.contentsigning.acquisition.ContentSigningAcquisitions;
import com.otilm.core.signing.contentsigning.formatting.ComputeDtbsRequests;
import com.otilm.core.signing.contentsigning.formatting.ContentSigningFormattingClient;
import com.otilm.core.signing.contentsigning.state.ContentSigningCursor;
import com.otilm.core.signing.contentsigning.state.ContentSigningTransitions;
import com.otilm.core.signing.engine.certificate.SigningCertificateValidatorFactory;
import com.otilm.core.signing.engine.certificate.ValidationResult;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.record.SigningRecordInputSource;
import com.otilm.core.signing.record.SigningRecordStrategyFactory;
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
    private final SigningRecordStrategyFactory signingRecordStrategyFactory;
    private final ContentSigningRecordFactory recordFactory;

    public ManagedContentSigningEngine(ContentSigningFormattingClient formattingClient,
            ContentSigningAcquisitions acquisitions,
            SigningCertificateValidatorFactory signingCertificateValidatorFactory, ClockSource clockSource,
            SigningRecordStrategyFactory signingRecordStrategyFactory, ContentSigningRecordFactory recordFactory) {
        this.formattingClient = formattingClient;
        this.acquisitions = acquisitions;
        this.signingCertificateValidatorFactory = signingCertificateValidatorFactory;
        this.clockSource = clockSource;
        this.signingRecordStrategyFactory = signingRecordStrategyFactory;
        this.recordFactory = recordFactory;
    }

    /**
     * Signs {@code request}'s document to its target level.
     *
     * @param protocol how the run was initiated, which is what its signing record will carry
     */
    public SignedContent sign(ContentSigningRequest request, SigningProfileModel<?, ?> signingProfile,
            ResolvedManagedContentSigningProfile profile, SigningProtocol protocol) throws SigningEngineException {
        List<BigInteger> serials = new ArrayList<>();
        try {
            return signToTargetLevel(request, signingProfile, profile, protocol, serials);
        } catch (Exception e) {
            throw loggedFailure(profile, request.targetLevel(), serials, e);
        }
    }

    private SignedContent signToTargetLevel(ContentSigningRequest request, SigningProfileModel<?, ?> signingProfile,
            ResolvedManagedContentSigningProfile profile, SigningProtocol protocol, List<BigInteger> serials)
            throws SigningEngineException {
        requireReachableLevel(request.targetLevel(), profile);
        requireAcceptableSigningCertificate(profile);
        Instant signingTime = clockSource.wallTimeInstant();
        SignatureAlgorithm signatureAlgorithm = acquisitions.signatureAlgorithm(profile);
        SignatureDigestCoherence.requireCoherent(signatureAlgorithm, request.authorizedDigest(), request.document());

        ComputeDtbsResponseDto dtbs = requireCompleteDtbs(
                computeDtbs(request, profile, signingTime, signatureAlgorithm));
        // The key is released only once the connector has committed to the authorized document.
        DtbsBindingVerifier.verify(request.authorizedDigest(), dtbs);
        byte[] signatureValue = acquisitions.signatureValue(profile, dtbs.getDtbs());
        ContentSigningCursor cursor = advance(ContentSigningCursor.DTBS_COMPUTED,
                ContentSigningCursor.SIGNATURE_ACQUIRED);

        byte[] signedDocument = embedSignatureValue(profile, dtbs, signatureValue, signatureAlgorithm);
        cursor = advance(cursor, ContentSigningCursor.SIGNED);

        SignatureLevel reached = SignatureLevel.SIGNED;
        if (request.targetLevel() != SignatureLevel.SIGNED) {
            signedDocument = applySignatureTimestamp(profile, signedDocument, detachedContentFor(request.document()),
                    request.targetLevel(), cursor, serials);
            reached = request.targetLevel();
        }

        SignedContent result = new SignedContent(signedDocument, reached, serials);
        recordSigning(signingProfile, profile, result, dtbs.getDtbs(), signatureValue, signingTime, protocol);
        return result;
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
        if (request.targetLevel() == SignatureLevel.SIGNED) {
            throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                    "augmentation to SIGNED was requested, but the document already carries a signature",
                    "The document is already signed; augmentation needs a level above SIGNED");
        }
        // No certificate or clock gate here: this path releases no key of the profile's own scheme and mints no
        // signingTime claim. The referenced TIMESTAMPING profile gates its own key and its own time.
        byte[] timestamped = applySignatureTimestamp(profile, request.signedDocument(), request.detachedContent(),
                request.targetLevel(), ContentSigningCursor.SIGNED, serials);

        SignedContent result = new SignedContent(timestamped, request.targetLevel(), serials);
        recordSigning(signingProfile, profile, result, null, null, clockSource.wallTimeInstant(), protocol);
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

    private ComputeDtbsResponseDto computeDtbs(ContentSigningRequest request,
            ResolvedManagedContentSigningProfile profile, Instant signingTime, SignatureAlgorithm signatureAlgorithm)
            throws SigningEngineException {
        ComputeDtbsRequestDto dtbsRequest = ComputeDtbsRequests.forFamily(profile.family());
        dtbsRequest.setFormattingAttributes(profile.signatureFormattingConnectorAttributes());
        dtbsRequest.setDocument(request.document());
        dtbsRequest.setSignerCertificateChain(encodedChain(profile));
        dtbsRequest.setSigningTime(signingTime.atOffset(ZoneOffset.UTC));
        dtbsRequest.setSignatureAlgorithm(signatureAlgorithm);
        return formattingClient.computeDtbs(profile.signatureFormattingConnector(), dtbsRequest);
    }

    /**
     * Acquiring the signature is not idempotent, so a response the connector already left incomplete has to be refused
     * before the key is exercised. A missing {@code formattingContext} would otherwise surface only at
     * {@code embedSignatureValue}, by which point the signature has been made and cannot be completed.
     */
    private static ComputeDtbsResponseDto requireCompleteDtbs(ComputeDtbsResponseDto response)
            throws SigningEngineException {
        if (response == null) {
            throw incompleteDtbs("connector returned no computeDtbs response");
        }
        if (response.getDtbs() == null) {
            throw incompleteDtbs("connector returned no dtbs to sign");
        }
        if (response.getFormattingContext() == null) {
            throw incompleteDtbs("connector returned no formattingContext to complete the signature with");
        }
        return response;
    }

    private static SigningEngineException incompleteDtbs(String defect) {
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
    private byte[] embedSignatureValue(ResolvedManagedContentSigningProfile profile, ComputeDtbsResponseDto dtbs,
            byte[] signatureValue, SignatureAlgorithm signatureAlgorithm) throws SigningEngineException {
        EmbedSignatureValueRequestDto embed = new EmbedSignatureValueRequestDto();
        embed.setFamily(profile.family());
        embed.setFormattingAttributes(profile.signatureFormattingConnectorAttributes());
        embed.setSignatureValue(signatureValue);
        embed.setSignatureAlgorithm(signatureAlgorithm);
        embed.setFormattingContext(dtbs.getFormattingContext());
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

        IssuedTimestamp issued = acquisitions.signatureTimestamp(profile, imprint, "signatureTimestamp");
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
    private static DocumentTransferDto detachedContentFor(DocumentTransferDto document) {
        return document instanceof DigestOnlyDocumentTransferDto ? document : null;
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
        if (isPlatformFault(e.failure())) {
            logger
                    .error("Content signing failed for signing profile '{}' at step '{}' targeting level {}, "
                            + "timestamp serials already issued {}: {}", profile.name(), step, targetLevel,
                            TimestampTokenSerialNumbers.hex(serials), e.operatorMessage(), e);
        } else {
            logger
                    .warn("Refusing to sign content for signing profile '{}' at step '{}' targeting level {}, "
                            + "timestamp serials already issued {}: {}", profile.name(), step, targetLevel,
                            TimestampTokenSerialNumbers.hex(serials), e.operatorMessage());
        }
    }

    /** Exhaustive so that a new failure class has to choose its log level rather than inherit one. */
    private static boolean isPlatformFault(SigningEngineFailure failure) {
        return switch (failure) {
            case SIGNER_FAULT, STEP_FAILED, CONNECTOR_FAULT -> true;
            case INVALID_INPUT, MALFORMED_INPUT, MISCONFIGURED, TIME_UNAVAILABLE, BINDING_VIOLATION -> false;
        };
    }

    /**
     * Records the run. The document is already signed, so a recording failure must never withdraw it: it is logged and
     * swallowed. The strategy is handed a deferred source so a profile with recording off never pays for the metadata.
     *
     * <p>
     * Only a completed run reaches this, so a failure after the signature timestamp was issued can leave a timestamp
     * record that no content-signing record references.
     */
    private void recordSigning(SigningProfileModel<?, ?> signingProfile, ResolvedManagedContentSigningProfile profile,
            SignedContent result, byte[] dtbs, byte[] signatureValue, Instant signingTime, SigningProtocol protocol) {
        try {
            SigningRecordInputSource source = recordFactory
                    .source(signingProfile, profile, result, dtbs, signatureValue, signingTime, protocol);
            signingRecordStrategyFactory
                    .strategyFor(signingProfile.recordPolicy().persistenceMode())
                    .recordSigning(source);
        } catch (Exception e) {
            logger
                    .error("Failed to record signing for signing profile '{}'; the document was signed regardless",
                            signingProfile.name(), e);
        }
    }
}
