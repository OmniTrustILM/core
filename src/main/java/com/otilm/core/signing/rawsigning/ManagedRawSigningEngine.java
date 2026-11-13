package com.otilm.core.signing.rawsigning;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureInputMode;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedRawSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.signing.engine.batch.BatchAdmission;
import com.otilm.core.signing.engine.batch.BatchRecordStager;
import com.otilm.core.signing.engine.certificate.SigningCertificateValidatorFactory;
import com.otilm.core.signing.engine.certificate.ValidationResult;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.signer.PrehashedSigning;
import com.otilm.core.signing.engine.signer.Signer;
import com.otilm.core.signing.engine.signer.SignerFactory;
import com.otilm.core.signing.record.SigningRecordInputSource;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Signs a batch of client digests, each as it is, with a raw signing profile's key in one provider call. The run holds
 * no transaction: the provider call runs outside one, and staging the records opens its own.
 */
@Component
public class ManagedRawSigningEngine {

    private static final Logger logger = LoggerFactory.getLogger(ManagedRawSigningEngine.class);

    private static final String CLIENT_MESSAGE = "Internal error during signing";

    private final SignerFactory signerFactory;
    private final SigningCertificateValidatorFactory signingCertificateValidatorFactory;
    private final RawSigningRecordFactory recordFactory;
    private final BatchRecordStager recordStager;

    public ManagedRawSigningEngine(SignerFactory signerFactory,
            SigningCertificateValidatorFactory signingCertificateValidatorFactory,
            RawSigningRecordFactory recordFactory, BatchRecordStager recordStager) {
        this.signerFactory = signerFactory;
        this.signingCertificateValidatorFactory = signingCertificateValidatorFactory;
        this.recordFactory = recordFactory;
        this.recordStager = recordStager;
    }

    /**
     * Signs every digest of {@code request} and stages one signing record per digest. Every check runs before the key
     * is used, so a refused batch is neither signed nor recorded.
     *
     * @param protocol how the run was initiated, which is what its signing records will carry
     * @return the signatures in request order
     */
    public RawSigningResult sign(RawSigningRequest request, SigningProfileModel<?, ?> model,
            ResolvedManagedRawSigningProfile profile, SigningProtocol protocol) throws SigningEngineException {
        try {
            return signDigests(request, model, profile, protocol);
        } catch (Exception e) {
            throw loggedFailure(profile, e);
        }
    }

    private RawSigningResult signDigests(RawSigningRequest request, SigningProfileModel<?, ?> model,
            ResolvedManagedRawSigningProfile profile, SigningProtocol protocol) throws SigningEngineException {
        List<RawSigningItem> items = request.items();
        BatchAdmission.admit(items.stream().map(RawSigningItem::identifier).toList());
        requirePrehashedDigests(request.inputMode());
        requireAcceptableSigningCertificate(profile);

        Signer signer = signerFactory.create(profile.resolvedScheme());
        SignatureAlgorithm signatureAlgorithm = signer.getSignatureAlgorithm();
        DigestAlgorithm digestAlgorithm = digestAlgorithmOf(signatureAlgorithm, profile);
        requireDigestAlgorithm(request.digestAlgorithm(), digestAlgorithm);
        requireDigestLengths(items, digestAlgorithm);

        List<byte[]> signatures = signer
                .signAll(items.stream().map(RawSigningItem::digest).toList(), SignatureInputMode.PREHASHED_DIGEST);
        List<SigningRecordInputSource> sources = recordFactory.sources(model, items, signatures, protocol);
        List<UUID> recordUuids = recordStager.stage(model, sources);
        return new RawSigningResult(signatureAlgorithm, profile.resolvedScheme().chain().chain(),
                signedItems(items, signatures, recordUuids));
    }

    /** The run owns this rule, so every door that reaches it refuses data signing without a check of its own. */
    private static void requirePrehashedDigests(SignatureInputMode inputMode) throws SigningEngineException {
        if (inputMode != SignatureInputMode.PREHASHED_DIGEST) {
            throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                    "a raw signing run was given input mode %s"
                            .formatted(inputMode == null ? null : inputMode.getCode()),
                    "Raw signing takes digests; data signing is not supported");
        }
    }

    /**
     * The Signing Profile model a run reads is cached, so a certificate revoked, expired or archived -- or a key
     * deactivated -- after profile save would otherwise still reach the key. A raw signature is no timestamp, so the
     * qualified-timestamp demand does not apply.
     */
    private void requireAcceptableSigningCertificate(ResolvedManagedRawSigningProfile profile)
            throws SigningEngineException {
        ResolvedManagedScheme signingScheme = profile.resolvedScheme();
        ValidationResult result = signingCertificateValidatorFactory
                .getValidator(signingScheme)
                .validate(signingScheme, SigningWorkflowType.RAW_SIGNING, false, profile.certificatePurpose());
        if (result instanceof ValidationResult.Nok nok) {
            throw new SigningEngineException(nok.failure(),
                    "signing certificate of Signing Profile '%s' is not acceptable: %s"
                            .formatted(profile.name(), nok.logMessage()),
                    CLIENT_MESSAGE);
        }
    }

    /**
     * Profile save refuses a key outside the prehashed bound, but a profile saved before that rule can still name one,
     * and it must fail as the configuration fault it is.
     */
    private static DigestAlgorithm digestAlgorithmOf(SignatureAlgorithm signatureAlgorithm,
            ResolvedManagedRawSigningProfile profile) throws SigningEngineException {
        if (!PrehashedSigning.admits(signatureAlgorithm)) {
            String code = signatureAlgorithm == null ? null : signatureAlgorithm.getCode();
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "the key of Signing Profile '%s' signs with %s, which cannot sign a prehashed digest"
                            .formatted(profile.name(), code),
                    "Signing key algorithm %s cannot be used for raw signing".formatted(code));
        }
        return PrehashedSigning.digestAlgorithm(signatureAlgorithm);
    }

    private static void requireDigestAlgorithm(DigestAlgorithm requested, DigestAlgorithm signed)
            throws SigningEngineException {
        if (requested != signed) {
            String requestedCode = requested == null ? null : requested.getCode();
            throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                    "the request names digest algorithm %s, but the key signs a %s digest"
                            .formatted(requestedCode, signed.getCode()),
                    "Digest algorithm %s does not match this Signing Profile, which signs a %s digest"
                            .formatted(requestedCode, signed.getCode()));
        }
    }

    private static void requireDigestLengths(List<RawSigningItem> items, DigestAlgorithm digestAlgorithm)
            throws SigningEngineException {
        int digestSize = digestAlgorithm.getDigestSizeBytes();
        for (RawSigningItem item : items) {
            int length = item.digest().length;
            if (length != digestSize) {
                throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                        "digest is %d bytes, but a %s digest is %d"
                                .formatted(length, digestAlgorithm.getCode(), digestSize),
                        "Each digest must be %d bytes for %s".formatted(digestSize, digestAlgorithm.getCode()))
                        .withItem(item.identifier());
            }
        }
    }

    /** The stager answers in source order, which is request order, or with nothing when the profile records nothing. */
    private static List<RawSignedItem> signedItems(List<RawSigningItem> items, List<byte[]> signatures,
            List<UUID> recordUuids) {
        List<RawSignedItem> signed = new ArrayList<>(items.size());
        for (int index = 0; index < items.size(); index++) {
            UUID recordUuid = recordUuids.isEmpty() ? null : recordUuids.get(index);
            signed.add(new RawSignedItem(items.get(index).identifier(), signatures.get(index), recordUuid));
        }
        return signed;
    }

    /**
     * Every escape is logged, including an unchecked one: a run that dies after the key has signed leaves no signing
     * record, so the log line is the only trace it ever had.
     */
    private static SigningEngineException loggedFailure(ResolvedManagedRawSigningProfile profile, Exception e) {
        SigningEngineException failure = asEngineFailure(e);
        logFailure(profile, failure);
        return failure;
    }

    /** The unchecked detail stays in the cause, which only the log reads; the caller gets the fixed client message. */
    private static SigningEngineException asEngineFailure(Exception e) {
        return e instanceof SigningEngineException engineFailure
                ? engineFailure
                : new SigningEngineException(SigningEngineFailure.STEP_FAILED, "unexpected error during raw signing", e,
                        CLIENT_MESSAGE);
    }

    /** Neither a digest nor a signature is log material; the item is named by the identifier its caller chose. */
    private static void logFailure(ResolvedManagedRawSigningProfile profile, SigningEngineException e) {
        String scope = e.itemIdentifier() != null ? "digest '%s'".formatted(e.itemIdentifier()) : "the batch";
        String step = e.step() != null ? e.step() : "none";
        if (isPlatformFault(e.failure())) {
            logger
                    .error("Raw signing failed for signing profile '{}' on {} at step '{}': {}", profile.name(), scope,
                            step, e.operatorMessage(), e);
        } else {
            logger
                    .warn("Refusing to sign digests for signing profile '{}' on {} at step '{}': {}", profile.name(),
                            scope, step, e.operatorMessage());
        }
    }

    /** Exhaustive so that a new failure class has to choose its log level rather than inherit one. */
    private static boolean isPlatformFault(SigningEngineFailure failure) {
        return switch (failure) {
            case SIGNER_FAULT, STEP_FAILED, CONNECTOR_FAULT -> true;
            case INVALID_INPUT, MALFORMED_INPUT, MISCONFIGURED, TIME_UNAVAILABLE, BINDING_VIOLATION -> false;
        };
    }
}
