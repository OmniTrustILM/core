package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.signing.nativesigning.SignDocumentItemDto;
import com.otilm.api.model.client.signing.nativesigning.SignDocumentRequestDto;
import com.otilm.api.model.client.signing.nativesigning.SignDocumentResponseDto;
import com.otilm.api.model.client.signing.nativesigning.SignDocumentResultDto;
import com.otilm.api.model.client.signing.nativesigning.SignRawRequestDto;
import com.otilm.api.model.client.signing.nativesigning.SignRawResponseDto;
import com.otilm.api.model.client.signing.nativesigning.SignRawResultDto;
import com.otilm.api.model.common.signature.DocumentTransferMode;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.aop.OutsideTransaction;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedManagedRawSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedSigningProfile;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.NativeSigningExternalService;
import com.otilm.core.signing.contentsigning.ContentSigningItem;
import com.otilm.core.signing.contentsigning.ContentSigningRequest;
import com.otilm.core.signing.contentsigning.ManagedContentSigningEngine;
import com.otilm.core.signing.contentsigning.SignedItem;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.resolver.SigningProfileResolverFactory;
import com.otilm.core.signing.nativesigning.IlmNativeProfileResolver;
import com.otilm.core.signing.nativesigning.NativeOperation;
import com.otilm.core.signing.rawsigning.ManagedRawSigningEngine;
import com.otilm.core.signing.rawsigning.RawSigningItem;
import com.otilm.core.signing.rawsigning.RawSigningRequest;
import com.otilm.core.signing.rawsigning.RawSigningResult;
import com.otilm.core.util.CertificateUtil;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class NativeSigningServiceImpl implements NativeSigningExternalService {

    private static final Logger LOG = LoggerFactory.getLogger(NativeSigningServiceImpl.class);

    private final IlmNativeProfileResolver nativeProfileResolver;
    private final SigningProfileResolverFactory signingProfileResolverFactory;
    private final ManagedContentSigningEngine contentSigningEngine;
    private final ManagedRawSigningEngine rawSigningEngine;

    public NativeSigningServiceImpl(IlmNativeProfileResolver nativeProfileResolver,
            SigningProfileResolverFactory signingProfileResolverFactory,
            ManagedContentSigningEngine contentSigningEngine, ManagedRawSigningEngine rawSigningEngine) {
        this.nativeProfileResolver = nativeProfileResolver;
        this.signingProfileResolverFactory = signingProfileResolverFactory;
        this.contentSigningEngine = contentSigningEngine;
        this.rawSigningEngine = rawSigningEngine;
    }

    @Override
    // NOT_SUPPORTED opens no transaction, so the rollback rule S8989 asks for never applies.
    @SuppressWarnings("java:S8989")
    @OutsideTransaction
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.SIGN)
    public SignDocumentResponseDto signDocument(SecuredUUID signingProfileUuid, SignDocumentRequestDto request)
            throws NotFoundException, SigningEngineException {
        SigningProfileModel<?, ?> signingProfile = nativeProfileResolver
                .resolve(signingProfileUuid.getValue(), NativeOperation.SIGN_DOCUMENT);
        ContentSigningRequest contentSigningRequest = contentSigningRequest(request);
        ResolvedManagedContentSigningProfile contentSigningProfile = resolvedProfile(signingProfile,
                ResolvedManagedContentSigningProfile.class, "a managed content-signing profile");
        List<SignedItem> signed = contentSigningEngine
                .sign(contentSigningRequest, signingProfile, contentSigningProfile, SigningProtocol.ILM_NATIVE);
        return signDocumentResponse(signed);
    }

    @Override
    // NOT_SUPPORTED opens no transaction, so the rollback rule S8989 asks for never applies.
    @SuppressWarnings("java:S8989")
    @OutsideTransaction
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.SIGN)
    public SignRawResponseDto signRaw(SecuredUUID signingProfileUuid, SignRawRequestDto request)
            throws NotFoundException, SigningEngineException {
        SigningProfileModel<?, ?> signingProfile = nativeProfileResolver
                .resolve(signingProfileUuid.getValue(), NativeOperation.SIGN_RAW);
        ResolvedManagedRawSigningProfile rawSigningProfile = resolvedProfile(signingProfile,
                ResolvedManagedRawSigningProfile.class, "a managed raw-signing profile");
        requirePinnedCertificate(rawSigningProfile, request.getCertificateFingerprint());
        RawSigningResult result = rawSigningEngine
                .sign(rawSigningRequest(request), signingProfile, rawSigningProfile, SigningProtocol.ILM_NATIVE);
        return signRawResponse(rawSigningProfile, result);
    }

    /**
     * The native gate already admitted only managed profiles of the operation's workflow. Any other resolution is a
     * misconfiguration.
     */
    private <P extends ResolvedSigningProfile> P resolvedProfile(SigningProfileModel<?, ?> signingProfile,
            Class<P> expectedType, String expectedKind) throws SigningEngineException {
        try {
            ResolvedSigningProfile resolved = signingProfileResolverFactory.resolve(signingProfile);
            if (!expectedType.isInstance(resolved)) {
                throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                        "Signing Profile '%s' resolved to %s, not %s"
                                .formatted(signingProfile.name(), resolved.getClass().getSimpleName(), expectedKind),
                        "The system is misconfigured.");
            }
            return expectedType.cast(resolved);
        } catch (SigningEngineException e) {
            throw loggedResolutionFailure(signingProfile, e);
        } catch (RuntimeException e) {
            throw loggedResolutionFailure(signingProfile, e);
        }
    }

    private static <E extends Exception> E loggedResolutionFailure(SigningProfileModel<?, ?> signingProfile,
            E failure) {
        if (failure instanceof SigningEngineException engineFailure) {
            LOG
                    .error("Native signing could not resolve signing profile '{}': {} {}", signingProfile.name(),
                            engineFailure.failure(), engineFailure.operatorMessage(), failure);
        } else {
            LOG.error("Native signing could not resolve signing profile '{}'", signingProfile.name(), failure);
        }
        return failure;
    }

    /**
     * A caller pins the certificate it prepared its digests for, so a signature under any other certificate would not
     * verify where the caller puts it. The refusal comes before the key is used.
     */
    private static void requirePinnedCertificate(ResolvedManagedRawSigningProfile profile, String pinnedFingerprint)
            throws SigningEngineException {
        if (pinnedFingerprint == null) {
            return;
        }
        X509Certificate signingCertificate = profile.resolvedScheme().chain().signingCertificate();
        String signingCertificateFingerprint = fingerprintOf(profile, signingCertificate);
        if (!signingCertificateFingerprint.equalsIgnoreCase(pinnedFingerprint)) {
            throw new ValidationException(
                    "The signing certificate of Signing Profile '%s' is not the one the request names"
                            .formatted(profile.name()));
        }
    }

    private static String fingerprintOf(ResolvedManagedRawSigningProfile profile, X509Certificate certificate)
            throws SigningEngineException {
        try {
            return CertificateUtil.getThumbprint(certificate);
        } catch (GeneralSecurityException e) {
            throw loggedCertificateFailure(profile, "fingerprint the signing certificate", e);
        }
    }

    /**
     * A certificate the profile resolved with was parsed from its encoding, so encoding or hashing it fails only on a
     * platform fault.
     */
    private static SigningEngineException loggedCertificateFailure(ResolvedManagedRawSigningProfile profile,
            String failedStep, GeneralSecurityException cause) {
        LOG.error("Native signing could not {} of signing profile '{}'", failedStep, profile.name(), cause);
        return new SigningEngineException(SigningEngineFailure.STEP_FAILED,
                "could not %s of Signing Profile '%s'".formatted(failedStep, profile.name()), cause,
                "Internal error during signing");
    }

    /** A native request carries no separately authorized digest. */
    private static ContentSigningRequest contentSigningRequest(SignDocumentRequestDto request) {
        DocumentTransferMode transferMode = request.getTransferMode();
        List<ContentSigningItem> items = request
                .getItems()
                .stream()
                .map(item -> ContentSigningItem
                        .withoutAuthorizedDigest(item.getIdentifier(), transferredContent(transferMode, item)))
                .toList();
        List<RequestAttribute> requestAttributes = request.getRequestAttributes() == null
                ? List.of()
                : request.getRequestAttributes();
        return new ContentSigningRequest(transferMode, request.getDigestAlgorithm(), items, requestAttributes);
    }

    private static byte[] transferredContent(DocumentTransferMode transferMode, SignDocumentItemDto item) {
        return switch (transferMode) {
            case INLINE -> item.getDocument();
            case DIGEST_ONLY -> item.getDocumentDigest();
        };
    }

    private static SignDocumentResponseDto signDocumentResponse(List<SignedItem> signed) {
        List<SignDocumentResultDto> results = signed
                .stream()
                .map(item -> new SignDocumentResultDto(item.identifier(), item.signingRecordUuid(),
                        item.content().output(), item.content().mediaType()))
                .toList();
        return new SignDocumentResponseDto(results);
    }

    private static RawSigningRequest rawSigningRequest(SignRawRequestDto request) {
        List<RawSigningItem> items = request
                .getItems()
                .stream()
                .map(item -> new RawSigningItem(item.getIdentifier(), item.getData()))
                .toList();
        return new RawSigningRequest(request.getSignatureInputMode(), request.getDigestAlgorithm(), items);
    }

    private static SignRawResponseDto signRawResponse(ResolvedManagedRawSigningProfile profile, RawSigningResult result)
            throws SigningEngineException {
        List<byte[]> signerCertificateChain = new ArrayList<>(result.certificateChain().size());
        for (X509Certificate certificate : result.certificateChain()) {
            signerCertificateChain.add(encoded(profile, certificate));
        }
        List<SignRawResultDto> results = result
                .items()
                .stream()
                .map(item -> new SignRawResultDto(item.identifier(), item.signingRecordUuid(), item.signature()))
                .toList();
        return new SignRawResponseDto(result.signatureAlgorithm(), signerCertificateChain, results);
    }

    private static byte[] encoded(ResolvedManagedRawSigningProfile profile, X509Certificate certificate)
            throws SigningEngineException {
        try {
            return certificate.getEncoded();
        } catch (GeneralSecurityException e) {
            throw loggedCertificateFailure(profile, "encode the certificate chain", e);
        }
    }
}
