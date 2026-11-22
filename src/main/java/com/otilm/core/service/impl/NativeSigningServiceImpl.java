package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.signing.nativesigning.SignDocumentItemDto;
import com.otilm.api.model.client.signing.nativesigning.SignDocumentRequestDto;
import com.otilm.api.model.client.signing.nativesigning.SignDocumentResponseDto;
import com.otilm.api.model.client.signing.nativesigning.SignDocumentResultDto;
import com.otilm.api.model.common.signature.DocumentTransferMode;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.aop.OutsideTransaction;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
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

    public NativeSigningServiceImpl(IlmNativeProfileResolver nativeProfileResolver,
            SigningProfileResolverFactory signingProfileResolverFactory,
            ManagedContentSigningEngine contentSigningEngine) {
        this.nativeProfileResolver = nativeProfileResolver;
        this.signingProfileResolverFactory = signingProfileResolverFactory;
        this.contentSigningEngine = contentSigningEngine;
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
        ResolvedManagedContentSigningProfile contentSigningProfile = contentSigningProfile(signingProfile);
        List<SignedItem> signed = contentSigningEngine
                .sign(contentSigningRequest, signingProfile, contentSigningProfile, SigningProtocol.ILM_NATIVE);
        return signDocumentResponse(signed);
    }

    private ResolvedManagedContentSigningProfile contentSigningProfile(SigningProfileModel<?, ?> signingProfile)
            throws SigningEngineException {
        try {
            return resolvedContentSigningProfile(signingProfile);
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
     * The native gate already admitted only managed content-signing profiles. Any other resolution is a
     * misconfiguration.
     */
    private ResolvedManagedContentSigningProfile resolvedContentSigningProfile(SigningProfileModel<?, ?> signingProfile)
            throws SigningEngineException {
        ResolvedSigningProfile resolved = signingProfileResolverFactory.resolve(signingProfile);
        if (!(resolved instanceof ResolvedManagedContentSigningProfile contentSigningProfile)) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "Signing Profile '%s' resolved to %s, not a managed content-signing profile"
                            .formatted(signingProfile.name(), resolved.getClass().getSimpleName()),
                    "The system is misconfigured.");
        }
        return contentSigningProfile;
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
}
