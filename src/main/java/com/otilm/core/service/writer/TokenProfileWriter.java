package com.otilm.core.service.writer;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.tokenprofile.AddTokenProfileRequestDto;
import com.otilm.api.model.client.cryptography.tokenprofile.EditTokenProfileRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.service.CommentInternalService;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TokenProfileWriter {

    private final TokenProfileRepository tokenProfileRepository;
    private final TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    private final AttributeEngine attributeEngine;
    private final CommentInternalService commentService;
    private final CryptographicKeyRepository cryptographicKeyRepository;
    private final SigningProfileVersionRepository signingProfileVersionRepository;

    public TokenProfileWriter(TokenProfileRepository tokenProfileRepository,
            TokenInstanceReferenceRepository tokenInstanceReferenceRepository, AttributeEngine attributeEngine,
            CommentInternalService commentService, CryptographicKeyRepository cryptographicKeyRepository,
            SigningProfileVersionRepository signingProfileVersionRepository) {
        this.tokenProfileRepository = tokenProfileRepository;
        this.tokenInstanceReferenceRepository = tokenInstanceReferenceRepository;
        this.attributeEngine = attributeEngine;
        this.commentService = commentService;
        this.cryptographicKeyRepository = cryptographicKeyRepository;
        this.signingProfileVersionRepository = signingProfileVersionRepository;
    }

    @Transactional(rollbackFor = Exception.class)
    public TokenProfileFullModel create(UUID tokenInstanceUuid, AddTokenProfileRequestDto request)
            throws NotFoundException, AttributeException {
        TokenInstanceReference parent = tokenInstanceReferenceRepository
                .findWithLockByUuid(tokenInstanceUuid)
                .orElseThrow(() -> new NotFoundException(TokenInstanceReferenceRepository.class, tokenInstanceUuid));

        TokenProfile profile = new TokenProfile();
        profile.setName(request.getName());
        profile.setDescription(request.getDescription());
        profile.setEnabled(request.isEnabled());
        profile.setTokenInstanceName(parent.getName());
        profile.setTokenInstanceReference(parent);
        if (request.getUsage() != null) {
            profile.setUsage(request.getUsage());
        }

        profile = tokenProfileRepository.save(profile);

        updateAttributes(profile.getUuid(), parent.getConnectorUuid(), request.getCustomAttributes(),
                request.getAttributes());
        return ImmutableTokenProfileFullModel.from(profile);
    }

    @Transactional(rollbackFor = Exception.class)
    public TokenProfileFullModel update(UUID tokenInstanceUuid, UUID tokenProfileUuid,
            EditTokenProfileRequestDto request) throws NotFoundException, AttributeException {
        TokenProfile profile = findScopedLocked(tokenInstanceUuid, tokenProfileUuid);
        if (request.getDescription() != null) {
            profile.setDescription(request.getDescription());
        }
        if (request.getEnabled() != null) {
            profile.setEnabled(request.getEnabled());
        }
        if (request.getUsage() != null) {
            profile.setUsage(request.getUsage());
        }
        UUID connectorUuid = profile.getTokenInstanceReference().getConnectorUuid();
        updateAttributes(tokenProfileUuid, connectorUuid, request.getCustomAttributes(), request.getAttributes());
        return ImmutableTokenProfileFullModel.from(profile);
    }

    @Transactional
    public void setEnabled(UUID profileUuid, boolean enabled) throws NotFoundException {
        findLocked(profileUuid).setEnabled(enabled);
    }

    @Transactional
    public void setEnabled(UUID parentUuid, UUID profileUuid, boolean enabled) throws NotFoundException {
        findScopedLocked(parentUuid, profileUuid).setEnabled(enabled);
    }

    @Transactional
    public void setUsages(UUID profileUuid, List<KeyUsage> usages) throws NotFoundException {
        findLocked(profileUuid).setUsage(usages);
    }

    @Transactional
    public void setUsages(UUID parentUuid, UUID profileUuid, List<KeyUsage> usages) throws NotFoundException {
        findScopedLocked(parentUuid, profileUuid).setUsage(usages);
    }

    @Transactional
    public void deleteScoped(UUID parentUuid, UUID profileUuid) throws NotFoundException {
        delete(findScopedLocked(parentUuid, profileUuid));
    }

    @Transactional
    public void deleteUnassociated(UUID profileUuid) throws NotFoundException {
        TokenProfile profile = findLocked(profileUuid);
        if (profile.getTokenInstanceReferenceUuid() != null) {
            throw new ValidationException(ValidationError
                    .create("Token Profile has associated Token Instance. Use the token instance scoped API to delete the Token Profile."));
        }
        delete(profile);
    }

    @Transactional
    public void deleteForBulk(UUID profileUuid) throws NotFoundException {
        delete(findLocked(profileUuid));
    }

    private void updateAttributes(UUID profileUuid, UUID connectorUuid, List<RequestAttribute> customAttributes,
            List<RequestAttribute> attributes) throws AttributeException, NotFoundException {
        attributeEngine.updateObjectCustomAttributesContent(Resource.TOKEN_PROFILE, profileUuid, customAttributes);
        attributeEngine
                .updateObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.TOKEN_PROFILE, profileUuid)
                        .connector(connectorUuid)
                        .build(), attributes);
    }

    private TokenProfile findLocked(UUID profileUuid) throws NotFoundException {
        return tokenProfileRepository
                .findWithLockByUuid(profileUuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, profileUuid));
    }

    private TokenProfile findScopedLocked(UUID parentUuid, UUID profileUuid) throws NotFoundException {
        // The locked entity is managed by this transaction; Hibernate persists mutations at commit by dirty checking.
        return tokenProfileRepository
                .findWithLockByUuidAndTokenInstanceReferenceUuid(profileUuid, parentUuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, profileUuid));
    }

    private void delete(TokenProfile profile) {
        validateNoDependentObjects(profile);
        String profileName = profile.getName();
        attributeEngine.deleteObjectAttributeContent(Resource.TOKEN_PROFILE, profile.getUuid());
        commentService.removeObjectComments(Resource.TOKEN_PROFILE, profile.getUuid());
        try {
            tokenProfileRepository.delete(profile);
            tokenProfileRepository.flush();
        } catch (DataIntegrityViolationException e) {
            throw new ValidationException(ValidationError
                    .create("Cannot delete Token Profile {}: dependent Key(s) or Signing Profile(s) were created concurrently. Retry to see current dependencies.",
                            profileName));
        }
    }

    private void validateNoDependentObjects(TokenProfile profile) {
        List<String> blockers = new ArrayList<>();
        long keyCount = cryptographicKeyRepository.countByTokenProfileUuid(profile.getUuid());
        if (keyCount > 0) {
            blockers.add(keyCount + " dependent Key(s)");
        }
        List<String> latestVersionNames = signingProfileVersionRepository
                .findSigningProfileNamesUsingTokenProfileInLatestVersion(profile.getUuid());
        if (!latestVersionNames.isEmpty()) {
            blockers.add("dependent Signing Profile(s): " + String.join(", ", latestVersionNames));
        }
        List<String> supersededOnlyNames = new ArrayList<>(
                signingProfileVersionRepository.findDistinctSigningProfileNamesByTokenProfileUuid(profile.getUuid()));
        supersededOnlyNames.removeAll(latestVersionNames);
        if (!supersededOnlyNames.isEmpty()) {
            blockers
                    .add("Signing Profile(s) referencing it only in superseded versions (released only by deleting the Signing Profile): "
                            + String.join(", ", supersededOnlyNames));
        }
        if (!blockers.isEmpty()) {
            throw new ValidationException(ValidationError
                    .create("Cannot delete Token Profile {}", profile.getName() + ": " + String.join("; ", blockers)));
        }
    }
}
