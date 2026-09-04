package com.otilm.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.cryptography.tokenprofile.AddTokenProfileRequestDto;
import com.otilm.api.model.client.cryptography.tokenprofile.EditTokenProfileRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDto;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.TokenProfile_;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.mapper.crypto.TokenProfileDtoMapper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.ImmutableTokenProfileBasicModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.TokenInstanceInternalService;
import com.otilm.core.service.TokenProfileExternalService;
import com.otilm.core.service.TokenProfileInternalService;
import com.otilm.core.service.writer.TokenProfileWriter;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service(Resource.Codes.TOKEN_PROFILE)
public class TokenProfileServiceImpl implements TokenProfileExternalService, TokenProfileInternalService {

    private static final Logger logger = LoggerFactory.getLogger(TokenProfileServiceImpl.class);

    private AuthorizationEnforcer authorizationEnforcer;
    private TokenInstanceInternalService tokenInstanceService;
    private AttributeEngine attributeEngine;
    private TokenProfileRepository tokenProfileRepository;
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    private TokenProfileWriter tokenProfileWriter;

    @Autowired
    public void setAttributeEngine(AttributeEngine value) {
        attributeEngine = value;
    }

    @Autowired
    public void setTokenProfileRepository(TokenProfileRepository value) {
        tokenProfileRepository = value;
    }

    @Autowired
    public void setTokenInstanceReferenceRepository(TokenInstanceReferenceRepository value) {
        tokenInstanceReferenceRepository = value;
    }

    @Autowired
    public void setTokenProfileWriter(TokenProfileWriter value) {
        tokenProfileWriter = value;
    }

    @Autowired
    public void setTokenInstanceService(TokenInstanceInternalService value) {
        tokenInstanceService = value;
    }

    @Autowired
    public void setAuthorizationEnforcer(AuthorizationEnforcer value) {
        authorizationEnforcer = value;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.LIST,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.LIST)
    public List<TokenProfileDto> listTokenProfiles(Optional<Boolean> enabled, SecurityFilter filter) {
        logger.info("Listing token profiles");
        filter.setParentRefProperty("tokenInstanceReferenceUuid");
        return tokenProfileRepository
                .findFullModelsUsingSecurityFilter(filter, enabled)
                .stream()
                .map(TokenProfileDtoMapper::mapToDto)
                .toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DETAIL,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public TokenProfileDetailDto getTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid)
            throws NotFoundException {
        logger.info("Getting token profile with uuid: {}", uuid);
        TokenProfileFullModel tokenProfile = findTokenProfile(tokenInstanceUuid.getValue(), uuid.getValue());
        return assembleDetail(tokenProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.CREATE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public TokenProfileDetailDto createTokenProfile(SecuredParentUUID tokenInstanceUuid,
            AddTokenProfileRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException,
            AttributeException, NotFoundException {
        logger.info("Creating token profile with name: {}", request.getName());
        if (StringUtils.isBlank(request.getName()))
            throw new ValidationException(ValidationError.create("Token Profile name must not be empty"));
        if (tokenProfileRepository.existsByName(request.getName()))
            throw new AlreadyExistException(TokenProfile.class, request.getName());
        ensureTokenExists(tokenInstanceUuid.getValue(), tokenInstanceUuid);
        attributeEngine.validateCustomAttributesContent(Resource.TOKEN_PROFILE, request.getCustomAttributes());
        validateTokenProfileAttributes(tokenInstanceUuid.getValue(), request.getAttributes());
        return assembleDetail(tokenProfileWriter.create(tokenInstanceUuid.getValue(), request));
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.UPDATE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public TokenProfileDetailDto editTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid,
            EditTokenProfileRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        logger.info("Editing token profile with uuid: {}", uuid);
        findTokenProfile(tokenInstanceUuid.getValue(), uuid.getValue());
        attributeEngine.validateCustomAttributesContent(Resource.TOKEN_PROFILE, request.getCustomAttributes());
        validateTokenProfileAttributes(tokenInstanceUuid.getValue(), request.getAttributes());
        return assembleDetail(tokenProfileWriter.update(tokenInstanceUuid.getValue(), uuid.getValue(), request));
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DELETE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void deleteTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException {
        tokenProfileWriter.deleteScoped(tokenInstanceUuid.getValue(), uuid.getValue());
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DELETE)
    public void deleteTokenProfile(SecuredUUID uuid) throws NotFoundException {
        tokenProfileWriter.deleteUnassociated(uuid.getValue());
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.ENABLE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void disableTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException {
        tokenProfileWriter.setEnabled(tokenInstanceUuid.getValue(), uuid.getValue(), false);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.ENABLE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void enableTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException {
        tokenProfileWriter.setEnabled(tokenInstanceUuid.getValue(), uuid.getValue(), true);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DELETE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void deleteTokenProfile(List<SecuredUUID> uuids) {
        for (SecuredUUID uuid : uuids)
            try {
                tokenProfileWriter.deleteForBulk(uuid.getValue());
            } catch (NotFoundException e) {
                logger.warn("Unable to find Token Profile with uuid {}. It may have already been deleted", uuid);
            } catch (ValidationException e) {
                logger.warn(e.getMessage());
            }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.ENABLE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void disableTokenProfile(List<SecuredUUID> uuids) {
        setEnabledForBulk(uuids, false);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.ENABLE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void enableTokenProfile(List<SecuredUUID> uuids) {
        setEnabledForBulk(uuids, true);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.UPDATE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void updateKeyUsages(List<SecuredUUID> uuids, List<KeyUsage> usages) {
        for (SecuredUUID uuid : uuids)
            try {
                tokenProfileWriter.setUsages(uuid.getValue(), usages);
            } catch (Exception e) {
                logger.warn(e.getMessage());
            }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.UPDATE,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void updateKeyUsages(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid,
            List<KeyUsage> usages) throws NotFoundException {
        tokenProfileWriter.setUsages(tokenInstanceUuid.getValue(), tokenProfileUuid.getValue(), usages);
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return tokenProfileRepository.findResourceObject(objectUuid, TokenProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID uuid) throws NotFoundException {
        ImmutableTokenProfileBasicModel profile = findBasicModel(uuid.getValue());
        enforceParentDetail(profile);
        return new NameAndUuidDto(profile.uuid(), profile.name());
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters,
            PaginationRequestDto pagination) {
        return tokenProfileRepository.listResourceObjects(filter, TokenProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        ImmutableTokenProfileBasicModel profile = findBasicModel(uuid.getValue());
        if (profile.tokenInstanceReferenceUuid() != null)
            enforceParentDetail(profile);
    }

    @Override
    public TokenProfile getTokenProfileEntity(SecuredUUID uuid) throws NotFoundException {
        return tokenProfileRepository
                .findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, uuid));
    }

    private TokenProfileDetailDto assembleDetail(TokenProfileFullModel profile) {
        TokenProfileDetailDto dto = TokenProfileDtoMapper.mapToDetailDto(profile);
        dto
                .setCustomAttributes(
                        attributeEngine.getObjectCustomAttributesContent(Resource.TOKEN_PROFILE, profile.uuid()));
        dto
                .setAttributes(attributeEngine
                        .getObjectDataAttributesContent(ObjectAttributeContentInfo
                                .builder(Resource.TOKEN_PROFILE, profile.uuid())
                                .connector(profile.connectorUuid().orElse(null))
                                .build()));
        return dto;
    }

    private ImmutableTokenProfileBasicModel findBasicModel(UUID profileUuid) throws NotFoundException {
        return tokenProfileRepository
                .findBasicModelByUuid(profileUuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, profileUuid));
    }

    private TokenProfileFullModel findTokenProfile(UUID tokenUuid, UUID profileUuid) throws NotFoundException {
        return tokenProfileRepository
                .findFullModelByUuidAndTokenInstanceReferenceUuid(profileUuid, tokenUuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, profileUuid));
    }

    private void ensureTokenExists(UUID tokenUuid, SecuredParentUUID securedTokenUuid) throws NotFoundException {
        if (!tokenInstanceReferenceRepository.existsByUuid(tokenUuid))
            throw new NotFoundException(TokenInstanceReferenceRepository.class, securedTokenUuid);
    }

    private void validateTokenProfileAttributes(UUID tokenUuid, List<RequestAttribute> attributes)
            throws ConnectorException, AttributeException, NotFoundException, ValidationException {
        tokenInstanceService.validateTokenProfileAttributes(SecuredUUID.fromUUID(tokenUuid), attributes);
    }

    private void enforceParentDetail(ImmutableTokenProfileBasicModel profile) {
        if (profile.tokenInstanceReferenceUuid() == null) {
            return;
        }
        authorizationEnforcer
                .enforce(Resource.TOKEN, ResourceAction.DETAIL,
                        SecuredUUID.fromUUID(profile.tokenInstanceReferenceUuid()));
    }

    private void setEnabledForBulk(List<SecuredUUID> uuids, boolean enabled) {
        for (SecuredUUID uuid : uuids)
            try {
                tokenProfileWriter.setEnabled(uuid.getValue(), enabled);
            } catch (NotFoundException e) {
                logger.warn("Unable to find Token Profile with uuid {}. It may have already been deleted", uuid);
            }
    }
}
