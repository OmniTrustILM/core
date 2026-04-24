package com.czertainly.core.service.impl;

import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.cryptography.tokenprofile.AddTokenProfileRequestDto;
import com.czertainly.api.model.client.cryptography.tokenprofile.EditTokenProfileRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.ConnectorApiClientDto;
import com.czertainly.api.model.core.cryptography.key.KeyUsage;
import com.czertainly.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.czertainly.api.model.core.cryptography.tokenprofile.TokenProfileDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.TokenInstanceReference;
import com.czertainly.core.dao.entity.TokenProfile;
import com.czertainly.core.dao.entity.TokenProfile_;
import com.czertainly.core.dao.repository.TokenInstanceReferenceRepository;
import com.czertainly.core.dao.repository.TokenProfileRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.PermissionEvaluator;
import com.czertainly.core.service.TokenProfileService;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service(Resource.Codes.TOKEN_PROFILE)
@Transactional
public class TokenProfileServiceImpl implements TokenProfileService {

    private static final Logger logger = LoggerFactory.getLogger(TokenProfileServiceImpl.class);


    // --------------------------------------------------------------------------------
    // Services & API Clients
    // --------------------------------------------------------------------------------
    private PermissionEvaluator permissionEvaluator;
    private ConnectorApiFactory connectorApiFactory;
    private AttributeEngine attributeEngine;
    // --------------------------------------------------------------------------------
    // Repositories
    // --------------------------------------------------------------------------------
    private TokenProfileRepository tokenProfileRepository;
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setTokenProfileRepository(TokenProfileRepository tokenProfileRepository) {
        this.tokenProfileRepository = tokenProfileRepository;
    }

    @Autowired
    public void setTokenInstanceReferenceRepository(TokenInstanceReferenceRepository tokenInstanceReferenceRepository) {
        this.tokenInstanceReferenceRepository = tokenInstanceReferenceRepository;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
        this.permissionEvaluator = permissionEvaluator;
    }

    //-------------------------------------------------------------------------------------
    //Service Implementations
    //-------------------------------------------------------------------------------------
    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.LIST, parentResource = Resource.TOKEN, parentAction = ResourceAction.LIST)
    public List<TokenProfileDto> listTokenProfiles(Optional<Boolean> enabled, SecurityFilter filter) {
        logger.info("Listing token profiles");
        filter.setParentRefProperty("tokenInstanceReferenceUuid");
        if (enabled.isEmpty()) {
            return tokenProfileRepository.findUsingSecurityFilter(filter)
                    .stream()
                    .map(TokenProfile::mapToDto)
                    .collect(Collectors.toList());
        } else {
            return tokenProfileRepository.findUsingSecurityFilter(filter, enabled.get())
                    .stream()
                    .map(TokenProfile::mapToDto)
                    .collect(Collectors.toList());
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public TokenProfileDetailDto getTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException {
        logger.info("Getting token profile with uuid: {}", uuid);
        TokenProfile tokenProfile = getTokenProfileEntity(uuid);
        TokenProfileDetailDto dto = tokenProfile.mapToDetailDto();
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.TOKEN_PROFILE, tokenProfile.getUuid()));
        dto.setAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.TOKEN_PROFILE, tokenProfile.getUuid()).connector(tokenProfile.getTokenInstanceReference().getConnectorUuid()).build()));
        logger.debug("Token profile detail: {}", dto);
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.CREATE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public TokenProfileDetailDto createTokenProfile(SecuredParentUUID tokenInstanceUuid, AddTokenProfileRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException, NotFoundException {
        logger.info("Creating token profile with name: {}", request.getName());
        if (StringUtils.isBlank(request.getName())) {
            throw new ValidationException(ValidationError.create("Token Profile name must not be empty"));
        }

        Optional<TokenProfile> optionalProfile = tokenProfileRepository.findByName(request.getName());
        if (optionalProfile.isPresent()) {
            throw new AlreadyExistException(TokenProfile.class, request.getName());
        }

        TokenInstanceReference tokenInstanceReference = tokenInstanceReferenceRepository.findByUuid(tokenInstanceUuid).orElseThrow(() -> new NotFoundException(TokenInstanceReferenceRepository.class, tokenInstanceUuid));

        logger.debug("Validating the custom and data attributes for the new token profile");
        attributeEngine.validateCustomAttributesContent(Resource.TOKEN_PROFILE, request.getCustomAttributes());
        mergeAndValidateAttributes(tokenInstanceReference, request.getAttributes());

        TokenProfile tokenProfile = createTokenProfile(request, tokenInstanceReference);
        tokenProfileRepository.save(tokenProfile);

        TokenProfileDetailDto tokenProfileDetailDto = tokenProfile.mapToDetailDto();
        tokenProfileDetailDto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.TOKEN_PROFILE, tokenProfile.getUuid(), request.getCustomAttributes()));
        tokenProfileDetailDto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.TOKEN_PROFILE, tokenProfile.getUuid()).connector(tokenInstanceReference.getConnectorUuid()).build(), request.getAttributes()));

        return tokenProfileDetailDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.UPDATE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public TokenProfileDetailDto editTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid, EditTokenProfileRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        logger.info("Editing token profile with uuid: {}", uuid);
        TokenProfile tokenProfile = getTokenProfileEntity(uuid);
        TokenInstanceReference tokenInstanceReference = tokenInstanceReferenceRepository.findByUuid(tokenInstanceUuid).orElseThrow(() -> new NotFoundException(TokenInstanceReference.class, tokenInstanceUuid));

        attributeEngine.validateCustomAttributesContent(Resource.TOKEN_PROFILE, request.getCustomAttributes());
        mergeAndValidateAttributes(tokenInstanceReference, request.getAttributes());

        updateTokenProfile(tokenProfile, tokenInstanceReference, request);
        tokenProfileRepository.save(tokenProfile);

        TokenProfileDetailDto tokenProfileDetailDto = tokenProfile.mapToDetailDto();
        tokenProfileDetailDto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.TOKEN_PROFILE, tokenProfile.getUuid(), request.getCustomAttributes()));
        tokenProfileDetailDto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.TOKEN_PROFILE, tokenProfile.getUuid()).connector(tokenInstanceReference.getConnectorUuid()).build(), request.getAttributes()));

        return tokenProfileDetailDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DELETE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void deleteTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException {
        logger.info("Deleting token profile with uuid: {}", uuid);
        deleteProfileInternal(uuid, false);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DELETE)
    public void deleteTokenProfile(SecuredUUID tokenProfileUuid) throws NotFoundException {
        logger.info("Deleting token profile with uuid: {}", tokenProfileUuid);
        deleteProfileInternal(tokenProfileUuid, true);

    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.ENABLE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void disableTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException {
        logger.info("Disabling token profile with uuid: {}", uuid);
        disableProfileInternal(uuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.ENABLE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void enableTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException {
        logger.info("Enabling token profile with uuid: {}", uuid);
        enableProfileInternal(uuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DELETE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void deleteTokenProfile(List<SecuredUUID> uuids) {
        logger.info("Deleting token profiles with uuids: {}", uuids);
        for (SecuredUUID uuid : uuids) {
            try {
                deleteProfileInternal(uuid, false);
            } catch (NotFoundException e) {
                logger.warn("Unable to find Token Profile with uuid {}. It may have already been deleted", uuid);
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.ENABLE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void disableTokenProfile(List<SecuredUUID> uuids) {
        logger.info("Disabling token profiles with uuids: {}", uuids);
        for (SecuredUUID uuid : uuids) {
            try {
                disableProfileInternal(uuid);
            } catch (NotFoundException e) {
                logger.warn("Unable to find Token Profile with uuid {}. It may have already been deleted", uuid);
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.ENABLE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void enableTokenProfile(List<SecuredUUID> uuids) {
        logger.info("Enabling token profiles with uuids: {}", uuids);
        for (SecuredUUID uuid : uuids) {
            try {
                enableProfileInternal(uuid);
            } catch (NotFoundException e) {
                logger.warn("Unable to find Token Profile with uuid {}. It may have already been deleted", uuid);
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.UPDATE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void updateKeyUsages(List<SecuredUUID> uuids, List<KeyUsage> usages) {
        logger.info("Request to update the key usages for {} with usages {}", uuids, usages);
        // Iterate through the keys
        for (SecuredUUID uuid : uuids) {
            try {
                TokenProfile tokenProfile = getTokenProfileEntity(uuid);
                tokenProfile.setUsage(usages);
                tokenProfileRepository.save(tokenProfile);
            } catch (Exception e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("Key Usages Updated: {}", uuids);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.UPDATE, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public void updateKeyUsages(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid, List<KeyUsage> usages) throws NotFoundException {
        TokenProfile tokenProfile = getTokenProfileEntity(tokenProfileUuid);
        tokenProfile.setUsage(usages);
        tokenProfileRepository.save(tokenProfile);
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return tokenProfileRepository.findResourceObject(objectUuid, TokenProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        TokenProfile profile = getTokenProfileEntity(objectUuid);
        permissionEvaluator.tokenInstance(profile.getTokenInstanceReference().getSecuredUuid());
        return new NameAndUuidDto(profile.getUuid(), profile.getName());
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        return tokenProfileRepository.listResourceObjects(filter, TokenProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        TokenProfile profile = getTokenProfileEntity(uuid);
        if (profile.getTokenInstanceReference() == null) {
            return;
        }
        // Parent Permission evaluation - Token Instance
        permissionEvaluator.tokenInstance(profile.getTokenInstanceReference().getSecuredUuid());

    }

    private void mergeAndValidateAttributes(TokenInstanceReference tokenInstanceRef, List<RequestAttribute> attributes) throws ConnectorException, AttributeException {
        logger.debug("Merging and validating attributes for token instance: {}. Request Attributes: {}", tokenInstanceRef, attributes);
        if (tokenInstanceRef.getConnector() == null) {
            throw new ValidationException(ValidationError.create("Connector of the Entity is not available / deleted"));
        }

        ConnectorApiClientDto connectorDto = tokenInstanceRef.getConnector().mapToApiClientDtoV1();

        // validate first by connector
        connectorApiFactory.getTokenInstanceApiClient(connectorDto).validateTokenProfileAttributes(connectorDto, tokenInstanceRef.getTokenInstanceUuid(), attributes);

        // list definitions
        List<BaseAttribute> definitions = connectorApiFactory.getTokenInstanceApiClient(connectorDto).listTokenProfileAttributes(connectorDto, tokenInstanceRef.getTokenInstanceUuid());

        // validate and update definitions with attribute engine
        attributeEngine.validateUpdateDataAttributes(tokenInstanceRef.getConnectorUuid(), null, definitions, attributes);
    }

    private TokenProfile createTokenProfile(AddTokenProfileRequestDto request, TokenInstanceReference tokenInstanceReference) {
        TokenProfile entity = new TokenProfile();
        entity.setName(request.getName());
        entity.setDescription(request.getDescription());
        entity.setEnabled(request.isEnabled());
        entity.setTokenInstanceName(tokenInstanceReference.getName());
        entity.setTokenInstanceReference(tokenInstanceReference);
        entity.setTokenInstanceReferenceUuid(tokenInstanceReference.getUuid());
        if(request.getUsage() != null) entity.setUsage(request.getUsage());
        return entity;
    }

    private void updateTokenProfile(TokenProfile entity, TokenInstanceReference tokenInstanceReference, EditTokenProfileRequestDto request) {
        if (request.getDescription() != null) entity.setDescription(request.getDescription());
        entity.setTokenInstanceReference(tokenInstanceReference);
        if (request.getEnabled() != null) entity.setEnabled(request.getEnabled());
        entity.setTokenInstanceName(tokenInstanceReference.getName());
        if(request.getUsage() != null) entity.setUsage(request.getUsage());
    }

    private void deleteProfileInternal(SecuredUUID uuid, boolean throwWhenAssociated) throws NotFoundException {
        TokenProfile tokenProfile = getTokenProfileEntity(uuid);
        if (throwWhenAssociated && tokenProfile.getTokenInstanceReference() == null) {
            throw new ValidationException(ValidationError.create("Token Profile has associated Token Instance. Use other API"));
        }
        attributeEngine.deleteObjectAttributeContent(Resource.TOKEN_PROFILE, tokenProfile.getUuid());
        tokenProfileRepository.delete(tokenProfile);
    }

    private void disableProfileInternal(SecuredUUID uuid) throws NotFoundException {
        TokenProfile tokenProfile = getTokenProfileEntity(uuid);
        tokenProfile.setEnabled(false);
        tokenProfileRepository.save(tokenProfile);
    }

    private void enableProfileInternal(SecuredUUID uuid) throws NotFoundException {
        TokenProfile tokenProfile = getTokenProfileEntity(uuid);
        tokenProfile.setEnabled(true);
        tokenProfileRepository.save(tokenProfile);
    }

    @Override
    public TokenProfile getTokenProfileEntity(SecuredUUID uuid) throws NotFoundException {
        return tokenProfileRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, uuid));
    }
}
