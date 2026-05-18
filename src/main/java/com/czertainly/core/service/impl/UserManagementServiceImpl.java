package com.czertainly.core.service.impl;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.auth.AddUserRequestDto;
import com.czertainly.api.model.client.auth.UpdateUserRequestDto;
import com.czertainly.api.model.client.auth.UserIdentificationRequestDto;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.UploadCertificateRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.core.auth.*;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.group.GroupDto;
import com.czertainly.api.model.core.logging.enums.AuditLogOutput;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.logging.enums.OperationResult;
import com.czertainly.api.model.core.logging.records.LogRecord;
import com.czertainly.api.model.core.logging.records.ResourceObjectIdentity;
import com.czertainly.api.model.core.logging.records.ResourceRecord;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.settings.SettingsSection;
import com.czertainly.api.model.core.settings.logging.LoggingSettingsDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.logging.LoggerWrapper;
import com.czertainly.core.logging.LoggingHelper;
import com.czertainly.core.messaging.jms.producers.AuditLogsProducer;
import com.czertainly.core.messaging.model.AuditLogMessage;
import com.czertainly.core.model.auth.AuthenticationRequestDto;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authn.client.AuthenticationCache;
import com.czertainly.core.security.authn.client.UserManagementApiClient;
import com.czertainly.core.events.transaction.UserCertificateAssignedEvent;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.*;
import com.czertainly.core.settings.SettingsCache;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.OAuth2Util;
import com.nimbusds.jwt.SignedJWT;
import jakarta.transaction.Transactional;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Service;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.*;
import java.text.ParseException;
import java.time.OffsetDateTime;
import java.util.*;

@Service(Resource.Codes.USER)
@Transactional
public class UserManagementServiceImpl implements UserManagementService {
    private static final LoggerWrapper logger = new LoggerWrapper(UserManagementServiceImpl.class, Module.AUTH, Resource.USER);

    @Value("${logging.schema-version}")
    private String schemaVersion;

    private UserManagementApiClient userManagementApiClient;

    private CertificateService certificateService;
    private GroupService groupService;
    private ResourceObjectAssociationService objectAssociationService;
    private AuditLogsProducer auditLogsProducer;

    private AttributeEngine attributeEngine;

    private FindByIndexNameSessionRepository<? extends Session> sessionRepository;

    private AuthenticationCache authenticationCache;

    @Autowired
    public void setAuthenticationCache(AuthenticationCache authenticationCache) {
        this.authenticationCache = authenticationCache;
    }

    @Autowired
    public void setAuditLogsProducer(AuditLogsProducer auditLogsProducer) {
        this.auditLogsProducer = auditLogsProducer;
    }

    @Autowired
    public void setSessionRepository(FindByIndexNameSessionRepository<? extends Session> sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    @Autowired
    public void setUserManagementApiClient(UserManagementApiClient userManagementApiClient) {
        this.userManagementApiClient = userManagementApiClient;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setGroupService(GroupService groupService) {
        this.groupService = groupService;
    }

    @Autowired
    public void setObjectAssociationService(ResourceObjectAssociationService objectAssociationService) {
        this.objectAssociationService = objectAssociationService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.LIST)
    public List<UserDto> listUsers() {
        return userManagementApiClient.getUsers().getData();
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.DETAIL)
    public UserDetailDto getUser(String userUuid) throws NotFoundException {
        UserDetailDto dto = userManagementApiClient.getUserDetail(userUuid);
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.USER, UUID.fromString(userUuid)));
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.CREATE)
    public UserDetailDto createUser(AddUserRequestDto request) throws CertificateException, NotFoundException, AttributeException {
        attributeEngine.validateCustomAttributesContent(Resource.USER, request.getCustomAttributes());
        if (StringUtils.isBlank(request.getUsername())) {
            throw new ValidationException(ValidationError.create("username must not be empty"));
        }
        UserRequestDto requestDto = new UserRequestDto();
        Certificate certificate = null;
        boolean userCertificateInRequest = (request.getCertificateUuid() != null && !request.getCertificateUuid().isEmpty()) || (request.getCertificateData() != null && !request.getCertificateData().isEmpty());
        // In case an existing certificate is provided in the request, it can be added to the request before user creation
        if (userCertificateInRequest) {
            certificate = getExistingCertificate(request.getCertificateUuid(), request.getCertificateData());
            if (certificate != null) {
                validateExistingCertificate(null, certificate);
                requestDto.setCertificateUuid(certificate.getUuid().toString());
                requestDto.setCertificateFingerprint(certificate.getFingerprint());
            }
        }
        requestDto.setEmail(request.getEmail());
        requestDto.setEnabled(request.getEnabled());
        requestDto.setUsername(request.getUsername());
        requestDto.setFirstName(request.getFirstName());
        requestDto.setLastName(request.getLastName());
        requestDto.setDescription(request.getDescription());

        List<NameAndUuidDto> groups = new ArrayList<>();
        for (String groupUuid : request.getGroupUuids()) {
            GroupDto groupDto = groupService.getGroup(SecuredUUID.fromString(groupUuid));
            groups.add(new NameAndUuidDto(groupDto.getUuid(), groupDto.getName()));
        }
        requestDto.setGroups(groups);

        UserDetailDto response = userManagementApiClient.createUser(requestDto);
        if (certificate != null) {
            certificateService.updateCertificateUser(certificate.getUuid(), response.getUuid());
            // User certificate needs to be updated and assigned asynchronously
        } else if (userCertificateInRequest) {
            uploadNewCertificate(response.getUuid(), request.getCertificateData());
        }

        response.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.USER, UUID.fromString(response.getUuid()), request.getCustomAttributes()));

        logger.logEvent(Operation.CREATE, OperationResult.SUCCESS, response.toLogData(), null, null);
        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.UPDATE)
    public UserDetailDto updateUser(String userUuid, UpdateUserRequestDto request) throws NotFoundException, CertificateException, AttributeException {
        attributeEngine.validateCustomAttributesContent(Resource.USER, request.getCustomAttributes());
        UserDetailDto dto = getUserUpdateRequestPayload(userUuid, request, "", "");
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.USER, UUID.fromString(userUuid), request.getCustomAttributes()));
        authenticationCache.evictByUserUuid(UUID.fromString(userUuid));
        return dto;
    }

    @Override
    //Internal Use Only -- For Auth Profile Update API
    public UserDetailDto updateUserInternal(String userUuid, UpdateUserRequestDto request, String certificateUuid, String certificateFingerprint) throws NotFoundException, CertificateException {
        UserDetailDto dto = getUserUpdateRequestPayload(userUuid, request, certificateUuid, certificateFingerprint);
        authenticationCache.evictByUserUuid(UUID.fromString(userUuid));
        return dto;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void updateUserCertificate(UserCertificateAssignedEvent event) {
        try {
            UserDetailDto dto = getUser(event.userUuid());
            UpdateUserRequestDto request = new UpdateUserRequestDto();
            request.setCertificateUuid(event.certificateUuid());
            request.setEmail(dto.getEmail());
            request.setDescription(dto.getDescription());
            request.setFirstName(dto.getFirstName());
            request.setLastName(dto.getLastName());
            List<String> groupUuids = dto.getGroups().stream().map(NameAndUuidDto::getUuid).toList();
            request.setGroupUuids(groupUuids);
            getUserUpdateRequestPayload(event.userUuid(), request, event.certificateUuid(), event.certificateFingerprint());
            authenticationCache.evictByUserUuid(UUID.fromString(event.userUuid()));
        } catch (NotFoundException | CertificateException e) {
            logger.getLogger().error("Failed to update certificate {} for user {} in auth service: {}", event.certificateUuid(), event.userUuid(), e.getMessage());
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.DELETE)
    public void deleteUser(String userUuid) {
        userManagementApiClient.removeUser(userUuid);
        UUID uuid = UUID.fromString(userUuid);
        certificateService.removeCertificateUser(uuid);
        objectAssociationService.removeOwnerAssociations(uuid);
        attributeEngine.deleteObjectAttributeContent(Resource.USER, UUID.fromString(userUuid));
        clearAuthenticationData(userUuid, "deleted");
    }

    private void clearAuthenticationData(String userUuid, String actionName) {
        authenticationCache.evictByUserUuid(UUID.fromString(userUuid));

        Map<String, ? extends Session> userSessions =
                sessionRepository.findByPrincipalName(userUuid);

        for (Map.Entry<String, ? extends Session> entry : userSessions.entrySet()) {
            OAuth2Util.endUserSession(entry.getValue().getAttribute("SPRING_SECURITY_CONTEXT"));
            sessionRepository.deleteById(entry.getKey());
        }
        if (!userSessions.isEmpty() && !logger.isLogFiltered(true, Module.AUTH, Resource.USER, OperationResult.SUCCESS)) {
            LoggingSettingsDto loggingSettingsDto = SettingsCache.getSettings(SettingsSection.LOGGING);
            AuditLogOutput output = loggingSettingsDto == null ? null : loggingSettingsDto.getAuditLogs().getOutput();
            auditLogsProducer.produceMessage(new AuditLogMessage(LogRecord.builder()
                    .version(schemaVersion)
                    .operation(Operation.LOGOUT)
                    .operationResult(OperationResult.SUCCESS)
                    .module(Module.AUTH)
                    .timestamp(OffsetDateTime.now())
                    .actor(LoggingHelper.getActorInfo())
                    .source(LoggingHelper.getSourceInfo())
                    .resource(ResourceRecord.builder().type(Resource.USER).objects(List.of(new ResourceObjectIdentity(null, UUID.fromString(userUuid)))).build())
                    .message("User with UUID %s has been %s".formatted(userUuid, actionName))
                    .build(), output));
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.UPDATE)
    public UserDetailDto updateRoles(String userUuid, List<String> roleUuids) {
        UserDetailDto result = userManagementApiClient.updateRoles(userUuid, roleUuids);
        authenticationCache.evictByUserUuid(UUID.fromString(userUuid));
        return result;
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.UPDATE)
    public UserDetailDto updateRole(String userUuid, String roleUuid) {
        UserDetailDto result = userManagementApiClient.updateRole(userUuid, roleUuid);
        authenticationCache.evictByUserUuid(UUID.fromString(userUuid));
        return result;
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.DETAIL)
    public SubjectPermissionsDto getPermissions(String userUuid) {
        return userManagementApiClient.getPermissions(userUuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.ENABLE)
    public UserDetailDto enableUser(String userUuid) {
        return userManagementApiClient.enableUser(userUuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.ENABLE)
    public UserDetailDto disableUser(String userUuid) {
        UserDetailDto result = userManagementApiClient.disableUser(userUuid);
        clearAuthenticationData(userUuid, "disabled");
        return result;
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.DETAIL)
    public List<RoleDto> getUserRoles(String userUuid) {
        return userManagementApiClient.getUserRoles(userUuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.UPDATE)
    public UserDetailDto removeRole(String userUuid, String roleUuid) {
        UserDetailDto result = userManagementApiClient.removeRole(userUuid, roleUuid);
        authenticationCache.evictByUserUuid(UUID.fromString(userUuid));
        return result;
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.DETAIL)
    public UserDetailDto identifyUser(UserIdentificationRequestDto request) throws NotFoundException {
        AuthenticationRequestDto authenticationRequest = new AuthenticationRequestDto();
        if (request.getCertificateContent() != null) {
            authenticationRequest.setCertificateContent(CertificateUtil.normalizeCertificateContent(request.getCertificateContent()));
        } else if (request.getAuthenticationToken() != null) {
            Map<String, Object> userClaims;
            SignedJWT signedJWT;
            try {
                signedJWT = SignedJWT.parse(request.getAuthenticationToken());
                userClaims = signedJWT.getJWTClaimsSet().getClaims();
            } catch (ParseException e) {
                throw new ValidationException("Could not extract claims from Authentication Token: " + e.getMessage());
            }
            authenticationRequest.setAuthenticationTokenUserClaims(userClaims);
        } else {
            throw new ValidationException("User cannot be identified without providing certificate or JWT token");
        }

        UserDetailDto dto = userManagementApiClient.identifyUser(authenticationRequest);
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.USER, UUID.fromString(dto.getUuid())));
        return dto;
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        UserDetailDto dto = userManagementApiClient.getUserDetail(objectUuid.toString());
        return new NameAndUuidDto(dto.getUuid(), dto.getUsername());
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return getResourceObjectInternal(objectUuid.getValue());
    }

    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        return listUsers().stream().map(u -> new NameAndUuidDto(u.getUuid(), u.getUsername())).toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getUser(uuid.toString());
    }

    private static void validateExistingCertificate(String userUuid, Certificate certificate) {
        if (certificate.isArchived())
            throw new ValidationException("Cannot assign archived certificate to the user.");
        if (!certificate.getState().equals(CertificateState.ISSUED)) {
            throw new ValidationException(ValidationError.create("Cannot assign certificate with state %s to the user".formatted(certificate.getState().getLabel())));
        }
        if (certificate.getUserUuid() != null && !certificate.getUserUuid().toString().equals(userUuid)) {
            throw new ValidationException(ValidationError.create("Cannot assign certificate to the user because it is already assigned to other user"));
        }
    }

    private void uploadNewCertificate(String userUuid, String certificateData) throws CertificateException {
        try {
            certificateService.upload(certificateData, null, UUID.fromString(userUuid));
            logger.getLogger().debug("New Certificate uploaded for the user {} has been queued for processing.", userUuid);
        } catch (Exception e) {
            throw new CertificateException("Cannot upload certificate that should be assigned to the user: " + e.getMessage());
        }
    }

    private @Nullable Certificate getExistingCertificate(String certificateUuid, String certificateData) throws NotFoundException, CertificateException {
        Certificate certificate = null;
        if (StringUtils.isNotBlank(certificateUuid)) {
            certificate = certificateService.getCertificateEntity(SecuredUUID.fromString(certificateUuid));
        } else {
            X509Certificate x509Cert = CertificateUtil.parseCertificate(certificateData);
            try {
                x509Cert.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                throw new ValidationException(ValidationError.create("Certificate is not valid."));
            }
            try {
                certificate = certificateService.getCertificateEntityByFingerprint(CertificateUtil.getThumbprint(x509Cert));
            } catch (NotFoundException e) {
               // Certificate stays null
            } catch (NoSuchAlgorithmException e) {
                throw new ValidationException(ValidationError.create("Cannot assign certificate to the user due to error in fingerprint calculation: " + e.getMessage()));
            }
        }
        return certificate;
    }

    private UserDetailDto getUserUpdateRequestPayload(String userUuid, UpdateUserRequestDto request, String certificateUuid, String certificateFingerPrint) throws NotFoundException, CertificateException {
        Certificate certificate = null;
        UserUpdateRequestDto requestDto = new UserUpdateRequestDto();

        boolean certificateInRequest = (request.getCertificateUuid() != null && !request.getCertificateUuid().isEmpty()) || (request.getCertificateData() != null && !request.getCertificateData().isEmpty());
        if (certificateInRequest) {
            certificate = getExistingCertificate(request.getCertificateUuid(), request.getCertificateData());
            if (certificate != null) {
                validateExistingCertificate(userUuid, certificate);
                requestDto.setCertificateUuid(certificate.getUuid().toString());
                requestDto.setCertificateFingerprint(certificate.getFingerprint());
            }
        } else {
            if (!certificateUuid.isEmpty()) requestDto.setCertificateUuid(certificateUuid);
            if (!certificateFingerPrint.isEmpty()) requestDto.setCertificateFingerprint(certificateFingerPrint);
        }

        requestDto.setDescription(request.getDescription());
        requestDto.setEmail(request.getEmail());
        requestDto.setFirstName(request.getFirstName());
        requestDto.setLastName(request.getLastName());

        if (request.getGroupUuids() != null) {
            List<NameAndUuidDto> groups = new ArrayList<>();
            for (String groupUuid : request.getGroupUuids()) {
                GroupDto groupDto = groupService.getGroup(SecuredUUID.fromString(groupUuid));
                groups.add(new NameAndUuidDto(groupDto.getUuid(), groupDto.getName()));
            }
            requestDto.setGroups(groups);
        }

        UserDetailDto response = userManagementApiClient.updateUser(userUuid, requestDto);

        try {
            certificateService.removeCertificateUser(UUID.fromString(response.getUuid()));
        } catch (Exception e) {
            logger.getLogger().info("Unable to remove user uuid. It may not exists {}", e.getMessage());
        }
        if (certificate != null) {
            certificateService.updateCertificateUser(certificate.getUuid(), response.getUuid());
        } else if (certificateInRequest) {
            uploadNewCertificate(response.getUuid(), request.getCertificateData());
        }
        return response;
    }
}
