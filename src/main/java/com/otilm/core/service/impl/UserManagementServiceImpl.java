package com.otilm.core.service.impl;

import com.nimbusds.jwt.SignedJWT;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.auth.AddUserRequestDto;
import com.otilm.api.model.client.auth.UpdateUserRequestDto;
import com.otilm.api.model.client.auth.UserIdentificationRequestDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.RoleDto;
import com.otilm.api.model.core.auth.SubjectPermissionsDto;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.api.model.core.auth.UserRequestDto;
import com.otilm.api.model.core.auth.UserUpdateRequestDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.group.GroupDto;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.api.model.core.logging.records.ResourceRecord;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.logging.LoggerWrapper;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.messaging.jms.producers.AuditLogsProducer;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.model.auth.AuthenticationRequestDto;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.RoleAssignmentGuard;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.CertificateUploadService;
import com.otilm.core.service.GroupExternalService;
import com.otilm.core.service.ListViewInternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.UserManagementExternalService;
import com.otilm.core.service.UserManagementInternalService;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.OAuth2Util;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.DefaultTransactionDefinition;

@Service(Resource.Codes.USER)
@Transactional
public class UserManagementServiceImpl implements UserManagementExternalService, UserManagementInternalService {
    private static final LoggerWrapper logger = new LoggerWrapper(UserManagementServiceImpl.class, Module.AUTH,
            Resource.USER);

    @Value("${logging.schema-version}")
    private String schemaVersion;

    private UserManagementApiClient userManagementApiClient;

    private CertificateInternalService certificateService;

    private PlatformTransactionManager transactionManager;
    private CertificateUploadService certificateUploadService;
    private GroupExternalService groupService;
    private ResourceObjectAssociationService objectAssociationService;
    private ListViewInternalService listViewService;
    private AuditLogsProducer auditLogsProducer;

    private AttributeEngine attributeEngine;

    private FindByIndexNameSessionRepository<? extends Session> sessionRepository;

    private AuthenticationCache authenticationCache;

    private RoleAssignmentGuard roleAssignmentGuard;

    @Autowired
    public void setRoleAssignmentGuard(RoleAssignmentGuard roleAssignmentGuard) {
        this.roleAssignmentGuard = roleAssignmentGuard;
    }

    @Autowired
    public void setCertificateUploadService(CertificateUploadService certificateUploadService) {
        this.certificateUploadService = certificateUploadService;
    }

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
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }

    @Autowired
    public void setCertificateService(CertificateInternalService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setGroupService(GroupExternalService groupService) {
        this.groupService = groupService;
    }

    @Autowired
    public void setObjectAssociationService(ResourceObjectAssociationService objectAssociationService) {
        this.objectAssociationService = objectAssociationService;
    }

    @Autowired
    public void setListViewService(ListViewInternalService listViewService) {
        this.listViewService = listViewService;
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
        dto
                .setCustomAttributes(
                        attributeEngine.getObjectCustomAttributesContent(Resource.USER, UUID.fromString(userUuid)));
        return dto;
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.CREATE)
    public UserDetailDto createUser(AddUserRequestDto request)
            throws CertificateException, NotFoundException, AttributeException {
        attributeEngine.validateCustomAttributesContent(Resource.USER, request.getCustomAttributes());
        if (StringUtils.isBlank(request.getUsername())) {
            throw new ValidationException(ValidationError.create("username must not be empty"));
        }
        UserRequestDto requestDto = new UserRequestDto();
        requestDto.setGroups(resolveGroups(request.getGroupUuids()));

        ResolvedCertificate resolved = null;
        if (StringUtils.isNotBlank(request.getCertificateUuid())
                || StringUtils.isNotBlank(request.getCertificateData())) {
            resolved = resolveUserCertificate(null, request.getCertificateUuid(), request.getCertificateData(),
                    request.getCertificateCustomAttributes());
            requestDto.setCertificateUuid(resolved.certificate().getUuid().toString());
            requestDto.setCertificateFingerprint(resolved.certificate().getFingerprint());
        }
        requestDto.setEmail(request.getEmail());
        requestDto.setEnabled(request.getEnabled());
        requestDto.setUsername(request.getUsername());
        requestDto.setFirstName(request.getFirstName());
        requestDto.setLastName(request.getLastName());
        requestDto.setDescription(request.getDescription());

        UserDetailDto response = userManagementApiClient.createUser(requestDto);

        ResolvedCertificate assigned = resolved;
        if (assigned != null) {
            inShortTransaction(() -> certificateService
                    .updateCertificateUser(assigned.certificate().getUuid(), response.getUuid()));
            inShortTransaction(
                    () -> applyCertificateCustomAttributes(assigned, request.getCertificateCustomAttributes()));
        }

        // The engine runs this in a transaction of its own, so a refusal here cannot undo the certificate
        // attributes that are already committed, as it would if the two shared one.
        response
                .setCustomAttributes(attributeEngine
                        .updateObjectCustomAttributesContent(Resource.USER, UUID.fromString(response.getUuid()),
                                request.getCustomAttributes()));

        logger.logEvent(Operation.CREATE, OperationResult.SUCCESS, response.toLogData(), null, null);
        return response;
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.UPDATE)
    public UserDetailDto updateUser(String userUuid, UpdateUserRequestDto request)
            throws NotFoundException, CertificateException, AttributeException {
        attributeEngine.validateCustomAttributesContent(Resource.USER, request.getCustomAttributes());
        try {
            UserDetailDto dto = getUserUpdateRequestPayload(userUuid, request, "", "");
            dto
                    .setCustomAttributes(attributeEngine
                            .updateObjectCustomAttributesContent(Resource.USER, UUID.fromString(userUuid),
                                    request.getCustomAttributes()));
            return dto;
        } finally {
            // The association commits in a transaction of its own, so a later failure still leaves the cached
            // authentication stale. Dropping it on the failing path costs a reload and nothing else.
            authenticationCache.evictByUserUuid(UUID.fromString(userUuid));
        }
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    // Internal Use Only -- For Auth Profile Update API
    public UserDetailDto updateUserInternal(String userUuid, UpdateUserRequestDto request, String certificateUuid,
            String certificateFingerprint) throws NotFoundException, CertificateException {
        try {
            return getUserUpdateRequestPayload(userUuid, request, certificateUuid, certificateFingerprint);
        } finally {
            authenticationCache.evictByUserUuid(UUID.fromString(userUuid));
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.DELETE)
    public void deleteUser(String userUuid) {
        userManagementApiClient.removeUser(userUuid);
        UUID uuid = UUID.fromString(userUuid);
        certificateService.removeCertificateUser(uuid);
        objectAssociationService.removeOwnerAssociations(uuid);
        listViewService.deleteViewsOfUser(uuid);
        attributeEngine.deleteObjectAttributeContent(Resource.USER, UUID.fromString(userUuid));
        clearAuthenticationData(userUuid, "deleted");
    }

    private void clearAuthenticationData(String userUuid, String actionName) {
        authenticationCache.evictByUserUuid(UUID.fromString(userUuid));

        Map<String, ? extends Session> userSessions = sessionRepository.findByPrincipalName(userUuid);

        for (Map.Entry<String, ? extends Session> entry : userSessions.entrySet()) {
            OAuth2Util.endUserSession(entry.getValue().getAttribute("SPRING_SECURITY_CONTEXT"));
            sessionRepository.deleteById(entry.getKey());
        }
        if (!userSessions.isEmpty()
                && !logger.isLogFiltered(true, Module.AUTH, Resource.USER, OperationResult.SUCCESS)) {
            LoggingSettingsDto loggingSettingsDto = SettingsCache.getSettings(SettingsSection.LOGGING);
            AuditLogOutput output = loggingSettingsDto == null ? null : loggingSettingsDto.getAuditLogs().getOutput();
            auditLogsProducer
                    .produceMessage(new AuditLogMessage(LogRecord
                            .builder()
                            .version(schemaVersion)
                            .operation(Operation.LOGOUT)
                            .operationResult(OperationResult.SUCCESS)
                            .module(Module.AUTH)
                            .timestamp(OffsetDateTime.now())
                            .actor(LoggingHelper.getActorInfo())
                            .source(LoggingHelper.getSourceInfo())
                            .resource(ResourceRecord
                                    .builder()
                                    .type(Resource.USER)
                                    .objects(List.of(new ResourceObjectIdentity(null, UUID.fromString(userUuid))))
                                    .build())
                            .message("User with UUID %s has been %s".formatted(userUuid, actionName))
                            .build(), output));
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.UPDATE)
    public UserDetailDto updateRoles(String userUuid, List<String> roleUuids) {
        roleAssignmentGuard.checkRolesAssignableToUser(userUuid, roleUuids);
        roleAssignmentGuard.checkRolesRetainedForUser(userUuid, roleUuids);
        UserDetailDto result = userManagementApiClient.updateRoles(userUuid, roleUuids);
        authenticationCache.evictByUserUuid(UUID.fromString(userUuid));
        return result;
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.UPDATE)
    public UserDetailDto updateRole(String userUuid, String roleUuid) {
        roleAssignmentGuard.checkRolesAssignableToUser(userUuid, List.of(roleUuid));
        return updateRoleInternal(userUuid, roleUuid);
    }

    @Override
    public UserDetailDto updateRoleInternal(String userUuid, String roleUuid) {
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
        rejectSystemUser(userUuid);
        return userManagementApiClient.enableUser(userUuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.ENABLE)
    public UserDetailDto disableUser(String userUuid) {
        rejectSystemUser(userUuid);
        UserDetailDto result = userManagementApiClient.disableUser(userUuid);
        clearAuthenticationData(userUuid, "disabled");
        return result;
    }

    /**
     * A system user's account state carries the identity as much as its role does — disabling acme stops ACME enrolment
     * as surely as detaching its role would.
     */
    private void rejectSystemUser(String userUuid) {
        UserDetailDto user = userManagementApiClient.getUserDetail(userUuid);
        if (user != null && Boolean.TRUE.equals(user.getSystemUser())) {
            throw new ValidationException(
                    "User '%s' is a system user and its state cannot be changed.".formatted(user.getUsername()));
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.DETAIL)
    public List<RoleDto> getUserRoles(String userUuid) {
        return userManagementApiClient.getUserRoles(userUuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.UPDATE)
    public UserDetailDto removeRole(String userUuid, String roleUuid) {
        roleAssignmentGuard.checkRoleRemovableFromUser(userUuid, roleUuid);
        UserDetailDto result = userManagementApiClient.removeRole(userUuid, roleUuid);
        authenticationCache.evictByUserUuid(UUID.fromString(userUuid));
        return result;
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.DETAIL)
    public UserDetailDto identifyUser(UserIdentificationRequestDto request) throws NotFoundException {
        AuthenticationRequestDto authenticationRequest = new AuthenticationRequestDto();
        if (request.getCertificateContent() != null) {
            authenticationRequest
                    .setCertificateContent(
                            CertificateUtil.normalizeCertificateContent(request.getCertificateContent()));
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
        dto
                .setCustomAttributes(attributeEngine
                        .getObjectCustomAttributesContent(Resource.USER, UUID.fromString(dto.getUuid())));
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
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters,
            PaginationRequestDto pagination) {
        return listUsers().stream().map(u -> new NameAndUuidDto(u.getUuid(), u.getUsername())).toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.USER, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getUser(uuid.toString());
    }

    private List<NameAndUuidDto> resolveGroups(List<String> groupUuids) throws NotFoundException {
        List<NameAndUuidDto> groups = new ArrayList<>();
        if (groupUuids == null) {
            return groups;
        }
        for (String groupUuid : groupUuids) {
            GroupDto groupDto = groupService.getGroup(SecuredUUID.fromString(groupUuid));
            groups.add(new NameAndUuidDto(groupDto.getUuid(), groupDto.getName()));
        }
        return groups;
    }

    private ResolvedCertificate resolveUserCertificate(String userUuid, String certificateUuid, String certificateData,
            List<RequestAttribute> certificateCustomAttributes) throws CertificateException, NotFoundException {
        Certificate certificate = null;
        boolean uploadCertificate = false;
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
                certificate = certificateService
                        .getCertificateEntityByFingerprint(CertificateUtil.getThumbprint(x509Cert));
            } catch (NotFoundException e) {
                uploadCertificate = true;
            } catch (NoSuchAlgorithmException e) {
                throw new ValidationException(ValidationError
                        .create("Cannot assign certificate to the user due to error in fingerprint calculation: "
                                + e.getMessage()));
            }
        }

        if (uploadCertificate) {
            return new ResolvedCertificate(uploadCertificate(certificateData, certificateCustomAttributes), true);
        } else {
            if (certificate.isArchived()) {
                throw new ValidationException("Cannot assign archived certificate to the user.");
            }
            if (!certificate.getState().equals(CertificateState.ISSUED)) {
                throw new ValidationException(ValidationError
                        .create("Cannot assign certificate with state %s to the user"
                                .formatted(certificate.getState().getLabel())));
            }
            if (certificate.getUserUuid() != null && !certificate.getUserUuid().toString().equals(userUuid)) {
                throw new ValidationException(ValidationError
                        .create("Cannot assign certificate to the user because it is already assigned to other user"));
            }
            if (certificateCustomAttributes != null && !certificateCustomAttributes.isEmpty()) {
                certificateService.evaluatePermissionChain(SecuredUUID.fromUUID(certificate.getUuid()));
                attributeEngine.validateCustomAttributesContent(Resource.CERTIFICATE, certificateCustomAttributes);
                checkCertificateCustomAttributePermissions(certificateCustomAttributes);
            }
        }
        return new ResolvedCertificate(certificate, false);
    }

    /** Carries whether the certificate was uploaded by this request, which decides where its attributes are written. */
    private record ResolvedCertificate(Certificate certificate, boolean uploaded) {
    }

    /**
     * Content validation drops the attributes the caller may not edit instead of refusing them, so without this the
     * refusal would come from the write, after the auth service has already accepted the user.
     */
    private void checkCertificateCustomAttributePermissions(List<RequestAttribute> certificateCustomAttributes)
            throws CertificateException, NotFoundException {
        try {
            attributeEngine.validateCustomAttributesUpdatePermissions(certificateCustomAttributes);
        } catch (AttributeException e) {
            logger.getLogger().error("Refused certificate custom attributes for the user request", e);
            throw new CertificateException(
                    "Cannot set custom attributes of the certificate that should be assigned to the user");
        }
    }

    private void detachCurrentCertificateUser(String userUuid) {
        try {
            certificateService.removeCertificateUser(UUID.fromString(userUuid));
        } catch (Exception e) {
            logger.getLogger().info("Unable to remove user uuid. It may not exists {}", e.getMessage());
        }
    }

    @FunctionalInterface
    private interface LocalWrite {
        void run() throws CertificateException, NotFoundException;
    }

    /**
     * Commits the writes in a transaction of their own, so nothing stays locked across the auth service call. A commit
     * that fails has already completed the transaction, and rolling a completed one back would throw over the original
     * failure.
     */
    private void inShortTransaction(LocalWrite write) throws CertificateException, NotFoundException {
        TransactionStatus status = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            write.run();
            transactionManager.commit(status);
        } catch (RuntimeException | CertificateException | NotFoundException e) {
            if (!status.isCompleted()) {
                transactionManager.rollback(status);
            }
            throw e;
        }
    }

    private void applyCertificateCustomAttributes(ResolvedCertificate resolved,
            List<RequestAttribute> certificateCustomAttributes) throws CertificateException, NotFoundException {
        if (resolved.uploaded() || certificateCustomAttributes == null || certificateCustomAttributes.isEmpty()) {
            return;
        }
        try {
            attributeEngine
                    .updateObjectCustomAttributesContent(Resource.CERTIFICATE, resolved.certificate().getUuid(),
                            certificateCustomAttributes);
        } catch (AttributeException e) {
            logger
                    .getLogger()
                    .error("Cannot set custom attributes of certificate {}", resolved.certificate().getUuid(), e);
            throw new CertificateException(
                    "Cannot set custom attributes of the certificate that should be assigned to the user");
        }
    }

    private Certificate uploadCertificate(String certificateData, List<RequestAttribute> certificateCustomAttributes)
            throws CertificateException {
        Certificate certificate;
        try {
            String fingerprint = certificateUploadService.upload(certificateData, certificateCustomAttributes, true);
            certificate = certificateService.getCertificateEntityByFingerprint(fingerprint);
            logger.getLogger().debug("New Certificate uploaded for the user");
        } catch (ValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateException(
                    "Cannot upload certificate that should be assigned to the user: " + e.getMessage());
        }
        return certificate;
    }

    private UserDetailDto getUserUpdateRequestPayload(String userUuid, UpdateUserRequestDto request,
            String certificateUuid, String certificateFingerPrint) throws NotFoundException, CertificateException {
        ResolvedCertificate resolved = null;
        UserUpdateRequestDto requestDto = new UserUpdateRequestDto();
        if (request.getGroupUuids() != null) {
            requestDto.setGroups(resolveGroups(request.getGroupUuids()));
        }

        if (StringUtils.isNotBlank(request.getCertificateUuid())
                || StringUtils.isNotBlank(request.getCertificateData())) {
            resolved = resolveUserCertificate(userUuid, request.getCertificateUuid(), request.getCertificateData(),
                    request.getCertificateCustomAttributes());
            requestDto.setCertificateUuid(resolved.certificate().getUuid().toString());
            requestDto.setCertificateFingerprint(resolved.certificate().getFingerprint());
        } else {
            if (!certificateUuid.isEmpty()) {
                requestDto.setCertificateUuid(certificateUuid);
            }
            if (!certificateFingerPrint.isEmpty()) {
                requestDto.setCertificateFingerprint(certificateFingerPrint);
            }
        }

        requestDto.setDescription(request.getDescription());
        requestDto.setEmail(request.getEmail());
        requestDto.setFirstName(request.getFirstName());
        requestDto.setLastName(request.getLastName());

        UserDetailDto response = userManagementApiClient.updateUser(userUuid, requestDto);

        ResolvedCertificate assigned = resolved;
        inShortTransaction(() -> {
            detachCurrentCertificateUser(response.getUuid());
            if (assigned != null) {
                certificateService.updateCertificateUser(assigned.certificate().getUuid(), response.getUuid());
            }
        });
        if (assigned != null) {
            inShortTransaction(
                    () -> applyCertificateCustomAttributes(assigned, request.getCertificateCustomAttributes()));
        }
        return response;
    }
}
