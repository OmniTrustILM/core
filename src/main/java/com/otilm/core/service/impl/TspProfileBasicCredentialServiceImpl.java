package com.otilm.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.protocols.tsp.TspBasicCredentialDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspBasicCredentialRequestDto;
import com.otilm.api.model.connector.secrets.content.BasicAuthSecretContent;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.secret.SecretDetailDto;
import com.otilm.api.model.core.secret.SecretRequestDto;
import com.otilm.api.model.core.secret.SecretUpdateRequestDto;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.entity.signing.TspProfileBasicCredential;
import com.otilm.core.dao.repository.signing.TspProfileBasicCredentialRepository;
import com.otilm.core.dao.repository.signing.TspProfileRepository;
import com.otilm.core.mapper.signing.TspProfileBasicCredentialMapper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.client.CredentialVerificationCache;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.TspProfileBasicCredentialService;
import com.otilm.core.service.SecretService;
import com.otilm.core.service.UserManagementService;
import com.otilm.core.service.VaultProfileService;
import com.otilm.core.service.writer.signing.TspProfileBasicCredentialWriter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service(Resource.Codes.TSP_PROFILE_BASIC_CREDENTIAL)
@Slf4j
public class TspProfileBasicCredentialServiceImpl implements TspProfileBasicCredentialService {

    private TspProfileRepository tspProfileRepository;
    private TspProfileBasicCredentialRepository credentialRepository;
    private TspProfileBasicCredentialWriter credentialWriter;
    private VaultProfileService vaultProfileService;
    private SecretService secretService;
    private UserManagementService userManagementService;
    private CredentialVerificationCache credentialVerificationCache;
    private CacheEvictor cacheEvictor;

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE_BASIC_CREDENTIAL, action = ResourceAction.LIST, parentResource = Resource.TSP_PROFILE, parentAction = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public List<TspBasicCredentialDto> list(SecuredParentUUID tspProfileUuid) throws NotFoundException {
        TspProfile profile = getTspProfile(tspProfileUuid);
        return credentialRepository.findByTspProfileUuid(profile.getUuid()).stream()
                .map(c -> TspProfileBasicCredentialMapper.mapToDto(c, resolveUserName(c.getMappedUserUuid())))
                .toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE_BASIC_CREDENTIAL, action = ResourceAction.DETAIL, parentResource = Resource.TSP_PROFILE, parentAction = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public TspBasicCredentialDto get(SecuredParentUUID tspProfileUuid, SecuredUUID uuid) throws NotFoundException {
        TspProfileBasicCredential row = getCredentialScoped(tspProfileUuid, uuid);
        return TspProfileBasicCredentialMapper.mapToDto(row, resolveUserName(row.getMappedUserUuid()));
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE_BASIC_CREDENTIAL, action = ResourceAction.CREATE, parentResource = Resource.TSP_PROFILE, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public TspBasicCredentialDto create(SecuredParentUUID tspProfileUuid, TspBasicCredentialRequestDto request) throws AlreadyExistException, AttributeException, ConnectorCommunicationException, NotFoundException {
        TspProfile profile = getTspProfile(tspProfileUuid);
        if (profile.getVaultProfileUuid() == null) {
            throw new ValidationException("A vault profile is required on the TSP profile before adding Basic credentials.");
        }
        if (request.getPassword() == null || request.getPassword().isBlank()) {
            throw new ValidationException("Password is required when creating a Basic credential.");
        }
        validateMappedUserExists(request.getMappedUserUuid());

        UUID secretUuid = createVaultSecret(profile, request.getUsername(), request.getPassword());
        TspProfileBasicCredential row = new TspProfileBasicCredential();
        row.setTspProfile(profile);
        row.setUsername(request.getUsername());
        row.setSecretUuid(secretUuid);
        row.setMappedUserUuid(request.getMappedUserUuid());
        try {
            row = credentialWriter.insert(row);
        } catch (DataIntegrityViolationException e) {
            deleteVaultSecretQuietly(secretUuid);
            throw new AlreadyExistException("A Basic credential with username '" + request.getUsername() + "' already exists on this profile.");
        } catch (RuntimeException e) {
            deleteVaultSecretQuietly(secretUuid);
            log.warn("Failed to persist Basic credential for TSP Profile {}", profile.getUuid(), e);
            throw e;
        }
        evictModelCache(profile.getName());
        return TspProfileBasicCredentialMapper.mapToDto(row, resolveUserName(row.getMappedUserUuid()));
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE_BASIC_CREDENTIAL, action = ResourceAction.UPDATE, parentResource = Resource.TSP_PROFILE, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public TspBasicCredentialDto update(SecuredParentUUID tspProfileUuid, SecuredUUID uuid, TspBasicCredentialRequestDto request) throws AlreadyExistException, AttributeException, ConnectorCommunicationException, NotFoundException {
        TspProfile profile = getTspProfile(tspProfileUuid);
        TspProfileBasicCredential credential = getCredentialScoped(tspProfileUuid, uuid);
        ensureUsernameAvailable(profile.getUuid(), request.getUsername(), credential.getUuid());
        validateMappedUserExists(request.getMappedUserUuid());

        // Vault rotation can run only when a new password is supplied.
        // On a username-only change the secret's stored username is left stale - it is informational only;
        // verification reads the username from the credential row, never from the secret content.
        // A later password rotation heals it, since rotation writes the current username too.
        boolean rotate = request.getPassword() != null && !request.getPassword().isBlank();
        if (rotate) {
            rotateVaultSecret(credential.getSecretUuid(), request.getUsername(), request.getPassword());
        }
        boolean mappedUserChanged = !Objects.equals(credential.getMappedUserUuid(), request.getMappedUserUuid());
        credential.setUsername(request.getUsername());
        credential.setMappedUserUuid(request.getMappedUserUuid());
        try {
            credential = credentialWriter.update(credential);
        } catch (DataIntegrityViolationException e) {
            throw new AlreadyExistException("A Basic credential with username '" + request.getUsername() + "' already exists on this profile.");
        }

        if (rotate || mappedUserChanged) {
            credentialVerificationCache.evictBySecretUuid(credential.getSecretUuid());
        }
        evictModelCache(profile.getName());
        return TspProfileBasicCredentialMapper.mapToDto(credential, resolveUserName(credential.getMappedUserUuid()));
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE_BASIC_CREDENTIAL, action = ResourceAction.DELETE, parentResource = Resource.TSP_PROFILE, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void delete(SecuredParentUUID tspProfileUuid, SecuredUUID uuid) throws AttributeException, ConnectorCommunicationException, NotFoundException {
        TspProfile profile = getTspProfile(tspProfileUuid);
        TspProfileBasicCredential credential = getCredentialScoped(tspProfileUuid, uuid);
        UUID secretUuid = credential.getSecretUuid();

        deleteVaultSecret(secretUuid);
        credentialWriter.deleteByUuid(credential.getUuid());
        credentialVerificationCache.evictBySecretUuid(secretUuid);
        evictModelCache(profile.getName());
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void deleteSecretsForProfile(UUID tspProfileUuid) {
        for (TspProfileBasicCredential credential : credentialRepository.findByTspProfileUuid(tspProfileUuid)) {
            UUID secretUuid = credential.getSecretUuid();
            try {
                deleteVaultSecret(secretUuid);
            } catch (AttributeException | ConnectorCommunicationException e) {
                log.warn("Could not delete vault secret {} during TSP profile {} teardown; manual reconciliation may be needed.",
                        secretUuid, tspProfileUuid, e);
            }
            credentialVerificationCache.evictBySecretUuid(secretUuid);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public void evictCachesForSecret(UUID secretUuid) {
        credentialRepository.findBySecretUuid(secretUuid).ifPresent(credential -> {
            evictModelCache(credential.getTspProfile().getName());
            credentialVerificationCache.evictBySecretUuid(secretUuid);
        });
    }

    private TspProfile getTspProfile(SecuredParentUUID tspProfileUuid) throws NotFoundException {
        return tspProfileRepository.findByUuid(SecuredUUID.fromUUID(tspProfileUuid.getValue()))
                .orElseThrow(() -> new NotFoundException("TSP Profile not found: " + tspProfileUuid));
    }

    private TspProfileBasicCredential getCredentialScoped(SecuredParentUUID tspProfileUuid, SecuredUUID uuid) throws NotFoundException {
        TspProfileBasicCredential row = credentialRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException("Basic credential not found: " + uuid));
        if (!row.getTspProfileUuid().equals(tspProfileUuid.getValue())) {
            throw new NotFoundException("Basic credential " + uuid + " does not belong to TSP profile " + tspProfileUuid);
        }
        return row;
    }

    /**
     * Rejects a username already taken by a different credential on the same profile, BEFORE any vault rotation runs.
     */
    private void ensureUsernameAvailable(UUID tspProfileUuid, String username, UUID excludeCredentialUuid) throws AlreadyExistException {
        Optional<TspProfileBasicCredential> existing = credentialRepository.findByTspProfileUuidAndUsername(tspProfileUuid, username);
        if (existing.isPresent() && !existing.get().getUuid().equals(excludeCredentialUuid)) {
            throw new AlreadyExistException("A Basic credential with username '" + username + "' already exists on this profile.");
        }
    }

    private UUID createVaultSecret(TspProfile profile, String username, String password)
            throws AlreadyExistException, AttributeException, ConnectorCommunicationException, NotFoundException {
        VaultProfile vaultProfile = resolveVaultProfile(profile.getVaultProfileUuid());
        UUID vaultInstanceUuid = vaultProfile.getVaultInstanceUuid();
        SecretRequestDto secretRequest = new SecretRequestDto();
        secretRequest.setName("tsp-basic-" + profile.getUuid() + "-" + username + "-" + UUID.randomUUID().toString().substring(0, 8));
        secretRequest.setSecret(new BasicAuthSecretContent(username, password));
        try {
            SecretDetailDto created = secretService.createSecret(secretRequest,
                    SecuredParentUUID.fromUUID(vaultProfile.getUuid()), SecuredUUID.fromUUID(vaultInstanceUuid));
            return UUID.fromString(created.getUuid());
        } catch (ConnectorException e) {
            throw vaultUnavailable("create", profile.getUuid().toString(), e);
        }
    }

    private void rotateVaultSecret(UUID secretUuid, String username, String password)
            throws AttributeException, ConnectorCommunicationException, NotFoundException {
        SecretUpdateRequestDto updateRequest = new SecretUpdateRequestDto();
        updateRequest.setSecret(new BasicAuthSecretContent(username, password));
        try {
            secretService.updateSecret(secretUuid, updateRequest);
        } catch (ConnectorException e) {
            throw vaultUnavailable("rotate", secretUuid.toString(), e);
        }
    }

    private void deleteVaultSecret(UUID secretUuid) throws AttributeException, ConnectorCommunicationException {
        try {
            secretService.deleteSecret(secretUuid, true);
        } catch (NotFoundException e) {
            log.info("Basic credential secret {} already absent in vault; treating delete as idempotent.", secretUuid);
        } catch (ConnectorException e) {
            throw vaultUnavailable("delete", secretUuid.toString(), e);
        }
    }

    private ConnectorCommunicationException vaultUnavailable(String operation, String reference, ConnectorException cause) {
        log.warn("Vault connector unavailable while trying to {} Basic credential secret (ref={})", operation, reference, cause);
        return new ConnectorCommunicationException("The vault connector is currently unavailable.", null);
    }

    private void deleteVaultSecretQuietly(UUID secretUuid) {
        try {
            secretService.deleteSecret(secretUuid, true);
        } catch (AttributeException | ConnectorException | NotFoundException e) {
            log.warn("Orphan Basic credential secret {} could not be cleaned up after a failed insert; manual reconciliation may be needed.", secretUuid, e);
        }
    }

    private VaultProfile resolveVaultProfile(UUID vaultProfileUuid) {
        if (vaultProfileUuid == null) {
            throw new ValidationException("A vault profile is required when Basic credentials are configured.");
        }
        try {
            return vaultProfileService.getVaultProfileEntity(SecuredUUID.fromUUID(vaultProfileUuid));
        } catch (NotFoundException e) {
            throw new ValidationException("Vault profile does not exist: " + vaultProfileUuid);
        }
    }

    private void validateMappedUserExists(UUID mappedUserUuid) throws NotFoundException {
        UserDetailDto user = userManagementService.getUser(mappedUserUuid.toString());
        if (user == null) {
            throw new NotFoundException("Mapped user does not exist: " + mappedUserUuid);
        }
    }

    private String resolveUserName(UUID mappedUserUuid) {
        try {
            UserDetailDto user = userManagementService.getUser(mappedUserUuid.toString());
            return user != null ? user.getUsername() : null;
        } catch (NotFoundException e) {
            // Best-effort display-name lookup: a mapped user that no longer exists resolves to null.
            return null;
        }
    }

    private void evictModelCache(String profileName) {
        cacheEvictor.evict(CacheConfig.TSP_PROFILE_CACHE, profileName);
    }

    @Autowired
    public void setTspProfileRepository(TspProfileRepository tspProfileRepository) {
        this.tspProfileRepository = tspProfileRepository;
    }

    @Autowired
    public void setCredentialRepository(TspProfileBasicCredentialRepository credentialRepository) {
        this.credentialRepository = credentialRepository;
    }

    @Autowired
    public void setCredentialWriter(TspProfileBasicCredentialWriter credentialWriter) {
        this.credentialWriter = credentialWriter;
    }

    @Autowired
    public void setVaultProfileService(VaultProfileService vaultProfileService) {
        this.vaultProfileService = vaultProfileService;
    }

    @Autowired
    public void setSecretService(SecretService secretService) {
        this.secretService = secretService;
    }

    @Autowired
    public void setUserManagementService(UserManagementService userManagementService) {
        this.userManagementService = userManagementService;
    }

    @Autowired
    public void setCredentialVerificationCache(CredentialVerificationCache credentialVerificationCache) {
        this.credentialVerificationCache = credentialVerificationCache;
    }

    @Autowired
    public void setCacheEvictor(CacheEvictor cacheEvictor) {
        this.cacheEvictor = cacheEvictor;
    }
}
