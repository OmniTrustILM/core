package com.otilm.core.service.impl;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.inspection.InspectedEntryDto;
import com.otilm.api.model.client.inspection.InspectionRequestDto;
import com.otilm.api.model.client.inspection.InspectionResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.container.Container;
import com.otilm.core.container.ContainerEntry;
import com.otilm.core.container.ContainerReader;
import com.otilm.core.container.InspectedEntryMapper;
import com.otilm.core.container.KeyEntry;
import com.otilm.core.key.normalization.KeyDescription;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorizationProgrammatic;
import com.otilm.core.service.FileInspectionExternalService;
import com.otilm.core.service.handler.KeyImportGates;
import com.otilm.core.service.handler.KeyImportGates.KeyKind;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Reads an uploaded file and reports what it holds, storing nothing.
 *
 * <p>
 * Reading a file is the first step of importing it, so whoever may import either half of what a file can hold may read
 * it: certificates or keys. A caller who names a token profile passes the checks the key import makes on it, and learns
 * of each key whether the profile would take it; that answer is the only thing a connector is asked.
 * </p>
 */
@Service
@Transactional(propagation = Propagation.NOT_SUPPORTED)
public class FileInspectionServiceImpl implements FileInspectionExternalService {

    static final String UNSUPPORTED_ALGORITHM = "The platform does not support the key's algorithm.";
    private static final String NOT_A_UUID = "tokenProfileUuid must be a UUID";
    private static final String UNANSWERED = "The connector of token profile %s did not answer what the profile imports. Try again.";

    private static final Logger logger = LoggerFactory.getLogger(FileInspectionServiceImpl.class);

    private final AuthorizationEnforcer authorizationEnforcer;
    private final KeyImportGates keyImportGates;
    private final ContainerReader containerReader;

    public FileInspectionServiceImpl(AuthorizationEnforcer authorizationEnforcer, KeyImportGates keyImportGates,
            ContainerReader containerReader) {
        this.authorizationEnforcer = authorizationEnforcer;
        this.keyImportGates = keyImportGates;
        this.containerReader = containerReader;
    }

    /**
     * Checks the caller before the file is read; the copy of the file read and the keys the file's entries keep are
     * overwritten whatever the outcome.
     */
    @Override
    @ExternalAuthorizationProgrammatic(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    public InspectionResponseDto inspect(InspectionRequestDto request) throws NotFoundException {
        try {
            authorizationEnforcer.enforce(Resource.CERTIFICATE, ResourceAction.CREATE);
        } catch (AccessDeniedException e) {
            authorizationEnforcer.enforce(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.IMPORT_KEY);
        }
        TokenProfileFullModel profile = request.getTokenProfileUuid() == null
                ? null
                : requireProfile(request.getTokenProfileUuid());
        byte[] file = request.getFile().content();
        try {
            Container container = containerReader.read(file, request.getPassphrase());
            try {
                InspectionResponseDto response = new InspectionResponseDto();
                response.setContainerDigest(container.digest());
                response.setEntries(entriesOf(container, profile));
                return response;
            } finally {
                container.clear();
            }
        } finally {
            Arrays.fill(file, (byte) 0);
        }
    }

    /** The named profile, which the caller may import keys into, named in the audit record. */
    private TokenProfileFullModel requireProfile(String tokenProfileUuid) throws NotFoundException {
        UUID uuid;
        try {
            uuid = UUID.fromString(tokenProfileUuid);
        } catch (IllegalArgumentException e) {
            throw new ValidationException(ValidationError.create(NOT_A_UUID));
        }
        TokenProfileFullModel profile = keyImportGates.requireAccess(uuid);
        authorizationEnforcer.enforce(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.IMPORT_KEY);
        LoggingHelper.putLogResourceInfo(Resource.TOKEN_PROFILE, true, uuid.toString(), profile.name());
        return profile;
    }

    /** The entries in file order, each key with whether the profile takes it when one is named. */
    private List<InspectedEntryDto> entriesOf(Container container, TokenProfileFullModel profile)
            throws NotFoundException {
        Map<KeyKind, Optional<String>> reasons = profile == null ? Map.of() : reasonsAgainst(profile, container);
        List<InspectedEntryDto> entries = new ArrayList<>();
        for (ContainerEntry entry : container.entries()) {
            InspectedEntryDto inspected = InspectedEntryMapper.map(entry);
            if (profile != null && entry instanceof KeyEntry key) {
                Optional<String> reason = key.description().supported()
                        ? reasons.get(kindOf(key.description()))
                        : Optional.of(UNSUPPORTED_ALGORITHM);
                inspected.setImportable(reason.isEmpty());
                inspected.setNotImportableReason(reason.orElse(null));
            }
            entries.add(inspected);
        }
        return entries;
    }

    /**
     * Why the profile cannot take each kind of key the file holds, from one answer of its connector. While the
     * connector cannot answer what the profile imports, every key is reported as not importable, as the profile itself
     * is shown then, and the rest of the file is still reported.
     */
    private Map<KeyKind, Optional<String>> reasonsAgainst(TokenProfileFullModel profile, Container container)
            throws NotFoundException {
        Set<KeyKind> kinds = new HashSet<>();
        for (ContainerEntry entry : container.entries()) {
            if (entry instanceof KeyEntry key && key.description().supported()) {
                kinds.add(kindOf(key.description()));
            }
        }
        try {
            return keyImportGates.notImportableReasons(profile, kinds);
        } catch (ConnectorException e) {
            logger
                    .warn("Could not learn what token profile {} imports, so its keys are reported as not importable: {}",
                            profile.uuid(), e.getMessage());
            Optional<String> unanswered = Optional.of(UNANSWERED.formatted(profile.name()));
            return kinds.stream().collect(Collectors.toMap(Function.identity(), kind -> unanswered));
        }
    }

    private static KeyKind kindOf(KeyDescription description) {
        return new KeyKind(description.type(), description.algorithm());
    }
}
