package com.otilm.core.service.handler;

import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.cryptography.key.KeyTransferAvailabilityDto;
import com.otilm.api.model.core.cryptography.key.KeyTransferCapabilityDto;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.model.crypto.TransferableKeyType;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.KeyTransferCapabilityWriter;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * What a token profile can export, as its connector answered for the profile's current scope.
 *
 * <p>
 * The answer is recorded on the profile and forgotten whenever something it depends on changes: the profile's
 * attributes or key usages, its token's attributes, the connector's registration, or a reload of the token. Whoever
 * needs an answer that is not recorded asks the connector for it, so no change leaves a profile without one for longer
 * than the connector takes to answer. An answer asked for before such a change is not recorded after it.
 * </p>
 */
@Service
public class KeyTransferCapabilityService {

    private static final Logger logger = LoggerFactory.getLogger(KeyTransferCapabilityService.class);

    private final ConnectorCapabilityService connectorCapabilityService;
    private final KeyProviderAdapterFactory keyProviderAdapterFactory;
    private final KeyTransferCapabilityWriter keyTransferCapabilityWriter;
    private final TokenProfileRepository tokenProfileRepository;

    public KeyTransferCapabilityService(ConnectorCapabilityService connectorCapabilityService,
            KeyProviderAdapterFactory keyProviderAdapterFactory,
            KeyTransferCapabilityWriter keyTransferCapabilityWriter, TokenProfileRepository tokenProfileRepository) {
        this.connectorCapabilityService = connectorCapabilityService;
        this.keyProviderAdapterFactory = keyProviderAdapterFactory;
        this.keyTransferCapabilityWriter = keyTransferCapabilityWriter;
        this.tokenProfileRepository = tokenProfileRepository;
    }

    /**
     * The algorithms the profile's connector exports, per key type, asking the connector when no answer is recorded. A
     * connector that does not declare key export exports nothing and is not asked.
     *
     * @param profile the profile to answer for
     * @return the answer, which is an empty map when the connector exports nothing from the profile, or empty when the
     * profile changed while the connector was being asked, so its answer no longer applies
     * @throws ConnectorException if the connector had to be asked and did not answer
     * @throws NotFoundException if the profile or its connector no longer exists
     */
    public Optional<Map<KeyRequestType, Set<KeyAlgorithm>>> exportableKeyTypes(TokenProfileFullModel profile)
            throws ConnectorException, NotFoundException {
        if (!declaresKeyExport(profile)) {
            return Optional.of(Map.of());
        }
        if (profile.exportableKeyTypes() != null) {
            return Optional.of(profile.exportableKeyTypes());
        }
        List<TransferableKeyType> answer = keyProviderAdapterFactory
                .forToken(profile.tokenInstance())
                .listExportableKeyTypes(profile);
        return keyTransferCapabilityWriter
                .recordAnswer(profile.uuid(), profile.exportableKeyTypesRevision(), answer)
                .map(TokenProfileFullModel::exportableKeyTypes);
    }

    /**
     * What the profile can export, for showing. A connector that cannot be asked right now leaves it unavailable until
     * the next time it is shown.
     *
     * @param profile the profile to describe
     * @return the profile's capability, which advertises export only
     */
    public KeyTransferCapabilityDto capabilityOf(TokenProfileFullModel profile) {
        Map<KeyRequestType, Set<KeyAlgorithm>> exportable = Map.of();
        try {
            exportable = exportableKeyTypes(profile).orElse(Map.of());
        } catch (ConnectorException | NotFoundException e) {
            logUnanswered(profile, e);
        }
        KeyTransferCapabilityDto capability = new KeyTransferCapabilityDto();
        capability.setExportAvailable(!exportable.isEmpty());
        capability.setExportableKeyTypes(exportable);
        capability.setImportableKeyTypes(Map.of());
        return capability;
    }

    /**
     * Whether any profile of the token can export, for showing. Once the connector cannot be reached, the remaining
     * profiles without an answer are not asked, so a connector that is down costs one attempt rather than one per
     * profile; a failure specific to one profile does not stop the others from being asked.
     *
     * @param token the token to describe
     * @return the token's availability, which advertises export only
     */
    public KeyTransferAvailabilityDto availabilityOf(TokenInstanceBasicModel token) {
        boolean reachable = true;
        for (TokenProfileFullModel profile : tokenProfileRepository
                .findFullModelsByTokenInstanceReferenceUuid(token.uuid())) {
            if (!reachable && profile.exportableKeyTypes() == null) {
                continue;
            }
            try {
                if (exportableKeyTypes(profile).filter(types -> !types.isEmpty()).isPresent()) {
                    return new KeyTransferAvailabilityDto(false, true);
                }
            } catch (ConnectorCommunicationException e) {
                reachable = false;
                logUnanswered(profile, e);
            } catch (ConnectorException | NotFoundException e) {
                logUnanswered(profile, e);
            }
        }
        return new KeyTransferAvailabilityDto(false, false);
    }

    private static void logUnanswered(TokenProfileFullModel profile, Exception e) {
        logger
                .warn("Could not learn what token profile {} can export, so it is shown as not exporting: {}",
                        profile.uuid(), e.getMessage());
    }

    private boolean declaresKeyExport(TokenProfileFullModel profile) {
        return connectorCapabilityService
                .supports(profile.tokenInstance().connectorInterface(), FeatureFlag.KEY_EXPORT);
    }
}
