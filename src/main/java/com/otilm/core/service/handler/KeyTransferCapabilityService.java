package com.otilm.core.service.handler;

import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.cryptography.key.KeyTransferAvailabilityDto;
import com.otilm.api.model.core.cryptography.key.KeyTransferCapabilityDto;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.crypto.KeyTransfer;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.model.crypto.TransferableKeyType;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.KeyTransferCapabilityWriter;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

/**
 * What a token profile can import and export, as its connector answered for the profile's current scope.
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
    private final TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    private final TokenProfileRepository tokenProfileRepository;

    public KeyTransferCapabilityService(ConnectorCapabilityService connectorCapabilityService,
            KeyProviderAdapterFactory keyProviderAdapterFactory,
            KeyTransferCapabilityWriter keyTransferCapabilityWriter,
            TokenInstanceReferenceRepository tokenInstanceReferenceRepository,
            TokenProfileRepository tokenProfileRepository) {
        this.connectorCapabilityService = connectorCapabilityService;
        this.keyProviderAdapterFactory = keyProviderAdapterFactory;
        this.keyTransferCapabilityWriter = keyTransferCapabilityWriter;
        this.tokenInstanceReferenceRepository = tokenInstanceReferenceRepository;
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
        return keyTypes(profile, KeyTransfer.EXPORT);
    }

    /**
     * The algorithms the profile's connector imports, per key type, asking the connector when no answer is recorded. A
     * connector that does not declare key import imports nothing and is not asked.
     *
     * @param profile the profile to answer for
     * @return the answer, which is an empty map when the connector imports nothing into the profile, or empty when the
     * profile changed while the connector was being asked, so its answer no longer applies
     * @throws ConnectorException if the connector had to be asked and did not answer
     * @throws NotFoundException if the profile or its connector no longer exists
     */
    public Optional<Map<KeyRequestType, Set<KeyAlgorithm>>> importableKeyTypes(TokenProfileFullModel profile)
            throws ConnectorException, NotFoundException {
        return keyTypes(profile, KeyTransfer.IMPORT);
    }

    private Optional<Map<KeyRequestType, Set<KeyAlgorithm>>> keyTypes(TokenProfileFullModel profile,
            KeyTransfer direction) throws ConnectorException, NotFoundException {
        if (!connectorCapabilityService
                .supports(profile.tokenInstance().connectorInterface(), direction.featureFlag())) {
            return Optional.of(Map.of());
        }
        Map<KeyRequestType, Set<KeyAlgorithm>> recorded = direction.recordedIn(profile);
        if (recorded != null) {
            return Optional.of(recorded);
        }
        KeyProviderAdapter adapter = keyProviderAdapterFactory.forToken(profile.tokenInstance());
        List<TransferableKeyType> answer = direction == KeyTransfer.IMPORT
                ? adapter.listImportableKeyTypes(profile)
                : adapter.listExportableKeyTypes(profile);
        return keyTransferCapabilityWriter
                .recordAnswer(profile.uuid(), profile.keyTypesRevision(), direction, answer)
                .map(direction::recordedIn);
    }

    /**
     * What the profile can import and export, for showing. While an answer cannot be learned, because the connector
     * cannot answer or an attribute the profile relies on cannot be used, the profile shows as unable to move keys that
     * way until it is shown again.
     *
     * @param profile the profile to describe
     * @return the profile's capability in both directions
     */
    public KeyTransferCapabilityDto capabilityOf(TokenProfileFullModel profile) {
        Inquiry inquiry = new Inquiry();
        Map<KeyRequestType, Set<KeyAlgorithm>> importable = inquiry.keyTypesOf(profile, KeyTransfer.IMPORT);
        Map<KeyRequestType, Set<KeyAlgorithm>> exportable = inquiry.keyTypesOf(profile, KeyTransfer.EXPORT);
        KeyTransferCapabilityDto capability = new KeyTransferCapabilityDto();
        capability.setImportAvailable(!importable.isEmpty());
        capability.setImportableKeyTypes(importable);
        capability.setExportAvailable(!exportable.isEmpty());
        capability.setExportableKeyTypes(exportable);
        return capability;
    }

    /**
     * Whether any profile of the token can import, and whether any can export, for showing.
     *
     * @param token the token to describe
     * @return the token's availability in both directions
     */
    public KeyTransferAvailabilityDto availabilityOf(TokenInstanceBasicModel token) {
        List<TokenProfileFullModel> profiles = tokenInstanceReferenceRepository
                .findFullModelByUuid(token.uuid())
                .map(tokenProfileRepository::findFullModelsByTokenInstance)
                .orElseGet(List::of);
        Inquiry inquiry = new Inquiry();
        boolean importAvailable = false;
        boolean exportAvailable = false;
        for (TokenProfileFullModel profile : profiles) {
            importAvailable = importAvailable || !inquiry.keyTypesOf(profile, KeyTransfer.IMPORT).isEmpty();
            exportAvailable = exportAvailable || !inquiry.keyTypesOf(profile, KeyTransfer.EXPORT).isEmpty();
            if (importAvailable && exportAvailable) {
                break;
            }
        }
        return new KeyTransferAvailabilityDto(importAvailable, exportAvailable);
    }

    /**
     * One round of answers for showing. An answer the connector failed to give is not asked for again in the round, so
     * a failing connector costs at most one attempt per answer rather than one per profile; recorded answers are still
     * read, and a failure specific to one profile does not stop the others from being asked.
     */
    private final class Inquiry {

        private final Set<KeyTransfer> failedAnswers = EnumSet.noneOf(KeyTransfer.class);

        Map<KeyRequestType, Set<KeyAlgorithm>> keyTypesOf(TokenProfileFullModel profile, KeyTransfer direction) {
            if (failedAnswers.contains(direction) && direction.recordedIn(profile) == null) {
                return Map.of();
            }
            try {
                return keyTypes(profile, direction).orElse(Map.of());
            } catch (ConnectorException e) {
                failedAnswers.addAll(answersFailedBy(e, direction));
                logUnanswered(profile, direction, e);
            } catch (NotFoundException | ValidationException e) {
                logUnanswered(profile, direction, e);
            }
            return Map.of();
        }
    }

    /**
     * The answers that would fail the same way for any other profile now: every answer once the connector cannot be
     * reached, the one asked for once the connector failed on its side giving it, and none after a failure specific to
     * the profile.
     */
    private static Set<KeyTransfer> answersFailedBy(ConnectorException e, KeyTransfer direction) {
        if (e instanceof ConnectorCommunicationException) {
            return EnumSet.allOf(KeyTransfer.class);
        }
        boolean failedOnItsSide = e instanceof ConnectorServerException
                || (e instanceof ConnectorProblemException problem
                        && problem.getProblemDetail().getStatus() >= HttpStatus.INTERNAL_SERVER_ERROR.value());
        return failedOnItsSide ? EnumSet.of(direction) : EnumSet.noneOf(KeyTransfer.class);
    }

    private static void logUnanswered(TokenProfileFullModel profile, KeyTransfer direction, Exception e) {
        logger
                .warn("Could not learn what token profile {} can {}, so it is shown as offering nothing: {}",
                        profile.uuid(), direction, e.getMessage());
    }
}
