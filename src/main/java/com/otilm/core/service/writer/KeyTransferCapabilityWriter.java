package com.otilm.core.service.writer;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.KeyTransfer;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.model.crypto.TransferableKeyType;
import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Records what a token profile's connector said it imports and exports, and forgets it when something the answers
 * depend on changes. Separate from {@link TokenProfileWriter} so the connector and token writers can forget answers
 * without depending on everything a profile writer needs.
 *
 * <p>
 * Every write here holds the profile's row lock and decides on the row as it stands under that lock, as every profile
 * writer does, so none of them can overwrite another's change to the row. Locks over several profiles are taken in UUID
 * order, so two of them cannot deadlock each other.
 * </p>
 */
@Service
public class KeyTransferCapabilityWriter {

    private final TokenProfileRepository tokenProfileRepository;
    private final EntityManager entityManager;

    public KeyTransferCapabilityWriter(TokenProfileRepository tokenProfileRepository, EntityManager entityManager) {
        this.tokenProfileRepository = tokenProfileRepository;
        this.entityManager = entityManager;
    }

    /**
     * Records the connector's answer for one direction of the profile, leaving the other direction's answer as it is,
     * unless something the answer depends on changed after it was asked for.
     *
     * @param profileUuid the profile the connector answered for
     * @param askedAtRevision the profile's revision when the connector was asked
     * @param direction whether the connector said what it imports or what it exports
     * @param keyTypes the answer, empty when the connector moves nothing that way for the profile
     * @return the profile as recorded, or empty when the answer was given for a scope the profile no longer has
     * @throws NotFoundException if the profile no longer exists
     */
    @Transactional(rollbackFor = Exception.class)
    public Optional<TokenProfileFullModel> recordAnswer(UUID profileUuid, int askedAtRevision, KeyTransfer direction,
            List<TransferableKeyType> keyTypes) throws NotFoundException {
        TokenProfile profile = current(tokenProfileRepository
                .findWithLockByUuid(profileUuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, profileUuid)));
        if (profile.getKeyTypesRevision() != askedAtRevision) {
            return Optional.empty();
        }
        switch (direction) {
            case IMPORT -> profile.setImportableKeyTypes(keyTypes);
            case EXPORT -> profile.setExportableKeyTypes(keyTypes);
        }
        return Optional.of(ImmutableTokenProfileFullModel.from(profile));
    }

    /**
     * Forgets the answers of every profile of the token.
     *
     * @param tokenUuid the token whose profiles to forget
     */
    @Transactional(rollbackFor = Exception.class)
    public void forgetForToken(UUID tokenUuid) {
        forget(tokenProfileRepository.findWithLockByTokenInstanceReferenceUuid(tokenUuid));
    }

    /**
     * Forgets the answers of every profile on every token of the connector. It joins the transaction that registers the
     * connector, so the answers are dropped exactly when the new registration takes effect: forgotten any earlier, the
     * connector could be asked again at its old registration and that answer kept.
     *
     * @param connectorUuid the connector whose profiles to forget
     */
    @Transactional(rollbackFor = Exception.class)
    public void forgetForConnector(UUID connectorUuid) {
        forget(tokenProfileRepository.findWithLockByConnectorUuid(connectorUuid));
    }

    private void forget(List<TokenProfile> locked) {
        locked.forEach(profile -> current(profile).forgetKeyTypes());
    }

    /**
     * The locked profile as its row now stands. With open-in-view the request may have loaded the profile before it
     * asked the connector, and the locked read hands back that same instance with the state it had then. TokenProfile
     * is not {@code @DynamicUpdate}, so a write from it would put back every column changed since.
     */
    private TokenProfile current(TokenProfile locked) {
        entityManager.refresh(locked);
        return locked;
    }
}
