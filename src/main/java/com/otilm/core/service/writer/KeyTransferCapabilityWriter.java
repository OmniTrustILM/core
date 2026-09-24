package com.otilm.core.service.writer;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.model.crypto.TransferableKeyType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Records what a token profile's connector said it exports, and forgets it when something the answer depends on
 * changes. Separate from {@link TokenProfileWriter} so the connector and token writers can forget answers without
 * depending on everything a profile writer needs.
 *
 * <p>
 * Every write here holds the profile's row lock, as every profile writer does, so none of them can overwrite another's
 * change to the row. Locks over several profiles are taken in UUID order, so two of them cannot deadlock each other.
 * </p>
 */
@Service
public class KeyTransferCapabilityWriter {

    private final TokenProfileRepository tokenProfileRepository;

    public KeyTransferCapabilityWriter(TokenProfileRepository tokenProfileRepository) {
        this.tokenProfileRepository = tokenProfileRepository;
    }

    /**
     * Records the connector's answer for the profile, unless something the answer depends on changed after it was asked
     * for.
     *
     * @param profileUuid the profile the connector answered for
     * @param askedAtRevision the profile's revision when the connector was asked
     * @param exportableKeyTypes the answer, empty when the connector exports nothing from the profile
     * @return the profile as recorded, or empty when the answer was given for a scope the profile no longer has
     * @throws NotFoundException if the profile no longer exists
     */
    @Transactional(rollbackFor = Exception.class)
    public Optional<TokenProfileFullModel> recordAnswer(UUID profileUuid, int askedAtRevision,
            List<TransferableKeyType> exportableKeyTypes) throws NotFoundException {
        TokenProfile profile = tokenProfileRepository
                .findWithLockByUuid(profileUuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, profileUuid));
        if (profile.getExportableKeyTypesRevision() != askedAtRevision) {
            return Optional.empty();
        }
        profile.setExportableKeyTypes(exportableKeyTypes);
        return Optional.of(ImmutableTokenProfileFullModel.from(profile));
    }

    /**
     * Forgets the answers of every profile of the token.
     *
     * @param tokenUuid the token whose profiles to forget
     */
    @Transactional(rollbackFor = Exception.class)
    public void forgetForToken(UUID tokenUuid) {
        tokenProfileRepository
                .findWithLockByTokenInstanceReferenceUuid(tokenUuid)
                .forEach(TokenProfile::forgetExportableKeyTypes);
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
        tokenProfileRepository
                .findWithLockByConnectorUuid(connectorUuid)
                .forEach(TokenProfile::forgetExportableKeyTypes);
    }
}
