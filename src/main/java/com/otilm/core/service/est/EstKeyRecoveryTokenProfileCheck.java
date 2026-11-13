package com.otilm.core.service.est;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.service.handler.KeyCreationRules;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Refuses, when an EST Profile is saved, a key recovery that could not serve a request: the keys it creates must be
 * exportable and able to sign the request, from the create-key attributes the profile stores. What only the connector
 * learns from those attributes, the algorithm of the key among it, is left to the request. The connector is asked, so
 * the caller holds no transaction.
 */
@Component
public class EstKeyRecoveryTokenProfileCheck {

    private static final Logger log = LoggerFactory.getLogger(EstKeyRecoveryTokenProfileCheck.class);

    private final TokenProfileRepository tokenProfileRepository;
    private final KeyCreationRules keyCreationRules;

    public EstKeyRecoveryTokenProfileCheck(TokenProfileRepository tokenProfileRepository,
            KeyCreationRules keyCreationRules) {
        this.tokenProfileRepository = tokenProfileRepository;
        this.keyCreationRules = keyCreationRules;
    }

    /**
     * @param tokenProfile the enabled token profile that the keys are created on
     * @param keyAttributes the create-key attributes that the profile stores
     * @throws ValidationException when the token profile cannot serve key recovery, with a message that is fixed or
     * names the profile and the attributes, never the connector's words
     */
    public void check(TokenProfile tokenProfile, List<RequestAttribute> keyAttributes)
            throws AttributeException, NotFoundException {
        requireNoSecretContent(tokenProfile, keyAttributes);
        TokenProfileFullModel model = load(tokenProfile);
        requireSigningUsage(model);
        try {
            keyCreationRules.requireExportSupport(model, KeyRequestType.KEY_PAIR);
            keyCreationRules.validateAttributes(KeyRequestType.KEY_PAIR, model, keyAttributes);
        } catch (ConnectorException e) {
            log
                    .warn("The connector of key recovery token profile {} could not check the key attributes: {}",
                            tokenProfile.getName(), e.getClass().getName());
            throw new ValidationException("The connector of key recovery token profile " + tokenProfile.getName()
                    + " could not check its export capability and key attributes");
        }
    }

    /** The attributes are stored as they are sent, so a secret among them would be kept in the clear. */
    private static void requireNoSecretContent(TokenProfile tokenProfile, List<RequestAttribute> keyAttributes) {
        List<String> secretNames = keyAttributes
                .stream()
                .filter(attribute -> attribute.getContentType() == AttributeContentType.SECRET)
                .map(RequestAttribute::getName)
                .toList();
        if (!secretNames.isEmpty()) {
            throw new ValidationException("Key attributes for token profile " + tokenProfile.getName()
                    + " cannot hold secret content: " + String.join(", ", secretNames));
        }
    }

    private TokenProfileFullModel load(TokenProfile tokenProfile) throws NotFoundException {
        if (tokenProfile.getTokenInstanceReferenceUuid() == null) {
            throw new ValidationException(
                    "Key recovery token profile " + tokenProfile.getName() + " does not belong to a token");
        }
        return tokenProfileRepository
                .findFullModelByUuidAndTokenInstanceReferenceUuid(tokenProfile.getUuid(),
                        tokenProfile.getTokenInstanceReferenceUuid())
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, tokenProfile.getUuid()));
    }

    /**
     * A key of a v2 token signs only when its token profile allows it, and the key takes its usages from the profile. A
     * key of a v1 token is not checked for usages.
     */
    private static void requireSigningUsage(TokenProfileFullModel model) {
        if (model.tokenInstance().connectorInterface() != null && !model.usages().contains(KeyUsage.SIGN)) {
            throw new ValidationException("Key recovery token profile " + model.name()
                    + " does not allow the signing usage, which a key needs to sign the request");
        }
    }
}
