package com.otilm.core.service.acme.eab;

import com.nimbusds.jose.jwk.JWK;
import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.connector.secrets.content.GenericSecretContent;
import com.otilm.api.model.connector.secrets.content.SecretContent;
import com.otilm.api.model.connector.secrets.content.SecretKeySecretContent;
import com.otilm.api.model.core.acme.ExternalAccountBinding;
import com.otilm.api.model.core.acme.Problem;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.service.SecretExternalService;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Verifies the External Account Binding of a newAccount request against the keys an ACME profile accepts (RFC 8555
 * section 7.3.4). The binding names one of them by UUID in its {@code kid} and MACs the account key with it, so a
 * client can only register an account when it already holds a key the operator provisioned.
 */
@Component
public class AcmeEabVerifier {

    private static final Logger logger = LoggerFactory.getLogger(AcmeEabVerifier.class);

    /**
     * The single rejection every failed binding gets, shared with the account write so that a binding invalidated by a
     * concurrent profile edit reads no differently from one that never verified. Which of the checks failed — an
     * unknown key identifier, a mismatched URL or account key, a bad MAC — would tell a caller which key identifiers
     * exist and which of its guesses came closest.
     */
    public static final String REJECTION = "The External Account Binding could not be verified";

    private static final String UNAVAILABLE = "The External Account Binding could not be verified at this time";

    private SecretExternalService secretService;

    @Autowired
    public void setSecretService(SecretExternalService secretService) {
        this.secretService = secretService;
    }

    /**
     * Resolves the binding to one of the profile's keys and verifies its MAC.
     *
     * <p>
     * Runs outside the caller's transaction: reading a key goes to the vault over HTTP, and no caller's transaction
     * should be held open for that. The secret read still opens a transaction of its own. The read is authorized as the
     * {@code acme} system user every ACME request runs as, which the platform grants {@code SECRET:GET_SECRET_CONTENT}.
     *
     * @return the UUID of the secret the binding verified under
     * @throws AcmeProblemDocumentException {@code externalAccountRequired} when no binding was sent,
     * {@code unauthorized} when one was sent and did not verify, {@code serverInternal} when the key could not be read
     * or is unusable
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public UUID verify(AcmeProfile acmeProfile, ExternalAccountBinding binding, JWK accountKey, URI requestUri)
            throws AcmeProblemDocumentException {
        if (binding == null) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.EXTERNAL_ACCOUNT_REQUIRED);
        }
        ExternalAccountBindingJws jws = ExternalAccountBindingJws.parse(binding);
        if (jws == null || jws.hasNonce()) {
            throw reject(acmeProfile, "the binding is not a well-formed HS256 flattened JWS");
        }
        UUID keyUuid = jws.keyIdentifier();
        List<UUID> accepted = acmeProfile.getEabSecretUuids();
        if (keyUuid == null || accepted == null || !accepted.contains(keyUuid)) {
            throw reject(acmeProfile, "the binding names a key the profile does not accept");
        }
        if (!jws.isForUrl(requestUri.toString())) {
            throw reject(acmeProfile, "the binding is for a different URL");
        }
        if (!jws.bindsAccountKey(accountKey)) {
            throw reject(acmeProfile, "the binding does not carry the account key");
        }

        byte[] macKey = macKeyOf(acmeProfile, keyUuid);
        boolean verified;
        try {
            verified = jws.verify(macKey);
        } catch (UnusableEabKeyException e) {
            throw unusableKey(acmeProfile, keyUuid, e);
        }
        if (!verified) {
            throw reject(acmeProfile, "the binding MAC does not verify under the named key");
        }
        return keyUuid;
    }

    private byte[] macKeyOf(AcmeProfile acmeProfile, UUID keyUuid) throws AcmeProblemDocumentException {
        SecretContent content;
        try {
            content = secretService.getSecretContent(keyUuid);
        } catch (Exception e) {
            // The key is configured but unreadable — an unavailable vault, a disabled secret, a deleted one. Nothing
            // the client can act on, and the underlying message may describe platform internals.
            logger
                    .error("ACME profile '{}': External Account Binding key {} could not be read",
                            acmeProfile.getName(), keyUuid, e);
            throw new AcmeProblemDocumentException(HttpStatus.INTERNAL_SERVER_ERROR, Problem.SERVER_INTERNAL,
                    UNAVAILABLE);
        }
        try {
            return AcmeEabKeys.decode(keyTextOf(content));
        } catch (UnusableEabKeyException e) {
            throw unusableKey(acmeProfile, keyUuid, e);
        }
    }

    private static String keyTextOf(SecretContent content) {
        if (content instanceof SecretKeySecretContent secretKey) {
            return secretKey.getContent();
        }
        if (content instanceof GenericSecretContent generic) {
            return generic.getContent();
        }
        throw new UnusableEabKeyException("a %s secret carries no External Account Binding key"
                .formatted(content == null ? "missing" : content.getType()));
    }

    private AcmeProblemDocumentException unusableKey(AcmeProfile acmeProfile, UUID keyUuid,
            UnusableEabKeyException cause) {
        logger
                .error("ACME profile '{}': External Account Binding key {} is unusable: {}", acmeProfile.getName(),
                        keyUuid, cause.getMessage());
        return new AcmeProblemDocumentException(HttpStatus.INTERNAL_SERVER_ERROR, Problem.SERVER_INTERNAL, UNAVAILABLE);
    }

    private AcmeProblemDocumentException reject(AcmeProfile acmeProfile, String reason) {
        logger.info("ACME profile '{}': External Account Binding rejected - {}", acmeProfile.getName(), reason);
        return new AcmeProblemDocumentException(HttpStatus.UNAUTHORIZED, Problem.UNAUTHORIZED, REJECTION);
    }
}
