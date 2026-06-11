package com.otilm.core.service.acme.message;

import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.common.JwsBody;
import com.otilm.api.model.core.acme.Problem;
import com.otilm.core.service.acme.AcmeConstants;
import com.otilm.core.util.AcmeJsonProcessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import lombok.Getter;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Map;

public class AcmeJwsRequest {

    private static final Logger logger = LoggerFactory.getLogger(AcmeJwsRequest.class);

    private final String request;
    @Getter
    private JWSObject jwsObject;
    @Getter
    private JWSHeader jwsHeader;
    @Getter
    private Payload jwsPayload;
    private PublicKey publicKey;
    @Getter
    private boolean isJwkPresent = false;
    @Getter
    private boolean isKidPresent = false;
    @Getter
    private JWK jwk;
    @Getter
    private String kid;

    public AcmeJwsRequest(String request) throws AcmeProblemDocumentException {
        this.request = request;
        readRequest();
    }

    public PublicKey getPublicKey() throws AcmeProblemDocumentException {
        if (publicKey == null) {
            readPublicKey();
        }
        return publicKey;
    }

    public boolean checkSignature(PublicKey publicKey) throws AcmeProblemDocumentException {
        try {
            String keyType = publicKey.getAlgorithm();
            if (keyType.equals(AcmeConstants.RSA_KEY_TYPE_NOTATION)) {
                return jwsObject.verify(new RSASSAVerifier((RSAPublicKey) publicKey));
            } else if (keyType.equals(AcmeConstants.EC_KEY_TYPE_NOTATION)) {
                return jwsObject.verify(new ECDSAVerifier((ECPublicKey) publicKey));
            } else {
                String message = "Account key is generated using unsupported key type by the server. Supported key types are " + String.join(", ", AcmeConstants.ACME_SUPPORTED_ALGORITHMS);
                logger.error(message);
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_PUBLIC_KEY, message);
            }
        } catch (JOSEException e) {
            logger.error("Error while verifying JWS signature, {}", e.getMessage());
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }
    }

    public void readRequest() throws AcmeProblemDocumentException {
        try{
            JwsBody jwsBody = AcmeJsonProcessor.generalBodyJsonParser(request, JwsBody.class);
            this.jwsObject = new JWSObject(new Base64URL(jwsBody.getProtected()), new Base64URL(jwsBody.getPayload()),
                    new Base64URL(jwsBody.getSignature()));
            this.jwsHeader = jwsObject.getHeader();
            this.jwsPayload = jwsObject.getPayload();
            if (jwsHeader.getJWK() != null) {
                this.isJwkPresent = true;
                this.jwk = jwsHeader.getJWK();
            }
            if (jwsHeader.getKeyID() != null) {
                this.isKidPresent = true;
                this.kid = jwsHeader.getKeyID();
            }
            if (isKidPresent && isJwkPresent) {
                logger.error("JWK Header contains both kid and jwk");
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
            }

            if (!isKidPresent && !isJwkPresent) {
                logger.error("JWK Header does not contains kid nor jwk");
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
            }
        } catch (ParseException | JsonProcessingException e) {
            logger.error("Error while parsing JWS request, {}", e.getMessage());
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }
    }

    public void readPublicKey() throws AcmeProblemDocumentException {
        JWK jwk = jwsHeader.getJWK();
        String keyType = jwk.getKeyType().toString();
        logger.debug("JWS public key type: {}", keyType);
        try {
            if (keyType.equals(AcmeConstants.RSA_KEY_TYPE_NOTATION)) {
                this.publicKey = jwk.toRSAKey().toPublicKey();
                int keySize = jwk.toRSAKey().size();
                if (keySize < AcmeConstants.ACME_RSA_MINIMUM_KEY_LENGTH){
                    logger.error("Key length is : " + keySize + ", Expecting more than: " + AcmeConstants.ACME_RSA_MINIMUM_KEY_LENGTH);
                    throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_PUBLIC_KEY,
                            "Bit length of the RSA key should be at least " + AcmeConstants.ACME_RSA_MINIMUM_KEY_LENGTH);
                }
            } else if (keyType.equals(AcmeConstants.EC_KEY_TYPE_NOTATION)) {
                this.publicKey = jwk.toECKey().toPublicKey();
                int keySize = jwk.toECKey().size();
                if (keySize < AcmeConstants.ACME_EC_MINIMUM_KEY_LENGTH){
                    logger.error("Key length is : " + keySize + ", Expecting more than: " + AcmeConstants.ACME_RSA_MINIMUM_KEY_LENGTH);
                    throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_PUBLIC_KEY,
                            "Bit length of the EC key should be at least " + AcmeConstants.ACME_RSA_MINIMUM_KEY_LENGTH);
                }
            } else {
                String message = "Account key is generated using unsupported key type by the server. Supported key types are " + String.join(", ", AcmeConstants.ACME_SUPPORTED_ALGORITHMS);
                logger.error(message);
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_PUBLIC_KEY, message);
            }
        } catch (JOSEException e) {
            logger.error("Error while parsing JWS public key, {}", e.getMessage());
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }
    }

    public void validateUrl(String requestUri) throws AcmeProblemDocumentException {
        if (jwsHeader.getCustomParam("url") == null) {
            logger.error("JWS Header does not contain url");
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED, "JWS Header does not contain url");
        }
        String headerUrl = jwsHeader.getCustomParam("url").toString();
        if (!requestUri.equals(headerUrl)) {
            logger.error("Request URL: " + requestUri + " does not match the JWS Header URL: " + headerUrl);
            throw new AcmeProblemDocumentException(HttpStatus.UNAUTHORIZED, Problem.MALFORMED, "Request URL and the header URL does not match");
        }
    }

    public String getJsonStringPayload() {
        final Map<String,Object> map = jwsObject.getPayload().toJSONObject();
        return new JSONObject(map).toJSONString();
    }

    public JWK getOldKeyJWK() throws ParseException {
        return jwsPayload.toJSONObject().get("oldKey") != null ? JWK.parse(new Gson().toJsonTree(jwsPayload.toJSONObject().get("oldKey")).toString()) : null;
    }

}
