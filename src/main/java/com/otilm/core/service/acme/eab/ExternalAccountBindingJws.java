package com.otilm.core.service.acme.eab;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import com.otilm.api.model.core.acme.ExternalAccountBinding;
import java.text.ParseException;
import java.util.Objects;
import java.util.UUID;

/**
 * The External Account Binding JWS of a newAccount request (RFC 8555 section 7.3.4), parsed once: an HS256 flattened
 * JWS whose protected header carries the binding key identifier and the newAccount URL and whose payload is the account
 * key as a JWK. Pure parsing and verification, no platform state.
 */
public final class ExternalAccountBindingJws {

    private final JWSObject jws;
    private final JWK boundAccountKey;

    private ExternalAccountBindingJws(JWSObject jws, JWK boundAccountKey) {
        this.jws = jws;
        this.boundAccountKey = boundAccountKey;
    }

    /**
     * @return the parsed binding, or null when the binding is structurally invalid: missing members, unparseable
     * base64url or header, an algorithm other than HS256, or a payload that is not a JWK
     */
    public static ExternalAccountBindingJws parse(ExternalAccountBinding binding) {
        if (binding == null || binding.getProtectedHeader() == null || binding.getPayload() == null
                || binding.getSignature() == null) {
            return null;
        }
        try {
            JWSObject jws = new JWSObject(new Base64URL(binding.getProtectedHeader()),
                    new Base64URL(binding.getPayload()), new Base64URL(binding.getSignature()));
            if (!JWSAlgorithm.HS256.equals(jws.getHeader().getAlgorithm())) {
                return null;
            }
            return new ExternalAccountBindingJws(jws, JWK.parse(jws.getPayload().toString()));
        } catch (ParseException | IllegalArgumentException e) {
            return null;
        }
    }

    /** The protected header {@code kid} parsed as the UUID of the secret holding the binding key, or null. */
    public UUID keyIdentifier() {
        String kid = jws.getHeader().getKeyID();
        if (kid == null) {
            return null;
        }
        try {
            return UUID.fromString(kid);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Whether the protected header carries a {@code nonce}. RFC 8555 section 7.3.4 lists the header's fields without
     * one, and a binding is replay-protected by the enclosing newAccount JWS; a nonce here would be consumed by
     * nothing, so its presence marks a client that is not producing the binding the RFC describes.
     */
    public boolean hasNonce() {
        return jws.getHeader().getCustomParam("nonce") != null;
    }

    /** Whether the protected header {@code url} equals the newAccount request URL. */
    public boolean isForUrl(String requestUrl) {
        Object url = jws.getHeader().getCustomParam("url");
        return url != null && url.toString().equals(requestUrl);
    }

    /** Whether the payload JWK is the account key of the enclosing newAccount JWS, by thumbprint. */
    public boolean bindsAccountKey(JWK accountKey) {
        if (accountKey == null) {
            return false;
        }
        try {
            return Objects.equals(boundAccountKey.computeThumbprint(), accountKey.computeThumbprint());
        } catch (JOSEException e) {
            return false;
        }
    }

    /**
     * Whether the MAC verifies under {@code key}.
     *
     * @throws UnusableEabKeyException when the MAC cannot be evaluated at all — a key shorter than the HS256 minimum,
     * or a fault in the provider. Neither is a wrong MAC, and neither should reach a client as one.
     */
    public boolean verify(byte[] key) {
        try {
            return jws.verify(new MACVerifier(key));
        } catch (KeyLengthException e) {
            throw new UnusableEabKeyException("binding key is shorter than the HS256 minimum key length", e);
        } catch (JOSEException e) {
            // Anything other than a short key is a fault in the JCA HMAC provider or the verifier, not a wrong MAC.
            // Returning false here would tell a client with a perfectly good credential that it was rejected.
            throw new UnusableEabKeyException("the binding MAC could not be evaluated", e);
        }
    }
}
