package com.otilm.core.service.acme.eab;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.otilm.api.model.core.acme.ExternalAccountBinding;
import java.util.UUID;

/** Builds RFC 8555 section 7.3.4 External Account Binding JWS objects the way an ACME client does. */
public final class EabTestUtil {

    private EabTestUtil() {
    }

    public static ExternalAccountBinding build(UUID kid, String url, JWK accountKey, byte[] macKey)
            throws JOSEException {
        return build(JWSAlgorithm.HS256, kid == null ? null : kid.toString(), url, accountKey, macKey);
    }

    public static ExternalAccountBinding buildWithNonce(UUID kid, String url, JWK accountKey, byte[] macKey,
            String nonce) throws JOSEException {
        return build(JWSAlgorithm.HS256, kid.toString(), url, accountKey, macKey, nonce);
    }

    public static ExternalAccountBinding build(JWSAlgorithm algorithm, String kid, String url, JWK accountKey,
            byte[] macKey) throws JOSEException {
        return build(algorithm, kid, url, accountKey, macKey, null);
    }

    private static ExternalAccountBinding build(JWSAlgorithm algorithm, String kid, String url, JWK accountKey,
            byte[] macKey, String nonce) throws JOSEException {
        JWSHeader.Builder header = new JWSHeader.Builder(algorithm);
        if (nonce != null) {
            header.customParam("nonce", nonce);
        }
        if (kid != null) {
            header.keyID(kid);
        }
        if (url != null) {
            header.customParam("url", url);
        }
        JWSObject jws = new JWSObject(header.build(), new Payload(accountKey.toPublicJWK().toJSONString()));
        jws.sign(new MACSigner(macKey));

        ExternalAccountBinding binding = new ExternalAccountBinding();
        binding.setProtectedHeader(jws.getHeader().toBase64URL().toString());
        binding.setPayload(jws.getPayload().toBase64URL().toString());
        binding.setSignature(jws.getSignature().toString());
        return binding;
    }
}
