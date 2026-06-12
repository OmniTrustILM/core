package com.otilm.core.service.acme;

import com.otilm.core.dao.entity.acme.AcmeNonce;
import com.otilm.core.dao.repository.acme.AcmeNonceRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObjectJSON;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

/**
 * Static utility helpers shared across ACME integration tests.
 */
public final class AcmeTestUtil {

    private AcmeTestUtil() {
    }

    /**
     * Builds a flattened JWS request body suitable for the ACME service endpoints.
     *
     * <p>When {@code accountId} is {@code null} the public key is embedded in the JWK header
     * (used for new-account requests). Otherwise, a {@code kid} header pointing to the account
     * URL is used.
     *
     * <p>A fresh nonce is persisted to {@code acmeNonceRepository} so the service can validate it.
     *
     * @param objectMapper        Jackson mapper used to serialize the payload
     * @param acmeKeyPair         RSA key pair to sign the JWS
     * @param acmeNonceRepository repository used to register the generated nonce
     * @param payload             request payload object (serialized to JSON), or {@code null} for POST-as-GET
     * @param url                 the ACME endpoint URL embedded in the JWS header
     * @param accountId           account ID for the {@code kid} header, or {@code null} for new-account
     * @param acmeProfileName     ACME profile name used to construct the account URL
     * @return flattened JWS serialisation
     */
    public static String createJwsRequest(
            ObjectMapper objectMapper,
            KeyPair acmeKeyPair,
            AcmeNonceRepository acmeNonceRepository,
            Object payload,
            String url,
            String accountId,
            String acmeProfileName) throws Exception {

        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256);
        headerBuilder.customParam("url", url);

        String nonce = "test-nonce-" + UUID.randomUUID();
        headerBuilder.customParam("nonce", nonce);

        AcmeNonce acmeNonce = new AcmeNonce();
        acmeNonce.setNonce(nonce);
        acmeNonce.setCreated(new Date());
        acmeNonce.setExpires(new Date(System.currentTimeMillis() + 3_600_000));
        acmeNonceRepository.save(acmeNonce);

        if (accountId == null) {
            headerBuilder.jwk(new RSAKey.Builder((RSAPublicKey) acmeKeyPair.getPublic()).build());
        } else {
            headerBuilder.keyID("http://localhost/acme/" + acmeProfileName + "/account/" + accountId);
        }

        Payload jwsPayload = payload != null
                ? new Payload(objectMapper.writeValueAsString(payload))
                : new Payload("");
        JWSObjectJSON jwsObject = new JWSObjectJSON(jwsPayload);
        jwsObject.sign(headerBuilder.build(), new RSASSASigner(acmeKeyPair.getPrivate()));

        return jwsObject.serializeFlattened();
    }

    /**
     * Creates a PKCS#10 certificate signing request for the given key pair and common name.
     *
     * @param keyPair    key pair whose public key is included in the CSR
     * @param commonName CN value for the subject distinguished name
     * @return DER-encoded CSR
     */
    public static PKCS10CertificationRequest createCsr(KeyPair keyPair, String commonName) throws OperatorCreationException {

        X500Name subject = new X500Name("CN=" + commonName);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        return new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic()).build(signer);
    }

    /**
     * Generates a self-signed X.509 certificate valid for 30 days.
     *
     * @param keyPair    key pair to use for both signing and the subject public key
     * @param commonName CN value for the subject and issuer distinguished names
     * @return self-signed certificate
     */
    public static X509Certificate createTestCertificate(KeyPair keyPair, String commonName) throws Exception {
        long now = System.currentTimeMillis();
        X500Name name = new X500Name("CN=" + commonName);
        Date notBefore = new Date(now);
        Date notAfter = new Date(now + 1_000L * 60 * 60 * 24 * 30);
        BigInteger serial = BigInteger.valueOf(now);

        JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(name, serial, notBefore, notAfter, name, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }
}
