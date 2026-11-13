package com.otilm.core.util.mocks;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.extension.ResponseDefinitionTransformerV2;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.PkiFixtures.Ca;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

/**
 * WireMock extension answering the v2 issue that {@code AuthorityProviderV2Adapter.issue} sends with a <em>real</em>
 * certificate of the CA for the public key and the subject of the request it carries, as an authority does. Register it
 * with {@code LoopbackWireMock.start(transformer)} and stub the issue with
 * {@link AuthorityV2ConnectorStubs#stubIssueCertifyingTheRequest()}.
 */
public final class CertifyingIssueTransformer implements ResponseDefinitionTransformerV2 {

    static final String NAME = "certifying-issue";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Duration VALIDITY = Duration.ofDays(1);

    private final Ca ca;

    /** @param ca the CA that certifies every request */
    public CertifyingIssueTransformer(Ca ca) {
        this.ca = ca;
    }

    @Override
    public ResponseDefinition transform(ServeEvent serveEvent) {
        try {
            String request = OBJECT_MAPPER.readTree(serveEvent.getRequest().getBodyAsString()).path("request").asText();
            X509Certificate certificate = certify(Base64.getMimeDecoder().decode(request));
            String der = Base64.getEncoder().encodeToString(certificate.getEncoded());
            return ResponseDefinitionBuilder
                    .like(serveEvent.getResponseDefinition())
                    .withBody("{\"certificateData\": \"%s\"}".formatted(der))
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("The certifying-issue transformer could not certify the request", e);
        }
    }

    private X509Certificate certify(byte[] requestDer) throws Exception {
        JcaPKCS10CertificationRequest request = new JcaPKCS10CertificationRequest(requestDer);
        PublicKey publicKey = request.getPublicKey();
        Instant now = Instant.now();
        return PkiFixtures
                .clientCertificateFor(ca, new KeyPair(publicKey, null), now.minus(Duration.ofMinutes(1)),
                        now.plus(VALIDITY), request.getSubject().toString());
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public boolean applyGlobally() {
        return false;
    }
}
