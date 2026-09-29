package com.otilm.core.logging;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.connector.secrets.content.BasicAuthSecretContent;
import com.otilm.api.model.connector.secrets.content.KeyValueSecretContent;
import com.otilm.api.model.connector.secrets.content.SecretContent;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.api.model.core.secret.SecretRequestDto;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LogRedactionTest {

    private static final String PASSWORD = "basic-auth-password";

    @Test
    void json_writesASensitiveFieldAsRedacted() {
        String json = LogRedaction.json(secretRequest());

        assertThat(json)
                .contains("\"name\":\"probe\"")
                .contains("\"username\":\"alice\"")
                .contains("\"password\":\"***\"")
                .doesNotContain(PASSWORD);
    }

    @Test
    void json_replacesAMapValuedSecretWhole() {
        String json = LogRedaction.json(new KeyValueSecretContent(Map.of("api-key", "key-value-secret")));

        assertThat(json).contains("\"content\":\"***\"").doesNotContain("api-key").doesNotContain("key-value-secret");
    }

    @Test
    void json_redactsASecretInsidePolymorphicAttributeContent() {
        RequestAttributeV2 attribute = new RequestAttributeV2(UUID.randomUUID(), "password",
                AttributeContentType.SECRET,
                List.of(new SecretAttributeContentV2(null, new SecretAttributeContentData("attribute-secret"))));

        String json = LogRedaction.json(Map.of("attributes", List.of(attribute)));

        assertThat(json).contains("\"secret\":\"***\"").doesNotContain("attribute-secret");
    }

    @Test
    void json_writesAPassphraseAsAnEmptyObject() {
        String json = LogRedaction.json(new PassphraseHolder(new Passphrase("passphrase-value".toCharArray())));

        assertThat(json).isEqualTo("{\"passphrase\":{}}");
    }

    @Test
    void json_namesAValueItCannotWrite() {
        assertThat(LogRedaction.json(new Exploding())).isEqualTo("[unserializable Exploding]");
    }

    @Test
    @SuppressWarnings("unchecked")
    void data_givesPlainDataWithTheSecretRedacted() {
        Map<String, Object> data = (Map<String, Object>) LogRedaction.data(secretRequest());

        Map<String, Object> secret = (Map<String, Object>) data.get("secret");
        assertThat(secret).containsEntry("username", "alice").containsEntry("password", "***");
    }

    @Test
    void data_namesAValueItCannotWrite() {
        assertThat(LogRedaction.data(new Exploding())).isEqualTo("[unserializable Exploding]");
    }

    @Test
    void token_keepsTheHeaderAndClaimsOfASignedJwt() throws JOSEException {
        String jwt = signedJwt();
        String[] parts = jwt.split("\\.");

        assertThat(LogRedaction.token(jwt)).isEqualTo(parts[0] + "." + parts[1]).doesNotContain(parts[2]);
    }

    @Test
    void token_redactsATokenThatIsNotASignedJwt() {
        assertThat(LogRedaction.token("opaque-access-token")).isEqualTo("***");
        assertThat(LogRedaction.token("a.b.c")).isEqualTo("***");
    }

    @Test
    @SuppressWarnings("unchecked")
    void data_keepsANullMemberThatJsonOmits() {
        PartiallyPresent value = new PartiallyPresent("present-value", null);

        Map<String, Object> data = (Map<String, Object>) LogRedaction.data(value);

        assertThat(data).containsEntry("present", "present-value").containsKey("absent");
        assertThat(data.get("absent")).isNull();
        assertThat(LogRedaction.json(value)).contains("\"present\":\"present-value\"").doesNotContain("absent");
    }

    @Test
    void json_redactsAPolymorphicSensitiveFieldWhole() {
        SecretContentHolder holder = new SecretContentHolder(new BasicAuthSecretContent("alice", PASSWORD));

        String json = LogRedaction.json(holder);

        assertThat(json).isEqualTo("{\"secret\":\"***\"}").doesNotContain(PASSWORD).doesNotContain("alice");
    }

    private static SecretRequestDto secretRequest() {
        SecretRequestDto request = new SecretRequestDto();
        request.setName("probe");
        request.setSecret(new BasicAuthSecretContent("alice", PASSWORD));
        return request;
    }

    private static String signedJwt() throws JOSEException {
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256),
                new JWTClaimsSet.Builder().issuer("https://idp.example").subject("alice").build());
        jwt.sign(new MACSigner("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8)));
        return jwt.serialize();
    }

    record PassphraseHolder(Passphrase passphrase) {
    }

    record PartiallyPresent(String present, String absent) {
    }

    static final class SecretContentHolder {

        @Sensitive
        public SecretContent secret;

        SecretContentHolder(SecretContent secret) {
            this.secret = secret;
        }
    }

    static final class Exploding {
        public String getValue() {
            throw new IllegalStateException("not writable");
        }
    }
}
