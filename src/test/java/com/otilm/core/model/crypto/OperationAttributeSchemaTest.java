package com.otilm.core.model.crypto;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import com.otilm.core.attribute.EcdsaSignatureAttributes;
import com.otilm.core.attribute.RsaSignatureAttributes;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

class OperationAttributeSchemaTest {

    private static final UUID CONNECTOR_UUID = UUID.fromString("5e7d0c1a-2b3c-4d5e-8f90-a1b2c3d4e5f6");

    private static final List<RequestAttribute> PSS_WITH_SHA_256 = List
            .of(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS),
                    RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256));

    @Test
    void requireOfferedSignatureAlgorithm_refusesTheSchemeAndDigest_forAV2KeyThatPresentsNeither() {
        // given: Core presents no field for a connector offering ML-DSA-65 alone
        List<BaseAttribute> published = List
                .of(SignatureAlgorithmAttribute.definition(List.of(SignatureAlgorithm.ML_DSA_65)));
        OperationAttributeSchema schema = new OperationAttributeSchema(CONNECTOR_UUID, List.of(), published,
                KeyAlgorithm.MLDSA);

        // when
        ThrowingCallable require = () -> schema.requireOfferedSignatureAlgorithm(PSS_WITH_SHA_256);

        // then
        assertThat(refusedAttributes(require))
                .containsExactlyInAnyOrder(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME,
                        RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST);
    }

    @Test
    void requireOfferedSignatureAlgorithm_refusesTheSchemeAndDigest_forAV1KeyThatPresentsNeither() {
        // given: Core's registry presents no field for a post-quantum key
        OperationAttributeSchema schema = OperationAttributeSchema.ofCoreRegistry(List.of());

        // when
        ThrowingCallable require = () -> schema.requireOfferedSignatureAlgorithm(PSS_WITH_SHA_256);

        // then
        assertThat(refusedAttributes(require))
                .containsExactlyInAnyOrder(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME,
                        RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST);
    }

    @Test
    void requireOfferedSignatureAlgorithm_refusesTheScheme_forAV1KeyThatPresentsTheDigestAlone() {
        // given
        OperationAttributeSchema schema = OperationAttributeSchema
                .ofCoreRegistry(EcdsaSignatureAttributes.getEcdsaSignatureAttributes());

        // when
        ThrowingCallable require = () -> schema.requireOfferedSignatureAlgorithm(PSS_WITH_SHA_256);

        // then
        assertThat(refusedAttributes(require)).containsExactly(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME);
    }

    @Test
    void requireOfferedSignatureAlgorithm_acceptsTheSchemeAndDigest_forAV1KeyThatPresentsBoth() {
        // given
        OperationAttributeSchema schema = OperationAttributeSchema
                .ofCoreRegistry(RsaSignatureAttributes.getRsaSignatureAttributes());

        // when
        ThrowingCallable require = () -> schema.requireOfferedSignatureAlgorithm(PSS_WITH_SHA_256);

        // then
        assertThatCode(require).doesNotThrowAnyException();
    }

    /** The field names the refusal's errors mention, one per error. */
    private static List<String> refusedAttributes(ThrowingCallable require) {
        ValidationException refusal = catchThrowableOfType(ValidationException.class, require);
        assertThat(refusal).as("refusal").isNotNull();
        return refusal
                .getErrors()
                .stream()
                .map(ValidationError::getErrorDescription)
                .map(OperationAttributeSchemaTest::fieldNamed)
                .toList();
    }

    private static String fieldNamed(String errorDescription) {
        return List
                .of(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME,
                        RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST)
                .stream()
                .filter(errorDescription::contains)
                .findFirst()
                .orElse(errorDescription);
    }
}
