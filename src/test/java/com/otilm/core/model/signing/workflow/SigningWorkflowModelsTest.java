package com.otilm.core.model.signing.workflow;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SignatureParameterPolicy;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class SigningWorkflowModelsTest {

    @Test
    void delegatedTimestampingWorkflow_reportsTimestampingType_andExposesFields() {
        DelegatedTimestampingWorkflow wf = new DelegatedTimestampingWorkflow("1.2.3", List.of("1.2.3", "1.2.4"),
                List.of(DigestAlgorithm.SHA_256), Boolean.TRUE);

        assertEquals(SigningWorkflowType.TIMESTAMPING, wf.getWorkflowType());
        assertEquals("1.2.3", wf.defaultPolicyId());
        assertEquals(List.of("1.2.3", "1.2.4"), wf.allowedPolicyIds());
        assertEquals(List.of(DigestAlgorithm.SHA_256), wf.allowedDigestAlgorithms());
        assertEquals(Boolean.TRUE, wf.validateTokenSignature());
        assertInstanceOf(TimestampingWorkflow.class, wf);
        assertInstanceOf(SigningWorkflow.class, wf);
    }

    @Test
    void managedContentSigningWorkflow_reportsContentSigningType_andExposesFields() {
        // given
        UUID connectorUuid = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        List<RequestAttribute> attrs = List.of();

        // when
        ManagedContentSigningWorkflow wf = new ManagedContentSigningWorkflow(connectorUuid, attrs, null, null, null,
                null, CertificatePurposeRequirements.NONE, SignatureParameterPolicy.DENY_ALL);

        // then
        assertThat(wf.getWorkflowType()).isEqualTo(SigningWorkflowType.CONTENT_SIGNING);
        assertThat(wf.signatureFormattingConnectorUuid()).isEqualTo(connectorUuid);
        assertThat(wf.signatureFormattingConnectorAttributes()).isNotNull();
        assertThat(wf).isInstanceOf(ContentSigningWorkflow.class);
        assertThat(wf).isInstanceOf(SigningWorkflow.class);
    }

    @Test
    void delegatedContentSigningWorkflow_reportsContentSigningType() {
        DelegatedContentSigningWorkflow wf = new DelegatedContentSigningWorkflow();

        assertEquals(SigningWorkflowType.CONTENT_SIGNING, wf.getWorkflowType());
        assertInstanceOf(ContentSigningWorkflow.class, wf);
        assertInstanceOf(SigningWorkflow.class, wf);
    }

    @Test
    void managedRawSigningWorkflow_reportsRawSigningType() {
        ManagedRawSigningWorkflow wf = new ManagedRawSigningWorkflow();

        assertEquals(SigningWorkflowType.RAW_SIGNING, wf.getWorkflowType());
        assertInstanceOf(RawSigningWorkflow.class, wf);
        assertInstanceOf(SigningWorkflow.class, wf);
    }

    @Test
    void delegatedRawSigningWorkflow_reportsRawSigningType() {
        DelegatedRawSigningWorkflow wf = new DelegatedRawSigningWorkflow();

        assertEquals(SigningWorkflowType.RAW_SIGNING, wf.getWorkflowType());
        assertInstanceOf(RawSigningWorkflow.class, wf);
        assertInstanceOf(SigningWorkflow.class, wf);
    }
}
