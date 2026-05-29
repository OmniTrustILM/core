package com.czertainly.core.model.signing.workflow;

import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SigningWorkflowModelsTest {

    @Test
    void delegatedTimestampingWorkflow_reportsTimestampingType_andExposesFields() {
        DelegatedTimestampingWorkflow wf = new DelegatedTimestampingWorkflow(
                "1.2.3",
                List.of("1.2.3", "1.2.4"),
                List.of(DigestAlgorithm.SHA_256),
                Boolean.TRUE);

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
        UUID connectorUuid = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        List<RequestAttribute> attrs = List.of();

        ManagedContentSigningWorkflow wf = new ManagedContentSigningWorkflow(connectorUuid, attrs);

        assertEquals(SigningWorkflowType.CONTENT_SIGNING, wf.getWorkflowType());
        assertEquals(connectorUuid, wf.signatureFormatterConnectorUuid());
        assertNotNull(wf.signatureFormatterConnectorAttributes());
        assertInstanceOf(ContentSigningWorkflow.class, wf);
        assertInstanceOf(SigningWorkflow.class, wf);
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
