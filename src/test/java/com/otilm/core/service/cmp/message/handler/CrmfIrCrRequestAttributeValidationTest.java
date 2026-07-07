package com.otilm.core.service.cmp.message.handler;

import com.otilm.api.interfaces.core.cmp.error.CmpCrmfValidationException;
import com.otilm.core.certificate.request.RequestAttributePolicyViolationException;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.service.cmp.CmpEntityUtil;
import com.otilm.core.service.cmp.CmpTestUtil;
import com.otilm.core.service.cmp.configurations.variants.Mobile3gppProfileContext;
import com.otilm.core.service.cmp.message.CertificateKeyServiceImpl;
import com.otilm.core.service.v2.impl.ClientOperationServiceImpl;
import com.otilm.core.util.BaseSpringBootTest;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * Verifies that {@link RequestAttributePolicyViolationException} is shaped into a {@link CmpCrmfValidationException}.
 */
@Transactional
class CrmfIrCrRequestAttributeValidationTest extends BaseSpringBootTest {

    @Autowired
    private CrmfIrCrMessageHandler crmfIrCrMessageHandler;

    @Autowired
    private CertificateKeyServiceImpl certificateKeyService;

    @MockitoBean(name = "clientOperationServiceImplV2")
    private ClientOperationServiceImpl clientOperationServiceImpl;

    @Test
    void shapesCrmfError_whenIrMissingRequiredRdn() throws Exception {
        // given — an ir request whose downstream issuance is rejected by the request-attribute policy
        var policyMessage = "Certificate request does not satisfy the request-attribute policy "
                + "of RA profile 'X': missing required RDN: CN";
        given(clientOperationServiceImpl.issueCertificate(any(), any(), any(), any()))
                .willThrow(new RequestAttributePolicyViolationException(policyMessage, List.of("missing required RDN: CN")));
        KeyPair keyPair = CmpTestUtil.generateKeyPairEC();
        PKIBody body = CmpTestUtil.createCrmfBody(keyPair, 555L);
        PKIMessage request = CmpTestUtil.createSignatureBasedMessage("888", keyPair.getPrivate(), body).toASN1Structure();
        RaProfile raProfile = CmpEntityUtil.createRaProfile();
        raProfile.setAuthorityInstanceReferenceUuid(UUID.randomUUID());

        // when / then — the handler shapes the policy violation into a CmpCrmfValidationException carrying
        // the safe, platform-authored message and no internal identifiers
        assertThatThrownBy(() -> crmfIrCrMessageHandler.handle(request,
                new Mobile3gppProfileContext(null, raProfile, request, certificateKeyService, null, null)))
                .isInstanceOf(CmpCrmfValidationException.class)
                .hasMessageContaining(policyMessage)
                .satisfies(ex -> assertThat(ex.getMessage())
                        .doesNotContainIgnoringCase("sql")
                        .doesNotContainIgnoringCase("exception")
                        .doesNotContain("com.otilm"));
    }
}
