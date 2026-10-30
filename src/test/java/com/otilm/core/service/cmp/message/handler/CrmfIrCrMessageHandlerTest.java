package com.otilm.core.service.cmp.message.handler;

import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.v2.ClientOperationInternalService;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link CrmfIrCrMessageHandler}.
 */
class CrmfIrCrMessageHandlerTest {

    private ClientOperationInternalService clientOperationService;
    private CrmfIrCrMessageHandler handler;

    @BeforeEach
    void setUp() {
        clientOperationService = mock(ClientOperationInternalService.class);
        handler = new CrmfIrCrMessageHandler();
        handler.setClientOperationService(clientOperationService);
    }

    @Test
    void recordsCmpProfileUuidAsProtocolProfile() throws Exception {
        UUID cmpProfileUuid = UUID.randomUUID();
        UUID raProfileUuid = UUID.randomUUID();
        ConfigurationContext configuration = configuration(cmpProfileUuid, raProfileUuid);
        when(clientOperationService
                .issueCertificate(any(SecuredParentUUID.class), any(SecuredUUID.class),
                        any(ClientCertificateIssueRequestDto.class), any(CertificateProtocolInfo.class)))
                .thenReturn(new ClientCertificateDataResponseDto());

        handler.handle(irMessage(), configuration);

        ArgumentCaptor<CertificateProtocolInfo> protocolInfo = ArgumentCaptor.forClass(CertificateProtocolInfo.class);
        verify(clientOperationService)
                .issueCertificate(any(SecuredParentUUID.class), any(SecuredUUID.class),
                        any(ClientCertificateIssueRequestDto.class), protocolInfo.capture());
        assertThat(protocolInfo.getValue().getProtocol()).isEqualTo(CertificateProtocol.CMP);
        assertThat(protocolInfo.getValue().getProtocolProfileUuid()).isEqualTo(cmpProfileUuid);
    }

    private static ConfigurationContext configuration(UUID cmpProfileUuid, UUID raProfileUuid) {
        CmpProfile cmpProfile = new CmpProfile();
        cmpProfile.setUuid(cmpProfileUuid);
        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(raProfileUuid);
        raProfile.setAuthorityInstanceReferenceUuid(UUID.randomUUID());
        ConfigurationContext configuration = mock(ConfigurationContext.class);
        when(configuration.getCmpProfile()).thenReturn(cmpProfile);
        when(configuration.getRaProfile()).thenReturn(raProfile);
        return configuration;
    }

    private static PKIMessage irMessage() {
        PKIHeader header = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(new X500Name("CN=test-sender")),
                new GeneralName(new X500Name("CN=test-recipient")))
                .setTransactionID(new DEROctetString(new byte[]{1, 2, 3, 4}))
                .setSenderNonce(new DEROctetString(new byte[]{5, 6, 7, 8}))
                .build();
        CertRequest certRequest = new CertRequest(new ASN1Integer(0),
                new CertTemplateBuilder().setSubject(new X500Name("CN=cmp-certificate")).build(), null);
        CertReqMessages certReqMessages = new CertReqMessages(new CertReqMsg(certRequest, null, null));
        return new PKIMessage(header, new PKIBody(PKIBody.TYPE_INIT_REQ, certReqMessages));
    }
}
