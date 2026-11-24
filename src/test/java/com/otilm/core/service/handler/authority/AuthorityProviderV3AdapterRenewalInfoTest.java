package com.otilm.core.service.handler.authority;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v3.CertificateSyncApiClient;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.connector.v3.certificate.CertificateRenewalInfoRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateRenewalInfoResponseDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.service.v2.ConnectorInternalService;
import com.otilm.core.util.ConnectorFailureFixtures;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorityProviderV3AdapterRenewalInfoTest {

    @Mock
    ConnectorInternalService connectorService;
    @Mock
    ConnectorApiFactory connectorApiFactory;
    @Mock
    AttributeEngine attributeEngine;
    @Mock
    OperationAttributeResolver operationAttributeResolver;
    @Mock
    ConnectorCapabilityService capabilityService;
    @Mock
    CertificateSyncApiClient certClient;

    private AuthorityProviderV3Adapter adapter;
    private AuthorityInstanceReference authority;
    private RaProfile raProfile;
    private ApiClientConnectorInfo connectorInfo;
    private final List<RenewalInfoItem> items = List.of(new RenewalInfoItem("r1", "Y2VydA==", List.of()));

    @BeforeEach
    void setUp() throws Exception {
        adapter = new AuthorityProviderV3Adapter(connectorService, connectorApiFactory, attributeEngine,
                operationAttributeResolver, null, capabilityService);
        UUID connectorUuid = UUID.randomUUID();
        connectorInfo = mock(ApiClientConnectorInfo.class);
        authority = new AuthorityInstanceReference();
        authority.setUuid(UUID.randomUUID());
        authority.setName("test-ca");
        authority.setConnectorUuid(connectorUuid);
        raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);
        lenient().when(connectorService.getConnectorForApiClient(connectorUuid)).thenReturn(connectorInfo);
        lenient().when(connectorApiFactory.getCertificateApiClientV3(connectorInfo)).thenReturn(certClient);
        lenient().when(attributeEngine.getRequestObjectDataAttributesContent(any())).thenReturn(List.of());
        lenient()
                .when(operationAttributeResolver.resolveForConnectorRequestAsSystem(any(), any()))
                .thenReturn(List.of());
        lenient().when(capabilityService.supports(authority, FeatureFlag.CERTIFICATE_RENEWAL_INFO)).thenReturn(true);
    }

    @Test
    void doesNotCallTheConnectorWithoutTheFlagAndSuspends() {
        when(capabilityService.supports(authority, FeatureFlag.CERTIFICATE_RENEWAL_INFO)).thenReturn(false);

        RenewalInfoCallResult result = adapter.renewalInfo(authority, raProfile, items);

        RenewalInfoCallResult.Suspend suspend = assertInstanceOf(RenewalInfoCallResult.Suspend.class, result);
        assertEquals("test-ca", suspend.authority());
        verifyNoInteractions(connectorApiFactory);
    }

    @Test
    void sendsTheItemsAndReturnsTheResponse() throws ConnectorException {
        CertificateRenewalInfoResponseDto response = new CertificateRenewalInfoResponseDto();
        when(certClient.renewalInfo(eq(connectorInfo), any(CertificateRenewalInfoRequestDtoV3.class)))
                .thenReturn(response);

        RenewalInfoCallResult result = adapter.renewalInfo(authority, raProfile, items);

        assertEquals(new RenewalInfoCallResult.Answered(response), result);
        ArgumentCaptor<CertificateRenewalInfoRequestDtoV3> sent = ArgumentCaptor
                .forClass(CertificateRenewalInfoRequestDtoV3.class);
        verify(certClient).renewalInfo(eq(connectorInfo), sent.capture());
        assertEquals("r1", sent.getValue().getCertificates().get(0).getReference());
        assertEquals("Y2VydA==", sent.getValue().getCertificates().get(0).getCertificate());
    }

    @Test
    void suspendsOnEntityNotFound() throws ConnectorException {
        when(certClient.renewalInfo(any(), any())).thenThrow(new ConnectorEntityNotFoundException("missing"));

        assertInstanceOf(RenewalInfoCallResult.Suspend.class, adapter.renewalInfo(authority, raProfile, items));
    }

    @Test
    void suspendsOnProblemNotFoundWithoutSpecificCode() throws ConnectorException {
        when(certClient.renewalInfo(any(), any()))
                .thenThrow(ConnectorFailureFixtures.problemRefusal(ErrorCode.RESOURCE_NOT_FOUND, 404));

        assertInstanceOf(RenewalInfoCallResult.Suspend.class, adapter.renewalInfo(authority, raProfile, items));
    }

    @Test
    void suspendsOnNotImplemented() throws ConnectorException {
        when(certClient.renewalInfo(any(), any()))
                .thenThrow(new ConnectorServerException("not implemented", HttpStatus.NOT_IMPLEMENTED));

        assertInstanceOf(RenewalInfoCallResult.Suspend.class, adapter.renewalInfo(authority, raProfile, items));
    }

    @Test
    void backsOffOnTooManyRequests() throws ConnectorException {
        when(certClient.renewalInfo(any(), any()))
                .thenThrow(ConnectorFailureFixtures.problemRefusal(ErrorCode.INTERNAL_SERVER_ERROR, 429));

        assertInstanceOf(RenewalInfoCallResult.BackOff.class, adapter.renewalInfo(authority, raProfile, items));
    }

    @Test
    void backsOffOnServiceUnavailable() throws ConnectorException {
        when(certClient.renewalInfo(any(), any()))
                .thenThrow(new ConnectorServerException("unavailable", HttpStatus.SERVICE_UNAVAILABLE));

        assertInstanceOf(RenewalInfoCallResult.BackOff.class, adapter.renewalInfo(authority, raProfile, items));
    }

    @Test
    void backsOffOnInvalidRequest() throws ConnectorException {
        when(certClient.renewalInfo(any(), any()))
                .thenThrow(ConnectorFailureFixtures.problemRefusal(ErrorCode.BAD_REQUEST, 422));

        assertInstanceOf(RenewalInfoCallResult.BackOff.class, adapter.renewalInfo(authority, raProfile, items));
    }

    @Test
    void backsOffOnTransportFailure() throws ConnectorException {
        when(certClient.renewalInfo(any(), any()))
                .thenThrow(new ConnectorCommunicationException("timeout", connectorInfo));

        assertInstanceOf(RenewalInfoCallResult.BackOff.class, adapter.renewalInfo(authority, raProfile, items));
    }

    @Test
    void backsOffOnAResponseThatCannotBeDeserialised() throws ConnectorException {
        when(certClient.renewalInfo(any(), any())).thenThrow(new ValidationException("Unknown status code"));

        assertInstanceOf(RenewalInfoCallResult.BackOff.class, adapter.renewalInfo(authority, raProfile, items));
    }

    @Test
    void backsOffWhenTheCapabilityCheckFails() {
        when(capabilityService.supports(authority, FeatureFlag.CERTIFICATE_RENEWAL_INFO))
                .thenThrow(new IllegalStateException("interface unreadable"));

        assertInstanceOf(RenewalInfoCallResult.BackOff.class, adapter.renewalInfo(authority, raProfile, items));
        verifyNoInteractions(connectorApiFactory);
    }
}
