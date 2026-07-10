package com.otilm.core.service.handler.authority;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v2.CertificateSyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.v2.CertRevocationDto;
import com.otilm.api.model.connector.v2.CertificateDataResponseDto;
import com.otilm.api.model.connector.v2.CertificateRenewRequestDto;
import com.otilm.api.model.connector.v2.CertificateSignRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.authority.CertificateRevocationReason;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.service.v2.ConnectorInternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Adapts the legacy v2 connector clients ({@link CertificateSyncApiClient} and
 * {@link com.otilm.api.interfaces.client.v1.AuthorityInstanceSyncApiClient}) to the
 * {@link AuthorityProviderAdapter} interface shape.
 *
 * <p>Does not alter any v2 wire behavior — it is a pure call-site shape adaptation.
 * v2 connectors MAY return HTTP 202 (async accepted) from issue, renew, or revoke.
 * {@link #mapV2Response(ResponseEntity)} surfaces 202 from issue/renew as
 * {@link AdapterOperationResult#asyncAccepted}; revoke applies equivalent logic inline.</p>
 */
@Component
public class AuthorityProviderV2Adapter extends AbstractAuthorityProviderAdapter {

    @Autowired
    public AuthorityProviderV2Adapter(ConnectorInternalService connectorService,
                                      ConnectorApiFactory connectorApiFactory,
                                      AttributeEngine attributeEngine) {
        super(connectorService, connectorApiFactory, attributeEngine);
    }

    @Override
    public AdapterOperationResult issue(Certificate cert, ClientCertificateIssueRequestDto req) throws ConnectorException {
        RaProfile raProfile = cert.getRaProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();

        CertificateSignRequestDto wire = new CertificateSignRequestDto();
        wire.setRequest(cert.getCertificateRequest().getContent());
        wire.setFormat(cert.getCertificateRequest().getCertificateRequestFormat());
        wire.setAttributes(issueAttributesFor(cert, authority));
        wire.setRaProfileAttributes(raProfileAttributesFor(raProfile, authority));

        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        ResponseEntity<CertificateDataResponseDto> response =
                connectorApiFactory.getCertificateApiClientV2(connectorDto)
                        .issueCertificate(connectorDto, authority.getAuthorityInstanceUuid(), wire);

        return mapV2Response(response);
    }

    @Override
    public AdapterOperationResult renew(Certificate oldCert, Certificate newCert, ClientCertificateRenewRequestDto req) throws ConnectorException {
        RaProfile raProfile = newCert.getRaProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();

        CertificateRenewRequestDto wire = new CertificateRenewRequestDto();
        // CSR is optional (e.g. reuse-key renewal); omit it when absent rather than NPE — matches V3.
        if (newCert.getCertificateRequest() != null) {
            wire.setRequest(newCert.getCertificateRequest().getContent());
            wire.setFormat(newCert.getCertificateRequest().getCertificateRequestFormat());
        }
        wire.setRaProfileAttributes(raProfileAttributesFor(raProfile, authority));
        wire.setCertificate(oldCert.getCertificateContent().getContent());
        wire.setMeta(loadMeta(oldCert, authority));

        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        ResponseEntity<CertificateDataResponseDto> response =
                connectorApiFactory.getCertificateApiClientV2(connectorDto)
                        .renewCertificate(connectorDto, authority.getAuthorityInstanceUuid(), wire);

        return mapV2Response(response);
    }

    @Override
    public AdapterOperationResult revoke(Certificate cert, ClientCertificateRevocationDto req) throws ConnectorException {
        RaProfile raProfile = cert.getRaProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();

        CertRevocationDto wire = new CertRevocationDto();
        wire.setReason(req.getReason() != null ? req.getReason() : CertificateRevocationReason.UNSPECIFIED);
        wire.setAttributes(req.getAttributes());
        wire.setRaProfileAttributes(raProfileAttributesFor(raProfile, authority));
        wire.setCertificate(cert.getCertificateContent().getContent());

        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        ResponseEntity<Void> response = connectorApiFactory.getCertificateApiClientV2(connectorDto)
                .revokeCertificate(connectorDto, authority.getAuthorityInstanceUuid(), wire);

        if (response.getStatusCode().value() == 202) {
            return AdapterOperationResult.asyncAccepted(null);
        }
        return AdapterOperationResult.syncNoContent();
    }

    @Override
    public List<BaseAttribute> listAuthorityInstanceAttributes(AuthorityInstanceReference authority) throws ConnectorException {
        // v2 authority-instance attributes come from the function-group attribute endpoint
        // (/v1/authorityProvider/{kind}/attributes). Legacy (LEGACY_AUTHORITY_PROVIDER) connectors
        // never reach this adapter — they stay on ConnectorInternalService's function-group path.
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        return connectorApiFactory.getAttributeApiClient(connectorDto)
                .listAttributeDefinitions(connectorDto,
                        com.otilm.api.model.core.connector.FunctionGroupCode.AUTHORITY_PROVIDER,
                        authority.getKind());
    }

    @Override
    public List<BaseAttribute> listRaProfileAttributes(AuthorityInstanceReference authority) throws ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        return connectorApiFactory.getAuthorityInstanceApiClient(connectorDto)
                .listRAProfileAttributes(connectorDto, authority.getAuthorityInstanceUuid());
    }

    @Override
    public List<BaseAttribute> listIssueAttributes(AuthorityInstanceReference authority, RaProfile raProfile) throws ConnectorException {
        // v2 endpoint is keyed by authorityInstanceUuid alone — raProfile is unused (single per-authority schema).
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        return connectorApiFactory.getCertificateApiClientV2(connectorDto)
                .listIssueCertificateAttributes(connectorDto, authority.getAuthorityInstanceUuid());
    }

    @Override
    public List<BaseAttribute> listRevokeAttributes(AuthorityInstanceReference authority, RaProfile raProfile) throws ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        return connectorApiFactory.getCertificateApiClientV2(connectorDto)
                .listRevokeCertificateAttributes(connectorDto, authority.getAuthorityInstanceUuid());
    }

    @Override
    public Boolean validateIssueAttributes(AuthorityInstanceReference authority, List<RequestAttribute> attributes)
            throws ValidationException, ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        return connectorApiFactory.getCertificateApiClientV2(connectorDto)
                .validateIssueCertificateAttributes(connectorDto, authority.getAuthorityInstanceUuid(), attributes);
    }

    @Override
    public Boolean validateRevokeAttributes(AuthorityInstanceReference authority, List<RequestAttribute> attributes)
            throws ValidationException, ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        return connectorApiFactory.getCertificateApiClientV2(connectorDto)
                .validateRevokeCertificateAttributes(connectorDto, authority.getAuthorityInstanceUuid(), attributes);
    }

    /**
     * Validates the authority instance's RA profile configuration against the connector.
     * Uses {@code validateRAProfileAttributes} as the v2 wire equivalent of "check connection"
     * for an authority: it probes the connector with the given attributes and throws on failure.
     */
    @Override
    public void checkAuthorityConnection(AuthorityInstanceReference authority, List<RequestAttribute> attributes)
            throws ValidationException, ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        connectorApiFactory.getAuthorityInstanceApiClient(connectorDto)
                .validateRAProfileAttributes(connectorDto, authority.getAuthorityInstanceUuid(), attributes);
    }

    // --- private helpers ---

    private List<RequestAttribute> issueAttributesFor(Certificate cert, AuthorityInstanceReference authority) {
        return attributeEngine.getRequestObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, cert.getUuid())
                        .connector(authority.getConnectorUuid())
                        .operation(AttributeOperation.CERTIFICATE_ISSUE)
                        .build());
    }

    /**
     * Maps a v2 connector response to an {@link AdapterOperationResult}.
     * HTTP 202 is surfaced as {@link AdapterOperationOutcome#ASYNC_ACCEPTED}; all other 2xx
     * responses (including 200) are treated as synchronous success ({@link AdapterOperationOutcome#SYNC_OK}).
     */
    private AdapterOperationResult mapV2Response(ResponseEntity<CertificateDataResponseDto> response) {
        CertificateDataResponseDto body = response.getBody();
        if (response.getStatusCode().value() == 202) {
            return AdapterOperationResult.asyncAccepted(body != null ? body.getMeta() : null);
        }
        return AdapterOperationResult.syncOk(
                body != null ? body.getCertificateData() : null,
                body != null ? body.getMeta() : null,
                null);
    }
}
