package com.czertainly.core.service.handler.authority;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.ConnectorProblemException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.interfaces.client.v3.AuthoritySyncApiClient;
import com.czertainly.api.interfaces.client.v3.CertificateSyncApiClient;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.error.ErrorCode;
import com.czertainly.api.model.connector.v3.certificate.CertificateDataResponseDto;
import com.czertainly.api.model.connector.v3.certificate.CertificateOperationCancelRequestDto;
import com.czertainly.api.model.connector.v3.certificate.CertificateOperationStatusRequestDto;
import com.czertainly.api.model.connector.v3.certificate.CertificateOperationStatusResponseDto;
import com.czertainly.api.model.connector.v3.certificate.CertificateRegistrationRequestDto;
import com.czertainly.api.model.connector.v3.certificate.CertificateRenewRequestDto;
import com.czertainly.api.model.connector.v3.certificate.CertificateRevocationRequestDto;
import com.czertainly.api.model.connector.v3.certificate.CertificateSignRequestDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.v2.ClientCertificateRegistrationDto;
import com.czertainly.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.czertainly.api.model.core.v2.ClientCertificateRevocationDto;
import com.czertainly.api.model.core.v2.ClientCertificateSignRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.exception.ConnectorAcceptedButLocalFailureException;
import com.czertainly.core.service.v2.ConnectorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Adapter for v3 authority provider connectors. Wraps {@link CertificateSyncApiClient} (v3)
 * and {@link AuthoritySyncApiClient} (v3) via {@link ConnectorApiFactory}.
 *
 * <p>Issue/renew/register: 200 = SYNC_OK, 202 = ASYNC_ACCEPTED.
 * Revoke: 204 = SYNC_NO_CONTENT, 202 = ASYNC_ACCEPTED, 200 = SYNC_OK (meta only).
 * Cancel: 204 = CANCELLED; 422 with OPERATION_PAST_POINT_OF_NO_RETURN = refused;
 * 422 with REGISTRATION_NOT_FOUND or OPERATION_NOT_TRACKED = not tracked.</p>
 *
 * <p>Post-acceptance failures (local mapping after 200/202) are wrapped in
 * {@link ConnectorAcceptedButLocalFailureException} — callers must NOT roll back
 * certificate state on this exception.</p>
 */
@Component
public class AuthorityProviderV3Adapter
        extends AbstractAuthorityProviderAdapter
        implements RegisterCapability, AsyncOperationCapability {

    @Autowired
    public AuthorityProviderV3Adapter(ConnectorService connectorService,
                                      ConnectorApiFactory connectorApiFactory,
                                      AttributeEngine attributeEngine) {
        super(connectorService, connectorApiFactory, attributeEngine);
    }

    // ---- AuthorityProviderAdapter ----

    @Override
    public AdapterOperationResult issue(Certificate cert, ClientCertificateSignRequestDto req) throws ConnectorException {
        RaProfile raProfile = cert.getRaProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);

        CertificateSignRequestDto wire = new CertificateSignRequestDto();
        wire.setRequest(cert.getCertificateRequest().getContent());
        wire.setFormat(cert.getCertificateRequest().getCertificateRequestFormat());
        wire.setAttributes(issueAttributesFor(cert, authority));
        wire.setAuthorityAttributes(authorityAttributesFor(authority));
        wire.setRaProfileAttributes(raProfileAttributesFor(raProfile, authority));
        // Replay any meta the connector emitted on a prior register/renew/issue for this cert.
        // Unified meta semantic — connector owns the bag; we forward verbatim. Empty when fresh issuance.
        wire.setMeta(loadMeta(cert, authority));

        return executeWithAcceptanceGuard(CertificateOperation.ISSUE,
                () -> connectorApiFactory.getCertificateApiClientV3(connectorDto).issue(connectorDto, wire),
                this::mapIssueRenewRegisterResponse);
    }

    @Override
    public AdapterOperationResult renew(Certificate oldCert, Certificate newCert, ClientCertificateRenewRequestDto req) throws ConnectorException {
        RaProfile raProfile = newCert.getRaProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);

        CertificateRenewRequestDto wire = new CertificateRenewRequestDto();
        if (newCert.getCertificateRequest() != null) {
            wire.setRequest(newCert.getCertificateRequest().getContent());
            wire.setFormat(newCert.getCertificateRequest().getCertificateRequestFormat());
        }
        wire.setExistingCertificate(oldCert.getCertificateContent().getContent());
        wire.setMeta(loadMeta(oldCert, authority));
        wire.setAuthorityAttributes(authorityAttributesFor(authority));
        wire.setRaProfileAttributes(raProfileAttributesFor(raProfile, authority));

        return executeWithAcceptanceGuard(CertificateOperation.RENEW,
                () -> connectorApiFactory.getCertificateApiClientV3(connectorDto).renew(connectorDto, wire),
                this::mapIssueRenewRegisterResponse);
    }

    @Override
    public AdapterOperationResult revoke(Certificate cert, ClientCertificateRevocationDto req) throws ConnectorException {
        RaProfile raProfile = cert.getRaProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);

        CertificateRevocationRequestDto wire = new CertificateRevocationRequestDto();
        wire.setCertificate(cert.getCertificateContent().getContent());
        wire.setReason(req.getReason());
        wire.setAttributes(req.getAttributes());
        wire.setMeta(loadMeta(cert, authority));
        wire.setAuthorityAttributes(authorityAttributesFor(authority));
        wire.setRaProfileAttributes(raProfileAttributesFor(raProfile, authority));

        return executeWithAcceptanceGuard(CertificateOperation.REVOKE,
                () -> connectorApiFactory.getCertificateApiClientV3(connectorDto).revoke(connectorDto, wire),
                this::mapRevokeResponse);
    }

    @Override
    public List<BaseAttribute> listIssueAttributes(AuthorityInstanceReference authority) throws ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        return connectorApiFactory.getCertificateApiClientV3(connectorDto)
                .listIssueAttributes(connectorDto, authorityAttributesFor(authority));
    }

    @Override
    public List<BaseAttribute> listRevokeAttributes(AuthorityInstanceReference authority) throws ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        return connectorApiFactory.getCertificateApiClientV3(connectorDto)
                .listRevokeAttributes(connectorDto, authorityAttributesFor(authority));
    }

    @Override
    public void checkAuthorityConnection(AuthorityInstanceReference authority, List<RequestAttribute> attributes)
            throws ValidationException, ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        connectorApiFactory.getAuthorityInstanceApiClientV3(connectorDto)
                .checkAuthorityConnection(connectorDto, attributes);
    }

    // ---- RegisterCapability ----

    @Override
    public List<BaseAttribute> listRegisterAttributes(AuthorityInstanceReference authority) throws ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        return connectorApiFactory.getCertificateApiClientV3(connectorDto)
                .listRegisterAttributes(connectorDto, authorityAttributesFor(authority));
    }

    @Override
    public AdapterOperationResult register(Certificate cert, ClientCertificateRegistrationDto req) throws ConnectorException {
        RaProfile raProfile = cert.getRaProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);

        CertificateRegistrationRequestDto wire = new CertificateRegistrationRequestDto();
        if (req != null) {
            wire.setSubjectDn(req.getSubjectDn());
            wire.setSubjectAltName(req.getSubjectAltName());
            wire.setExtensions(req.getExtensions());
            wire.setAttributes(req.getAttributes());
        }
        wire.setAuthorityAttributes(authorityAttributesFor(authority));
        wire.setRaProfileAttributes(raProfileAttributesFor(raProfile, authority));

        return executeWithAcceptanceGuard(CertificateOperation.REGISTER,
                () -> connectorApiFactory.getCertificateApiClientV3(connectorDto).register(connectorDto, wire),
                this::mapIssueRenewRegisterResponse);
    }

    // ---- AsyncOperationCapability ----

    /**
     * Issues 3 separate {@code attribute_content_2_object} reads (cert meta + authority
     * attrs + RA profile attrs) plus the connector HTTP call per poll message. Bounded
     * constant per message (not per cert), so the absolute round-trip cost is small —
     * but in high-throughput async pipelines (thousands of in-flight cert ops) a single
     * batched lookup would halve the DB load from this listener. Tracked as M4-M9
     * follow-up; the API surface change in AttributeEngine is out of scope for this batch.
     */
    @Override
    public StatusPollResult pollStatus(Certificate cert, CertificateOperation op) throws ConnectorException {
        RaProfile raProfile = cert.getRaProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);

        CertificateOperationStatusRequestDto wire = new CertificateOperationStatusRequestDto();
        wire.setMeta(loadMeta(cert, authority));
        wire.setAuthorityAttributes(authorityAttributesFor(authority));
        wire.setRaProfileAttributes(raProfileAttributesFor(raProfile, authority));

        CertificateSyncApiClient v3Client = connectorApiFactory.getCertificateApiClientV3(connectorDto);
        CertificateOperationStatusResponseDto resp = switch (op) {
            case ISSUE, RENEW -> v3Client.getIssueStatus(connectorDto, wire);
            case REVOKE       -> v3Client.getRevokeStatus(connectorDto, wire);
            case REGISTER     -> v3Client.getRegisterStatus(connectorDto, wire);
        };
        return new StatusPollResult(resp.getStatus(), resp.getCertificateData(), resp.getMeta(), resp.getReason());
    }

    @Override
    public CancelResult cancel(Certificate cert, CertificateOperation op) throws ConnectorException {
        RaProfile raProfile = cert.getRaProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);

        CertificateOperationCancelRequestDto wire = new CertificateOperationCancelRequestDto();
        wire.setMeta(loadMeta(cert, authority));
        wire.setAuthorityAttributes(authorityAttributesFor(authority));
        wire.setRaProfileAttributes(raProfileAttributesFor(raProfile, authority));

        CertificateSyncApiClient v3Client = connectorApiFactory.getCertificateApiClientV3(connectorDto);
        try {
            switch (op) {
                case ISSUE, RENEW -> v3Client.cancelIssue(connectorDto, wire);
                case REVOKE       -> v3Client.cancelRevoke(connectorDto, wire);
                case REGISTER     -> v3Client.cancelRegister(connectorDto, wire);
            }
            return new CancelResult(CancelOutcome.CANCELLED);
        } catch (ConnectorProblemException e) {
            ErrorCode code = e.getProblemDetail() != null ? e.getProblemDetail().getErrorCode() : null;
            if (code == ErrorCode.OPERATION_PAST_POINT_OF_NO_RETURN) {
                return new CancelResult(CancelOutcome.REFUSED_PAST_POINT_OF_NO_RETURN);
            }
            if (ConnectorOperationErrorCodes.isOperationNotTracked(code)) {
                return new CancelResult(CancelOutcome.NOT_TRACKED);
            }
            throw e;
        }
    }

    // ---- private helpers ----

    @FunctionalInterface
    private interface ConnectorCall {
        ResponseEntity<CertificateDataResponseDto> call() throws ConnectorException;
    }

    /**
     * Runs a v3 connector call and maps the response, applying the post-acceptance failure rule:
     * once the connector returns 2xx, a failure in the local mapping is surfaced as
     * {@link ConnectorAcceptedButLocalFailureException} (callers must NOT roll back state).
     * Connector-side failures (the call itself throwing) propagate unchanged.
     */
    private AdapterOperationResult executeWithAcceptanceGuard(
            CertificateOperation op, ConnectorCall call,
            java.util.function.Function<ResponseEntity<CertificateDataResponseDto>, AdapterOperationResult> mapper)
            throws ConnectorException {
        boolean connectorAccepted = false;
        try {
            ResponseEntity<CertificateDataResponseDto> response = call.call();
            connectorAccepted = response.getStatusCode().is2xxSuccessful();
            return mapper.apply(response);
        } catch (ConnectorException e) {
            throw e;
        } catch (RuntimeException e) {
            if (connectorAccepted) {
                throw new ConnectorAcceptedButLocalFailureException(
                        "Connector accepted " + op.name().toLowerCase() + " but local mapping failed", e);
            }
            throw e;
        }
    }

    private List<RequestAttribute> issueAttributesFor(Certificate cert, AuthorityInstanceReference authority) {
        return attributeEngine.getRequestObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, cert.getUuid())
                        .connector(authority.getConnectorUuid())
                        .build());
    }

    private List<RequestAttribute> authorityAttributesFor(AuthorityInstanceReference authority) {
        return attributeEngine.getRequestObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.AUTHORITY, authority.getUuid())
                        .connector(authority.getConnectorUuid())
                        .build());
    }

    private AdapterOperationResult mapIssueRenewRegisterResponse(ResponseEntity<CertificateDataResponseDto> response) {
        CertificateDataResponseDto body = response.getBody();
        int status = response.getStatusCode().value();
        if (status == 202) {
            return AdapterOperationResult.asyncAccepted(body != null ? body.getMeta() : null);
        }
        if (status == 200) {
            return AdapterOperationResult.syncOk(
                    body != null ? body.getCertificateData() : null,
                    body != null ? body.getMeta() : null,
                    body != null ? body.getCertificateType() : null);
        }
        throw new IllegalStateException("Unexpected v3 status: " + status);
    }

    private AdapterOperationResult mapRevokeResponse(ResponseEntity<CertificateDataResponseDto> response) {
        CertificateDataResponseDto body = response.getBody();
        int status = response.getStatusCode().value();
        if (status == 204) {
            return AdapterOperationResult.syncNoContent();
        }
        if (status == 202) {
            return AdapterOperationResult.asyncAccepted(body != null ? body.getMeta() : null);
        }
        if (status == 200) {
            return AdapterOperationResult.syncOk(
                    body != null ? body.getCertificateData() : null,
                    body != null ? body.getMeta() : null,
                    body != null ? body.getCertificateType() : null);
        }
        throw new IllegalStateException("Unexpected v3 revoke status: " + status);
    }
}
