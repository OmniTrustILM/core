package com.otilm.core.service.handler.authority;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v3.AuthoritySyncApiClient;
import com.otilm.api.interfaces.client.v3.CertificateSyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.connector.v3.certificate.CertificateAttributeListRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateDataResponseDto;
import com.otilm.api.model.connector.v3.certificate.CertificateOperationCancelRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateOperationStatusRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateOperationStatusResponseDto;
import com.otilm.api.model.connector.v3.certificate.CertificateRegistrationRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateRenewRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateRequestContent;
import com.otilm.api.model.connector.v3.certificate.CertificateRevocationRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateSignRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.authority.CertificateRevocationReason;
import com.otilm.api.model.core.v2.ClientCertificateRegistrationDto;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.api.model.core.v2.ClientCertificateSignRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.certificate.request.RegisterWireBuilder;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.exception.ConnectorAcceptedButLocalFailureException;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.v2.ConnectorInternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Function;

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

    private final ConnectorCapabilityService capabilityService;

    @Autowired
    public AuthorityProviderV3Adapter(ConnectorInternalService connectorService,
                                      ConnectorApiFactory connectorApiFactory,
                                      AttributeEngine attributeEngine,
                                      ConnectorCapabilityService capabilityService) {
        super(connectorService, connectorApiFactory, attributeEngine);
        this.capabilityService = capabilityService;
    }

    // ---- AuthorityProviderAdapter ----

    @Override
    public AdapterOperationResult issue(Certificate cert, ClientCertificateSignRequestDto req) throws ConnectorException {
        RaProfile raProfile = cert.getRaProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);

        CertificateSignRequestDtoV3 wire = new CertificateSignRequestDtoV3();
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

        CertificateRenewRequestDtoV3 wire = new CertificateRenewRequestDtoV3();
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

        CertificateRevocationRequestDtoV3 wire = new CertificateRevocationRequestDtoV3();
        wire.setCertificate(cert.getCertificateContent().getContent());
        wire.setReason(req.getReason() != null ? req.getReason() : CertificateRevocationReason.UNSPECIFIED);
        wire.setAttributes(req.getAttributes());
        wire.setMeta(loadMeta(cert, authority));
        wire.setAuthorityAttributes(authorityAttributesFor(authority));
        wire.setRaProfileAttributes(raProfileAttributesFor(raProfile, authority));

        return executeWithAcceptanceGuard(CertificateOperation.REVOKE,
                () -> connectorApiFactory.getCertificateApiClientV3(connectorDto).revoke(connectorDto, wire),
                this::mapRevokeResponse);
    }

    @Override
    public List<BaseAttribute> listAuthorityInstanceAttributes(AuthorityInstanceReference authority) throws ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        return connectorApiFactory.getAuthorityInstanceApiClientV3(connectorDto)
                .listAuthorityAttributes(connectorDto);
    }

    @Override
    public List<BaseAttribute> listRaProfileAttributes(AuthorityInstanceReference authority) throws ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        return connectorApiFactory.getAuthorityInstanceApiClientV3(connectorDto)
                .listRaProfileAttributes(connectorDto, authorityAttributesFor(authority));
    }

    @Override
    public List<BaseAttribute> listIssueAttributes(AuthorityInstanceReference authority, RaProfile raProfile) throws ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        return connectorApiFactory.getCertificateApiClientV3(connectorDto)
                .listIssueAttributes(connectorDto, attributeListRequest(authority, raProfile));
    }

    @Override
    public List<BaseAttribute> listRevokeAttributes(AuthorityInstanceReference authority, RaProfile raProfile) throws ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        return connectorApiFactory.getCertificateApiClientV3(connectorDto)
                .listRevokeAttributes(connectorDto, attributeListRequest(authority, raProfile));
    }

    @Override
    public void validateIssueAttributes(AuthorityInstanceReference authority, List<RequestAttribute> attributes) {
        // v3 has no connector-side /validate; the caller validates structurally against the listed
        // definitions (AttributeEngine.validateUpdateDataAttributes) — no connector round-trip.
    }

    @Override
    public void validateRevokeAttributes(AuthorityInstanceReference authority, List<RequestAttribute> attributes) {
        // v3 has no connector-side /validate — see validateIssueAttributes.
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
    public List<BaseAttribute> listRegisterAttributes(AuthorityInstanceReference authority, RaProfile raProfile) throws ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        return connectorApiFactory.getCertificateApiClientV3(connectorDto)
                .listRegisterAttributes(connectorDto, attributeListRequest(authority, raProfile));
    }

    @Override
    public AdapterOperationResult register(Certificate cert, ClientCertificateRegistrationDto req) throws ConnectorException {
        RaProfile raProfile = cert.getRaProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);

        X509RequestContent content = RegisterWireBuilder.buildContent(
                req != null ? req.getSubjectDn() : null,
                req != null ? req.getSubjectAltName() : null,
                req != null ? req.getExtensions() : null);
        boolean structured = capabilityService.supports(authority, FeatureFlag.CERTIFICATE_REQUEST_STRUCTURED);
        CertificateRegistrationRequestDtoV3 wire = RegisterWireBuilder.buildRegistration(content, structured);
        if (req != null) {
            wire.setAttributes(req.getAttributes());
        }
        wire.setAuthorityAttributes(authorityAttributesFor(authority));
        wire.setRaProfileAttributes(raProfileAttributesFor(raProfile, authority));

        return executeWithAcceptanceGuard(CertificateOperation.REGISTER,
                () -> connectorApiFactory.getCertificateApiClientV3(connectorDto).register(connectorDto, wire),
                this::mapIssueRenewRegisterResponse);
    }

    @Override
    public AdapterOperationResult issueRegistered(Certificate cert, List<MetadataAttribute> replayMeta,
                                                  CertificateRequestContent requestContent) throws ConnectorException {
        RaProfile raProfile = cert.getRaProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);

        CertificateSignRequestDtoV3 wire = new CertificateSignRequestDtoV3();
        // Forward the CSR intact to preserve proof-of-possession.
        wire.setRequest(cert.getCertificateRequest().getContent());
        wire.setFormat(cert.getCertificateRequest().getCertificateRequestFormat());
        wire.setAttributes(issueAttributesFor(cert, authority));
        wire.setAuthorityAttributes(authorityAttributesFor(authority));
        wire.setRaProfileAttributes(raProfileAttributesFor(raProfile, authority));
        // Replay the binding's CA handle; fall back to stored meta when the binding carried none.
        wire.setMeta(replayMeta != null && !replayMeta.isEmpty() ? replayMeta : loadMeta(cert, authority));
        wire.setRequestContent(requestContent);

        return executeWithAcceptanceGuard(CertificateOperation.ISSUE,
                () -> connectorApiFactory.getCertificateApiClientV3(connectorDto).issue(connectorDto, wire),
                this::mapIssueRenewRegisterResponse);
    }

    // ---- AsyncOperationCapability ----

    @Override
    public StatusPollResult pollStatus(Certificate cert, CertificateOperation op) throws ConnectorException {
        RaProfile raProfile = cert.getRaProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);

        CertificateOperationStatusRequestDtoV3 wire = new CertificateOperationStatusRequestDtoV3();
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

        CertificateOperationCancelRequestDtoV3 wire = new CertificateOperationCancelRequestDtoV3();
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
            Function<ResponseEntity<CertificateDataResponseDto>, AdapterOperationResult> mapper)
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
                        .operation(AttributeOperation.CERTIFICATE_ISSUE)
                        .build());
    }

    private List<RequestAttribute> authorityAttributesFor(AuthorityInstanceReference authority) {
        return attributeEngine.getRequestObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.AUTHORITY, authority.getUuid())
                        .connector(authority.getConnectorUuid())
                        .build());
    }

    /**
     * Builds the body for the three v3 attribute-list endpoints (issue/revoke/register). Both
     * attribute blobs are required so the stateless connector can identify the upstream CA AND
     * scope the returned schema to a specific RA profile. {@code raProfile} may be null only for
     * authority-wide listing flows that don't exist today — callers go through the operator
     * controller which always carries a profile.
     */
    private CertificateAttributeListRequestDtoV3 attributeListRequest(AuthorityInstanceReference authority, RaProfile raProfile) {
        CertificateAttributeListRequestDtoV3 dto = new CertificateAttributeListRequestDtoV3();
        dto.setAuthorityAttributes(authorityAttributesFor(authority));
        dto.setRaProfileAttributes(raProfile != null ? raProfileAttributesFor(raProfile, authority) : List.of());
        return dto;
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
