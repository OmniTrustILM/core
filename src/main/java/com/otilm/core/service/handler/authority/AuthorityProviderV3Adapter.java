package com.otilm.core.service.handler.authority;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v3.AuthoritySyncApiClient;
import com.otilm.api.interfaces.client.v3.CertificateSyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.connector.v3.certificate.CertificateAttributeListRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateDataResponseDto;
import com.otilm.api.model.connector.v3.certificate.CertificateOperationCancelRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateOperationStatusRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateOperationStatusResponseDto;
import com.otilm.api.model.connector.v3.certificate.CertificateRegistrationRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateRenewRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateRevocationRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateSignRequestDtoV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.authority.CertificateRevocationReason;
import com.otilm.api.model.core.v2.ClientCertificateRegistrationDto;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.api.model.core.v2.ClientCertificateSignRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.exception.ConnectorAcceptedButLocalFailureException;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.service.v2.ConnectorInternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
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

    private final OperationAttributeResolver operationAttributeResolver;
    private final OutboundSecretContainment outboundContainment;

    @Autowired
    public AuthorityProviderV3Adapter(ConnectorInternalService connectorService,
                                      ConnectorApiFactory connectorApiFactory,
                                      AttributeEngine attributeEngine,
                                      OperationAttributeResolver operationAttributeResolver,
                                      OutboundSecretContainment outboundContainment) {
        super(connectorService, connectorApiFactory, attributeEngine);
        this.operationAttributeResolver = operationAttributeResolver;
        this.outboundContainment = outboundContainment;
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
        wire.setRaProfileAttributes(resolvedRaProfileAttributes(raProfile, authority));
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
        wire.setRaProfileAttributes(resolvedRaProfileAttributes(raProfile, authority));

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
        wire.setRaProfileAttributes(resolvedRaProfileAttributes(raProfile, authority));

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
        List<RequestAttribute> authorityAttributes = authorityAttributesFor(authority);
        List<BaseAttribute> response = connectorApiFactory.getAuthorityInstanceApiClientV3(connectorDto)
                .listRaProfileAttributes(connectorDto, authorityAttributes);
        return contained(response, authorityAttributes);
    }

    @Override
    public List<BaseAttribute> listIssueAttributes(AuthorityInstanceReference authority, RaProfile raProfile) throws ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        CertificateAttributeListRequestDtoV3 request = attributeListRequest(authority, raProfile);
        List<BaseAttribute> response = connectorApiFactory.getCertificateApiClientV3(connectorDto)
                .listIssueAttributes(connectorDto, request);
        return contained(response, request.getAuthorityAttributes(), request.getRaProfileAttributes());
    }

    @Override
    public List<BaseAttribute> listRevokeAttributes(AuthorityInstanceReference authority, RaProfile raProfile) throws ConnectorException {
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);
        CertificateAttributeListRequestDtoV3 request = attributeListRequest(authority, raProfile);
        List<BaseAttribute> response = connectorApiFactory.getCertificateApiClientV3(connectorDto)
                .listRevokeAttributes(connectorDto, request);
        return contained(response, request.getAuthorityAttributes(), request.getRaProfileAttributes());
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
        CertificateAttributeListRequestDtoV3 request = attributeListRequest(authority, raProfile);
        List<BaseAttribute> response = connectorApiFactory.getCertificateApiClientV3(connectorDto)
                .listRegisterAttributes(connectorDto, request);
        return contained(response, request.getAuthorityAttributes(), request.getRaProfileAttributes());
    }

    /**
     * Fail closed if the connector echoed back a secret Core expanded into the request. The v3 attribute-list
     * responses flow to the operator's attribute-selection UI (unlike issue/revoke/register, whose response is
     * certificate data), so they get the same outbound-secret containment the callback path applies.
     */
    @SafeVarargs
    private List<BaseAttribute> contained(List<BaseAttribute> response, List<RequestAttribute>... sentAttributes) {
        Set<String> expandedSecrets = new HashSet<>();
        for (List<RequestAttribute> attributes : sentAttributes) {
            outboundContainment.recordExpandedSecretsFromRequest(attributes, expandedSecrets);
        }
        outboundContainment.assertNoExpandedSecretOutbound(response, expandedSecrets);
        return response;
    }

    @Override
    public AdapterOperationResult register(Certificate cert, ClientCertificateRegistrationDto req) throws ConnectorException {
        RaProfile raProfile = cert.getRaProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        ApiClientConnectorInfo connectorDto = connectorForApiClient(authority);

        CertificateRegistrationRequestDtoV3 wire = new CertificateRegistrationRequestDtoV3();
        if (req != null) {
            wire.setSubjectDn(req.getSubjectDn());
            wire.setSubjectAltName(req.getSubjectAltName());
            wire.setExtensions(req.getExtensions());
            wire.setAttributes(req.getAttributes());
        }
        wire.setAuthorityAttributes(authorityAttributesFor(authority));
        wire.setRaProfileAttributes(resolvedRaProfileAttributes(raProfile, authority));

        return executeWithAcceptanceGuard(CertificateOperation.REGISTER,
                () -> connectorApiFactory.getCertificateApiClientV3(connectorDto).register(connectorDto, wire),
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
        wire.setRaProfileAttributes(resolvedRaProfileAttributes(raProfile, authority));

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
        wire.setRaProfileAttributes(resolvedRaProfileAttributes(raProfile, authority));

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

    /**
     * v3 connectors are stateless: the stored authority/ra-profile attributes carry references (CREDENTIAL, RESOURCE
     * incl. SECRET) the connector cannot resolve itself. Core resolves them to inline content via
     * {@link OperationAttributeResolver} under the platform's attribute-content-resolver system identity — authorized at the
     * operation level, not per acting caller (so it works for operators, protocol robots, and the principal-less
     * status-poll path alike). v2 stays stateful and is untouched — the base adapter's non-dereferencing helpers
     * still serve it.
     */
    private List<RequestAttribute> authorityAttributesFor(AuthorityInstanceReference authority) throws ConnectorException {
        List<RequestAttribute> stored = attributeEngine.getRequestObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.AUTHORITY, authority.getUuid())
                        .connector(authority.getConnectorUuid())
                        .build());
        return operationAttributeResolver.resolveForConnectorRequestAsSystem(authority.getConnectorUuid(), stored);
    }

    private List<RequestAttribute> resolvedRaProfileAttributes(RaProfile raProfile, AuthorityInstanceReference authority)
            throws ConnectorException {
        return operationAttributeResolver.resolveForConnectorRequestAsSystem(
                authority.getConnectorUuid(), raProfileAttributesFor(raProfile, authority));
    }

    /**
     * Builds the body for the three v3 attribute-list endpoints (issue/revoke/register). Both
     * attribute blobs are required so the stateless connector can identify the upstream CA AND
     * scope the returned schema to a specific RA profile. {@code raProfile} may be null only for
     * authority-wide listing flows that don't exist today — callers go through the operator
     * controller which always carries a profile.
     */
    private CertificateAttributeListRequestDtoV3 attributeListRequest(AuthorityInstanceReference authority, RaProfile raProfile) throws ConnectorException {
        CertificateAttributeListRequestDtoV3 dto = new CertificateAttributeListRequestDtoV3();
        dto.setAuthorityAttributes(authorityAttributesFor(authority));
        dto.setRaProfileAttributes(raProfile != null ? resolvedRaProfileAttributes(raProfile, authority) : List.of());
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
