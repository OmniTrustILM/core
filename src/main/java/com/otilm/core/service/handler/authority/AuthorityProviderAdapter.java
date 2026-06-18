package com.otilm.core.service.handler.authority;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.api.model.core.v2.ClientCertificateSignRequestDto;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;

import java.util.List;

/**
 * Common authority-provider operations supported by every interface version (v1 not implemented).
 * Methods take Core's operator DTOs; adapter translates to version-specific wire DTOs internally.
 */
public interface AuthorityProviderAdapter {

    /**
     * Issues a certificate through the authority provider.
     *
     * @param cert the certificate to issue — provides the CSR ({@code getCertificateRequest()}) and
     *             the RA-profile association used to resolve connector attributes.
     * @param req  the operator-level sign request DTO. Currently informational at the adapter layer:
     *             the wire body is reconstructed from the persisted certificate plus the attribute
     *             engine (Core persists the operator's CSR + request attributes before the adapter
     *             runs, then the adapter re-reads them). Kept for contract symmetry with
     *             {@code renew}/{@code revoke}/{@code register}, which do consume their DTOs.
     */
    AdapterOperationResult issue(Certificate cert, ClientCertificateSignRequestDto req) throws ConnectorException;

    /**
     * Renews (or rekeys) a certificate through the authority provider.
     *
     * @param oldCert the predecessor certificate — provides the old cert content
     *                ({@code getCertificateContent().getContent()}) and its connector-issued metadata.
     * @param newCert the successor certificate — provides the new CSR
     *                ({@code getCertificateRequest().getContent()} / {@code .getCertificateRequestFormat()})
     *                and the RA profile association used to look up connector attributes.
     * @param req     the operator-level renew request DTO. Not consumed by the adapter: client-visible
     *                fields (e.g. {@code replaceInLocations}) are handled by the service layer and the
     *                wire body is derived from oldCert/newCert. Kept for contract symmetry with the
     *                other operations.
     */
    AdapterOperationResult renew(Certificate oldCert, Certificate newCert, ClientCertificateRenewRequestDto req) throws ConnectorException;

    AdapterOperationResult revoke(Certificate cert, ClientCertificateRevocationDto req) throws ConnectorException;

    /**
     * Authority-instance attribute definitions. v2 lists via the function-group attribute endpoint
     * (`/v1/authorityProvider/{kind}/attributes`); v3 via the stateless
     * `/v3/authorityProvider/authorities/attributes`. Used by authority create/edit so the operator
     * input is validated against the version-correct schema (legacy connectors do NOT use this —
     * they stay on the function-group path in ConnectorService).
     */
    List<BaseAttribute> listAuthorityInstanceAttributes(AuthorityInstanceReference authority) throws ConnectorException;

    /**
     * RA-profile attribute schema for the authority — the attributes an operator fills when defining
     * an RA profile under this authority. v2 keys it by {@code authorityInstanceUuid}; v3 is stateless
     * and resolves it from the authority's own data attributes.
     */
    List<BaseAttribute> listRaProfileAttributes(AuthorityInstanceReference authority) throws ConnectorException;

    /**
     * Dynamic issue-attribute schema scoped to a specific RA profile. v3 carries both
     * {@code authorityAttributes} (auth/identity to the upstream CA) and {@code raProfileAttributes}
     * (which profile/template determines the schema). v2 ignores {@code raProfile} — its endpoint
     * is keyed by {@code authorityInstanceUuid} alone and returns a single per-authority schema.
     */
    List<BaseAttribute> listIssueAttributes(AuthorityInstanceReference authority, RaProfile raProfile) throws ConnectorException;

    /** See {@link #listIssueAttributes} — identical semantics for revoke. */
    List<BaseAttribute> listRevokeAttributes(AuthorityInstanceReference authority, RaProfile raProfile) throws ConnectorException;

    /**
     * Connector-side validation of operator-supplied issue attributes. v2 calls the connector's
     * {@code /validate} endpoint; v3 is a no-op (the v3 contract dropped {@code /validate} — Core
     * validates structurally against the listed definitions instead).
     */
    void validateIssueAttributes(AuthorityInstanceReference authority, List<RequestAttribute> attributes) throws ValidationException, ConnectorException;

    /** Connector-side validation of operator-supplied revoke attributes. See {@link #validateIssueAttributes}. */
    void validateRevokeAttributes(AuthorityInstanceReference authority, List<RequestAttribute> attributes) throws ValidationException, ConnectorException;

    void checkAuthorityConnection(AuthorityInstanceReference authority, List<RequestAttribute> attributes) throws ValidationException, ConnectorException;
}
