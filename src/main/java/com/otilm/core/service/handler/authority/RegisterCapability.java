package com.otilm.core.service.handler.authority;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.v3.certificate.CertificateRequestContent;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.v2.ClientCertificateRegistrationDto;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import org.springframework.lang.Nullable;

import java.util.List;

/**
 * v3-only capability: pre-register a certificate identity at the upstream CA before a CSR exists.
 */
public interface RegisterCapability {

    /** Dynamic register-attribute schema scoped to an RA profile (authority + RA-profile attributes). */
    List<BaseAttribute> listRegisterAttributes(AuthorityInstanceReference authority, RaProfile raProfile) throws ConnectorException;

    /**
     * Sends a pre-registration request; the CA reserves a slot/identity and returns a tracking handle in the
     * response metadata.
     *
     * <p><b>Failure contract:</b> a failure after the connector accepts (2xx/202) must throw
     * {@link com.otilm.core.exception.ConnectorAcceptedButLocalFailureException}; a raw {@link RuntimeException}
     * signals a pre-acceptance failure.
     *
     * @param identityContent the registration identity projected once by the orchestrator — from structured
     *                         {@code csrAttributes} or from the flat subjectDn/subjectAltName/extensions — so the
     *                         persisted placeholder and the wire derive from the same content; when null the
     *                         adapter builds it from the request's flat fields defensively
     * @return SYNC_OK when the CA confirmed immediately, ASYNC_ACCEPTED when polling is needed.
     */
    AdapterOperationResult register(Certificate cert, ClientCertificateRegistrationDto req,
                                    @Nullable X509RequestContent identityContent) throws ConnectorException;

    /**
     * Issues a certificate against a prior registration: the client CSR is forwarded intact, the binding's CA
     * handle is replayed as {@code meta}, and {@code requestContent} carries the registered identity for
     * connectors advertising {@code CERTIFICATE_IDENTITY_OVERRIDE}. Failure contract is the same as
     * {@link #register}.
     *
     * @param replayMeta     the CA handle from the binding; when empty the adapter falls back to stored metadata
     * @param requestContent the registered identity, or null when the connector lacks the override capability
     */
    AdapterOperationResult issueRegistered(Certificate cert, List<MetadataAttribute> replayMeta,
                                           @Nullable CertificateRequestContent requestContent) throws ConnectorException;
}
