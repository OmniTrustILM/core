package com.otilm.core.service.handler.authority;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.v3.certificate.CertificateRequestContent;
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
     * Sends a pre-registration request to the upstream CA, which reserves a slot/identity and returns a tracking
     * handle in the response metadata.
     *
     * <p><b>Failure contract:</b> any failure <i>after</i> the connector accepts (HTTP 2xx/202) MUST be thrown as
     * {@link com.otilm.core.exception.ConnectorAcceptedButLocalFailureException}; a raw {@link RuntimeException}
     * therefore signals a pre-acceptance failure with no upstream work in flight.
     *
     * @return SYNC_OK when the CA confirmed immediately, ASYNC_ACCEPTED when polling is needed.
     */
    AdapterOperationResult register(Certificate cert, ClientCertificateRegistrationDto req) throws ConnectorException;

    /**
     * Issues a certificate against a prior registration: the client CSR is forwarded <b>intact</b>
     * (proof-of-possession preserved), the binding's CA handle is replayed as {@code meta}, and the optional
     * {@code requestContent} carries the registered identity for connectors advertising
     * {@code CERTIFICATE_IDENTITY_OVERRIDE}.
     *
     * <p><b>Failure contract:</b> same as {@link #register} — post-acceptance failures surface as
     * {@link com.otilm.core.exception.ConnectorAcceptedButLocalFailureException}.
     *
     * @param replayMeta     the CA handle from the binding; when empty the adapter falls back to stored metadata
     * @param requestContent the registered identity, or null when the connector lacks the override capability
     */
    AdapterOperationResult issueRegistered(Certificate cert, List<MetadataAttribute> replayMeta,
                                           @Nullable CertificateRequestContent requestContent) throws ConnectorException;
}
