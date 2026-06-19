package com.otilm.core.service.handler.authority.lifecycle;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.service.CryptographicKeyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CertificateRevocationFinalizerTest {

    @Mock private AttributeEngine attributeEngine;
    @Mock private CryptographicKeyService keyService;

    private CertificateRevocationFinalizer finalizer;

    private static final UUID CERT_UUID = UUID.randomUUID();
    private static final UUID CONNECTOR_UUID = UUID.randomUUID();
    private static final UUID KEY_UUID = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        finalizer = new CertificateRevocationFinalizer(attributeEngine, keyService);
    }

    @Test
    void prepareRevokeFinalization_appliesAttributes_capturesDestroyKey_clearsFields() throws Exception {
        Certificate cert = certWithAuthority();
        when(cert.getPendingRevokeAttributes()).thenReturn(List.of(mock(RequestAttribute.class)));
        when(cert.getPendingRevokeDestroyKey()).thenReturn(Boolean.TRUE);
        when(cert.getKey()).thenReturn(mock(CryptographicKey.class));
        when(cert.getKeyUuid()).thenReturn(KEY_UUID);

        CertificateRevocationFinalizer.KeyCleanup cleanup = finalizer.prepareRevokeFinalization(cert);

        assertThat(cleanup.destroyKey()).isTrue();
        assertThat(cleanup.keyUuid()).isEqualTo(KEY_UUID);
        verify(attributeEngine).updateObjectDataAttributesContent(any(ObjectAttributeContentInfo.class), any());
        verify(cert).setPendingRevokeDestroyKey(null);
        verify(cert).setPendingRevokeAttributes(null);
    }

    @Test
    void prepareRevokeFinalization_noAttributes_noDestroyKey_noKey() throws Exception {
        Certificate cert = certWithAuthority();
        when(cert.getPendingRevokeAttributes()).thenReturn(null);
        when(cert.getPendingRevokeDestroyKey()).thenReturn(null);
        when(cert.getKey()).thenReturn(null);

        CertificateRevocationFinalizer.KeyCleanup cleanup = finalizer.prepareRevokeFinalization(cert);

        assertThat(cleanup.destroyKey()).isFalse();
        assertThat(cleanup.keyUuid()).isNull();
        verifyNoInteractions(attributeEngine);
        verify(cert).setPendingRevokeDestroyKey(null);
        verify(cert).setPendingRevokeAttributes(null);
    }

    @Test
    void applyPreservedRevokeAttributes_emptyList_skips() {
        Certificate cert = certWithAuthority();
        when(cert.getPendingRevokeAttributes()).thenReturn(List.of());

        finalizer.applyPreservedRevokeAttributes(cert);

        verifyNoInteractions(attributeEngine);
    }

    @Test
    void applyPreservedRevokeAttributes_engineFailure_swallowed() throws Exception {
        Certificate cert = certWithAuthority();
        when(cert.getPendingRevokeAttributes()).thenReturn(List.of(mock(RequestAttribute.class)));
        doThrow(new IllegalStateException("attr engine down"))
                .when(attributeEngine).updateObjectDataAttributesContent(any(ObjectAttributeContentInfo.class), any());

        // Best-effort: a failure here must not propagate (the connector revoke already completed).
        finalizer.applyPreservedRevokeAttributes(cert);

        verify(attributeEngine).updateObjectDataAttributesContent(any(ObjectAttributeContentInfo.class), any());
    }

    @Test
    void destroyKeyIfRequested_destroys() throws Exception {
        finalizer.destroyKeyIfRequested(new CertificateRevocationFinalizer.KeyCleanup(true, KEY_UUID), CERT_UUID);

        verify(keyService).destroyKey(eq(List.of(KEY_UUID.toString())));
    }

    @Test
    void destroyKeyIfRequested_none_doesNothing() {
        finalizer.destroyKeyIfRequested(CertificateRevocationFinalizer.KeyCleanup.NONE, CERT_UUID);

        verifyNoInteractions(keyService);
    }

    @Test
    void destroyKeyIfRequested_destroyTrueButNoKeyUuid_doesNothing() {
        finalizer.destroyKeyIfRequested(new CertificateRevocationFinalizer.KeyCleanup(true, null), CERT_UUID);

        verifyNoInteractions(keyService);
    }

    @Test
    void destroyKeyIfRequested_keyServiceFailure_swallowed() throws Exception {
        doThrow(new IllegalStateException("key service down"))
                .when(keyService).destroyKey(any());

        // Best-effort, post-commit: a failure must not propagate after the revoke is committed.
        finalizer.destroyKeyIfRequested(new CertificateRevocationFinalizer.KeyCleanup(true, KEY_UUID), CERT_UUID);

        verify(keyService).destroyKey(any());
    }

    @Test
    void clearPendingRevokeFields_clearsBoth() {
        Certificate cert = mock(Certificate.class);

        finalizer.clearPendingRevokeFields(cert);

        verify(cert).setPendingRevokeDestroyKey(null);
        verify(cert).setPendingRevokeAttributes(null);
    }

    private Certificate certWithAuthority() {
        AuthorityInstanceReference authority = mock(AuthorityInstanceReference.class);
        lenient().when(authority.getConnectorUuid()).thenReturn(CONNECTOR_UUID);
        RaProfile raProfile = mock(RaProfile.class);
        lenient().when(raProfile.getAuthorityInstanceReference()).thenReturn(authority);
        Certificate cert = mock(Certificate.class);
        lenient().when(cert.getUuid()).thenReturn(CERT_UUID);
        lenient().when(cert.getRaProfile()).thenReturn(raProfile);
        return cert;
    }
}
