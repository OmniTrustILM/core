package com.otilm.core.certificate.type;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorityCertificateTypesTest {

    private static final String RA_PROFILE_NAME = "profile";

    @Mock
    private RaProfileRepository raProfileRepository;
    @Mock
    private AuthorityProviderAdapterFactory adapterFactory;
    @Mock
    private AuthorityProviderAdapter adapter;

    private AuthorityCertificateTypes authorityCertificateTypes;
    private RaProfile raProfile;

    @BeforeEach
    void createRaProfileOfAnAuthority() {
        var authority = new AuthorityInstanceReference();
        authority.setConnector(new Connector());
        raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        raProfile.setName(RA_PROFILE_NAME);
        raProfile.setAuthorityInstanceReference(authority);
        when(raProfileRepository.findWithAuthorityByUuid(raProfile.getUuid())).thenReturn(Optional.of(raProfile));
        lenient().when(adapterFactory.forAuthority(authority)).thenReturn(adapter);
        authorityCertificateTypes = new AuthorityCertificateTypes(raProfileRepository, adapterFactory);
    }

    @Test
    void returnsTheTypesTheAuthorityReports_whenAskedForAnRaProfile() throws Exception {
        // given
        Set<CertificateType> reported = EnumSet.of(CertificateType.X509, CertificateType.SSH);
        stubReportedTypes(reported);

        // when
        Set<CertificateType> supported = authorityCertificateTypes.supportedTypes(raProfile.getUuid());

        // then
        assertThat(supported).isEqualTo(reported);
    }

    @Test
    void acceptsTheType_whenTheAuthorityReportsIt() throws Exception {
        // given
        stubReportedTypes(EnumSet.of(CertificateType.SSH));

        // when
        ThrowingCallable check = () -> authorityCertificateTypes.requireSupport(CertificateType.SSH, raProfile);

        // then
        assertThatCode(check).doesNotThrowAnyException();
    }

    @Test
    void treatsAMissingTypeAsX509_whenCheckingTheAuthority() throws Exception {
        // given
        stubReportedTypes(EnumSet.of(CertificateType.X509));

        // when
        ThrowingCallable check = () -> authorityCertificateTypes.requireSupport(null, raProfile);

        // then
        assertThatCode(check).doesNotThrowAnyException();
    }

    @Test
    void refusesTheTypeNamingTheRaProfile_whenTheAuthorityDoesNotReportIt() throws Exception {
        // given
        CertificateType notIssued = CertificateType.SSH;
        stubReportedTypes(EnumSet.of(CertificateType.X509));

        // when
        ThrowingCallable check = () -> authorityCertificateTypes.requireSupport(notIssued, raProfile);

        // then
        assertThatThrownBy(check)
                .isInstanceOf(UnsupportedCertificateTypeException.class)
                .hasMessageContaining(notIssued.getCode())
                .hasMessageContaining(RA_PROFILE_NAME);
    }

    @Test
    void refusesWithoutTheConnectorsWords_whenTheAuthorityCannotBeAsked() throws Exception {
        // given
        var connectorFailure = new ConnectorException("text written by the connector");
        when(adapter.listCertificateTypes(raProfile.getAuthorityInstanceReference(), raProfile))
                .thenThrow(connectorFailure);

        // when
        ThrowingCallable check = () -> authorityCertificateTypes.requireSupport(CertificateType.X509, raProfile);

        // then
        assertThatThrownBy(check)
                .isInstanceOf(CertificateTypesUnavailableException.class)
                .hasMessageContaining(RA_PROFILE_NAME)
                .hasMessageNotContaining(connectorFailure.getMessage())
                .hasCause(connectorFailure);
    }

    @Test
    void refusesNamingTheMissingConnector_whenTheAuthorityHasNone() {
        // given
        raProfile.getAuthorityInstanceReference().setConnector(null);

        // when
        ThrowingCallable check = () -> authorityCertificateTypes.requireSupport(CertificateType.X509, raProfile);

        // then
        assertThatThrownBy(check).isInstanceOf(ValidationException.class).hasMessageContaining("not available");
        verifyNoInteractions(adapter);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private void stubReportedTypes(Set<CertificateType> reported) throws ConnectorException {
        when(adapter.listCertificateTypes(raProfile.getAuthorityInstanceReference(), raProfile)).thenReturn(reported);
    }
}
