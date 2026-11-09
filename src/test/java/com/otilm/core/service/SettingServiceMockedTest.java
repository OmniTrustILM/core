package com.otilm.core.service;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.settings.CertificateRegistrationSettingsUpdateDto;
import com.otilm.api.model.core.settings.CertificateSettingsUpdateDto;
import com.otilm.api.model.core.settings.PlatformSettingsUpdateDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SigningSettingsDto;
import com.otilm.api.model.core.settings.UtilsSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsUpdateDto;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.impl.SettingServiceImpl;
import com.otilm.core.settings.SettingsCache;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SettingServiceMockedTest {

    @Mock
    private SettingRepository settingRepository;
    @Mock
    private SettingsCache settingsCache;

    private SettingServiceImpl settingService;

    @BeforeEach
    void setUp() {
        settingService = new SettingServiceImpl(settingsCache, settingRepository, ObjectMapperFactory.wire());
    }

    /**
     * Integration tests are single-threaded, so they stay green if the locks are removed or swapped. This pins the
     * fixed order that keeps the keys acyclic: utils, certificates, signing, all before the rows are read.
     */
    @Test
    void takesTheSectionLocksInOrderBeforeReadingTheRows_whenEverySectionIsUpdated() {
        // given
        when(settingRepository.findBySection(SettingsSection.PLATFORM)).thenReturn(List.of());
        PlatformSettingsUpdateDto everySection = createAllSectionsUpdate();

        // when
        settingService.updatePlatformSettings(everySection);

        // then
        InOrder inOrder = inOrder(settingRepository);
        inOrder.verify(settingRepository).lockUtilsWrites();
        inOrder.verify(settingRepository).lockCertificateWrites();
        inOrder.verify(settingRepository).lockSigningWrites();
        inOrder.verify(settingRepository).findBySection(SettingsSection.PLATFORM);
    }

    /** Integration tests are single-threaded, so they do not detect an unnecessary lock for an omitted section. */
    @Test
    void takesOnlyTheUtilsLock_whenTheUpdateCarriesOnlyUtils() {
        // given
        when(settingRepository.findBySection(SettingsSection.PLATFORM)).thenReturn(List.of());
        PlatformSettingsUpdateDto utilsOnly = new PlatformSettingsUpdateDto();
        utilsOnly.setUtils(new UtilsSettingsDto());

        // when
        settingService.updatePlatformSettings(utilsOnly);

        // then
        verify(settingRepository).lockUtilsWrites();
        verify(settingRepository, never()).lockCertificateWrites();
        verify(settingRepository, never()).lockSigningWrites();
    }

    @Test
    void takesOnlyTheCertificatesLock_whenTheUpdateCarriesOnlyCertificates() {
        // given
        when(settingRepository.findBySection(SettingsSection.PLATFORM)).thenReturn(List.of());
        PlatformSettingsUpdateDto certificatesOnly = createAllSectionsUpdate();
        certificatesOnly.setUtils(null);
        certificatesOnly.setSigning(null);

        // when
        settingService.updatePlatformSettings(certificatesOnly);

        // then
        verify(settingRepository).lockCertificateWrites();
        verify(settingRepository, never()).lockUtilsWrites();
        verify(settingRepository, never()).lockSigningWrites();
    }

    @Test
    void takesOnlyTheSigningLock_whenTheUpdateCarriesOnlySigning() {
        // given
        when(settingRepository.findBySection(SettingsSection.PLATFORM)).thenReturn(List.of());
        PlatformSettingsUpdateDto signingOnly = new PlatformSettingsUpdateDto();
        signingOnly.setSigning(new SigningSettingsDto());

        // when
        settingService.updatePlatformSettings(signingOnly);

        // then
        verify(settingRepository).lockSigningWrites();
        verify(settingRepository, never()).lockUtilsWrites();
        verify(settingRepository, never()).lockCertificateWrites();
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://example.com:-1/jwks", "http://example.com:+1/jwks"})
    void anOAuth2ProviderUpdateRejectsAJwkSetUrlWithASignedPort(String jwkSetUrl) {
        OAuth2ProviderSettingsUpdateDto providerSettings = new OAuth2ProviderSettingsUpdateDto();
        providerSettings.setJwkSetUrl(jwkSetUrl);

        ValidationException exception = Assertions
                .assertThrows(ValidationException.class,
                        () -> settingService.updateOAuth2ProviderSettings("signed-port-jwk-url", providerSettings));

        Assertions
                .assertEquals("JWK Set URL is invalid: Illegal character in port number at index 19.",
                        exception.getMessage());
    }

    private static PlatformSettingsUpdateDto createAllSectionsUpdate() {
        CertificateSettingsUpdateDto certificates = new CertificateSettingsUpdateDto();
        certificates.setRegistration(new CertificateRegistrationSettingsUpdateDto());
        PlatformSettingsUpdateDto update = new PlatformSettingsUpdateDto();
        update.setUtils(new UtilsSettingsDto());
        update.setCertificates(certificates);
        update.setSigning(new SigningSettingsDto());
        return update;
    }
}
