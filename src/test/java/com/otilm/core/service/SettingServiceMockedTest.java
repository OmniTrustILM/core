package com.otilm.core.service;

import com.otilm.api.model.core.settings.CertificateRegistrationSettingsUpdateDto;
import com.otilm.api.model.core.settings.CertificateSettingsUpdateDto;
import com.otilm.api.model.core.settings.PlatformSettingsUpdateDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.UtilsSettingsDto;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.impl.SettingServiceImpl;
import com.otilm.core.settings.SettingsCache;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The advisory locks a platform settings update takes, and their order. The integration tests are single-threaded, so
 * they would stay green with the locks gone or swapped; this pins what they cannot.
 */
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
        when(settingRepository.findBySection(SettingsSection.PLATFORM)).thenReturn(List.of());
    }

    /** Utils first, then certificates, both before the rows are read: a fixed order is what keeps two keys acyclic. */
    @Test
    void aPlatformUpdateTakesTheUtilsLockThenTheCertificatesLockBeforeReadingTheRows() {
        settingService.updatePlatformSettings(bothSections());

        InOrder inOrder = inOrder(settingRepository);
        inOrder.verify(settingRepository).lockUtilsWrites();
        inOrder.verify(settingRepository).lockCertificateWrites();
        inOrder.verify(settingRepository).findBySection(SettingsSection.PLATFORM);
    }

    @Test
    void aSectionLeftOutOfTheUpdateTakesNoLock() {
        PlatformSettingsUpdateDto utilsOnly = new PlatformSettingsUpdateDto();
        utilsOnly.setUtils(new UtilsSettingsDto());
        settingService.updatePlatformSettings(utilsOnly);
        verify(settingRepository).lockUtilsWrites();
        verify(settingRepository, never()).lockCertificateWrites();

        clearInvocations(settingRepository);
        PlatformSettingsUpdateDto certificatesOnly = bothSections();
        certificatesOnly.setUtils(null);
        settingService.updatePlatformSettings(certificatesOnly);
        verify(settingRepository).lockCertificateWrites();
        verify(settingRepository, never()).lockUtilsWrites();
    }

    private static PlatformSettingsUpdateDto bothSections() {
        CertificateSettingsUpdateDto certificates = new CertificateSettingsUpdateDto();
        certificates.setRegistration(new CertificateRegistrationSettingsUpdateDto());
        PlatformSettingsUpdateDto update = new PlatformSettingsUpdateDto();
        update.setUtils(new UtilsSettingsDto());
        update.setCertificates(certificates);
        return update;
    }
}
