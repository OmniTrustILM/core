package com.otilm.core.integration.service;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.settings.BrandingSettingsDto;
import com.otilm.api.model.core.settings.BrandingSettingsUpdateDto;
import com.otilm.api.model.core.settings.BrandingTheme;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SettingsSectionCategory;
import com.otilm.core.dao.entity.Setting;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.sql.DataSource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;

class BrandingSettingsITest extends BaseSpringBootTest {

    private static final String PRIMARY = "#0073CF";
    private static final String SECONDARY = "#00A3E0";

    @Autowired
    private SettingExternalService settingService;

    @Autowired
    private SettingRepository settingRepository;

    @Autowired
    private DataSource dataSource;

    private List<Setting> storedBranding() {
        return settingRepository
                .findBySectionAndCategory(SettingsSection.PLATFORM,
                        SettingsSectionCategory.PLATFORM_BRANDING.getCode());
    }

    private BrandingSettingsUpdateDto update(String primary, String secondary, BrandingTheme theme) {
        BrandingSettingsUpdateDto branding = new BrandingSettingsUpdateDto();
        branding.setPrimaryColor(primary);
        branding.setSecondaryColor(secondary);
        branding.setDefaultTheme(theme);
        return branding;
    }

    @Test
    void anUnbrandedPlatformReportsBrandingWithEveryFieldUnset() {
        BrandingSettingsDto branding = settingService.getBrandingSettings();

        Assertions.assertNotNull(branding);
        Assertions.assertNull(branding.getPrimaryColor());
        Assertions.assertNull(branding.getLightLogo());
        Assertions.assertNull(branding.getDefaultTheme());
        Assertions.assertTrue(storedBranding().isEmpty());
    }

    @Test
    void brandingIsPersistedAndReadBack() {
        settingService.updateBrandingSettings(update(PRIMARY, SECONDARY, BrandingTheme.DARK));

        BrandingSettingsDto branding = settingService.getBrandingSettings();

        Assertions.assertEquals(PRIMARY, branding.getPrimaryColor());
        Assertions.assertEquals(SECONDARY, branding.getSecondaryColor());
        Assertions.assertEquals(BrandingTheme.DARK, branding.getDefaultTheme());
    }

    /** Branding is stored under the PLATFORM section, so the platform read has to carry it as its own category. */
    @Test
    void brandingIsPartOfThePlatformSettings() {
        settingService.updateBrandingSettings(update(PRIMARY, null, null));

        PlatformSettingsDto platform = settingService.getPlatformSettings();

        Assertions.assertNotNull(platform.getBranding());
        Assertions.assertEquals(PRIMARY, platform.getBranding().getPrimaryColor());
        Assertions
                .assertTrue(storedBranding()
                        .stream()
                        .allMatch(setting -> SettingsSectionCategory.PLATFORM_BRANDING
                                .getCode()
                                .equals(setting.getCategory())));
    }

    /**
     * Reset to default is per field rather than all-or-nothing: the row is removed so the field falls back on its own,
     * leaving the fields the operator kept exactly as they were.
     */
    @Test
    void clearingOneFieldRemovesOnlyItsOwnRow() {
        settingService.updateBrandingSettings(update(PRIMARY, SECONDARY, BrandingTheme.LIGHT));
        Assertions.assertEquals(3, storedBranding().size());

        settingService.updateBrandingSettings(update(PRIMARY, null, BrandingTheme.LIGHT));

        BrandingSettingsDto branding = settingService.getBrandingSettings();
        Assertions.assertEquals(PRIMARY, branding.getPrimaryColor());
        Assertions.assertNull(branding.getSecondaryColor());
        Assertions.assertEquals(BrandingTheme.LIGHT, branding.getDefaultTheme());
        Assertions.assertEquals(2, storedBranding().size());
        Assertions
                .assertTrue(storedBranding().stream().noneMatch(setting -> "secondaryColor".equals(setting.getName())));
    }

    @Test
    void clearingEveryFieldLeavesNoStoredBranding() {
        settingService.updateBrandingSettings(update(PRIMARY, SECONDARY, BrandingTheme.DARK));

        settingService.updateBrandingSettings(new BrandingSettingsUpdateDto());

        Assertions.assertTrue(storedBranding().isEmpty());
        Assertions.assertNull(settingService.getBrandingSettings().getPrimaryColor());
    }

    @Test
    void anInvalidColorIsRejectedAndNothingIsStored() {
        BrandingSettingsUpdateDto branding = update("not-a-color", SECONDARY, null);

        Assertions.assertThrows(ValidationException.class, () -> settingService.updateBrandingSettings(branding));
        Assertions.assertTrue(storedBranding().isEmpty());
    }

    @Test
    void anInvalidLogoIsRejectedBeforeAnyFieldIsWritten() {
        BrandingSettingsUpdateDto branding = update(PRIMARY, SECONDARY, null);
        branding.setLightLogo("data:image/jpeg;base64,/9j/4AAQ");

        Assertions.assertThrows(ValidationException.class, () -> settingService.updateBrandingSettings(branding));
        Assertions.assertTrue(storedBranding().isEmpty());
    }

    /**
     * The platform settings read is on the hot path for every page render, so a theme code that no longer maps to
     * anything is dropped rather than allowed to fail the whole read.
     */
    /**
     * Each field is written by looking for its row and inserting when there is none, so two first updates racing each
     * other could both find nothing and insert the same field twice. The lock is held by this test on a connection of
     * its own, which is enough to show the update waits for it rather than reading rows out from under a concurrent
     * writer.
     */
    @Test
    void aBrandingUpdateWaitsForAConcurrentOneToRelease() throws Exception {
        try (Connection lockHolder = dataSource.getConnection()) {
            lockHolder.setAutoCommit(false);
            try (var lock = lockHolder
                    .prepareStatement("SELECT pg_advisory_xact_lock(hashtext('platform-branding-settings'))")) {
                lock.execute();
            }

            CountDownLatch reached = new CountDownLatch(1);
            CompletableFuture<Void> concurrentUpdate = CompletableFuture.runAsync(() -> {
                SecurityContextHolder.getContext().setAuthentication(getAuthentication());
                reached.countDown();
                settingService.updateBrandingSettings(update(PRIMARY, SECONDARY, BrandingTheme.DARK));
            });

            Assertions.assertTrue(reached.await(10, TimeUnit.SECONDS));
            Assertions
                    .assertThrows(TimeoutException.class, () -> concurrentUpdate.get(1, TimeUnit.SECONDS),
                            "the update did not wait for the branding lock");

            lockHolder.rollback();
            Assertions.assertDoesNotThrow(() -> concurrentUpdate.get(30, TimeUnit.SECONDS));
        }

        Assertions.assertEquals(3, storedBranding().size());
        Assertions.assertEquals(PRIMARY, settingService.getBrandingSettings().getPrimaryColor());
    }

    @Test
    void anUnknownStoredThemeIsIgnoredRatherThanFailingTheRead() {
        Setting theme = new Setting();
        theme.setSection(SettingsSection.PLATFORM);
        theme.setCategory(SettingsSectionCategory.PLATFORM_BRANDING.getCode());
        theme.setName("defaultTheme");
        theme.setValue("midnight");
        settingRepository.save(theme);

        BrandingSettingsDto branding = settingService.getBrandingSettings();

        Assertions.assertNull(branding.getDefaultTheme());
    }

    /**
     * The reason branding has its own action at all. Every other grant this caller holds — including {@code UPDATE}
     * over settings — is left in place, so a refusal here can only come from the missing {@code UPDATE_BRANDING}.
     */
    @Test
    void anOperatorWithoutUpdateBrandingCannotChangeBranding() {
        denyResourceAccess(Resource.SETTINGS, ResourceAction.UPDATE_BRANDING);
        BrandingSettingsUpdateDto branding = update(PRIMARY, SECONDARY, null);

        Assertions.assertThrows(AccessDeniedException.class, () -> settingService.updateBrandingSettings(branding));
        Assertions.assertTrue(storedBranding().isEmpty());
    }

    /** The same caller still reads branding, which is gated by the broader LIST the settings pages already need. */
    @Test
    void anOperatorWithoutUpdateBrandingCanStillReadBranding() {
        settingService.updateBrandingSettings(update(PRIMARY, null, null));
        denyResourceAccess(Resource.SETTINGS, ResourceAction.UPDATE_BRANDING);

        Assertions.assertEquals(PRIMARY, settingService.getBrandingSettings().getPrimaryColor());
    }

    /**
     * The sanitizer is only worth anything if it sits between the request and the row. Asserted against the stored
     * value rather than the read-back DTO, so a sanitizer wired in after persistence would still fail here.
     */
    @Test
    void onlyTheSanitizedSvgReachesTheSettingsTable() {
        String hostile = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 100'>"
                + "<script>alert(1)</script><rect width='200' height='100' onload='alert(2)' fill='#0073CF'/></svg>";
        BrandingSettingsUpdateDto branding = new BrandingSettingsUpdateDto();
        branding
                .setLightLogo("data:image/svg+xml;base64,"
                        + Base64.getEncoder().encodeToString(hostile.getBytes(StandardCharsets.UTF_8)));

        settingService.updateBrandingSettings(branding);

        String stored = storedBranding()
                .stream()
                .filter(setting -> "lightLogo".equals(setting.getName()))
                .findFirst()
                .orElseThrow()
                .getValue();
        String decoded = new String(Base64.getDecoder().decode(stored.substring(stored.indexOf(',') + 1)),
                StandardCharsets.UTF_8);

        Assertions.assertFalse(decoded.contains("script"), decoded);
        Assertions.assertFalse(decoded.contains("onload"), decoded);
        Assertions.assertTrue(decoded.contains("#0073CF"), decoded);
    }

    @Test
    void theExistingPlatformCategoriesAreUnaffected() {
        settingService.updateBrandingSettings(update(PRIMARY, SECONDARY, BrandingTheme.DARK));

        PlatformSettingsDto platform = settingService.getPlatformSettings();

        Assertions.assertNotNull(platform.getUtils());
        Assertions.assertNotNull(platform.getCertificates());
        Assertions.assertTrue(platform.getCertificates().getValidation().getEnabled());
    }
}
