package com.otilm.core.integration.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.settings.CertificateRegistrationSettingsUpdateDto;
import com.otilm.api.model.core.settings.CertificateRequestAttributesSettingsUpdateDto;
import com.otilm.api.model.core.settings.CertificateSettingsUpdateDto;
import com.otilm.api.model.core.settings.CertificateValidationSettingsUpdateDto;
import com.otilm.api.model.core.settings.EventSettingsDto;
import com.otilm.api.model.core.settings.EventsSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsUpdateDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SettingsSectionCategory;
import com.otilm.api.model.core.settings.UtilsSettingsDto;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsUpdateDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsResponseDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsUpdateDto;
import com.otilm.core.attribute.CsrAttributes;
import com.otilm.core.dao.entity.Setting;
import com.otilm.core.dao.entity.workflows.Trigger;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.dao.repository.workflows.TriggerRepository;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.impl.SettingServiceImpl;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

class SettingServiceITest extends BaseSpringBootTest {

    private static final String TEST_TRIGGER_NAME = "testTriggerName";
    private static final String TEST_TRIGGER_UUID = "3a1db3f5-f9eb-4fbf-92c9-c4c1499bfca7";
    private static final String UNREACHABLE_JWK_SET_URL = "http://127.0.0.1:1/jwks";

    @Autowired
    private SettingExternalService settingService;

    @Autowired
    private SettingRepository settingRepository;

    @Autowired
    private TriggerRepository triggerRepository;

    @BeforeEach
    void setUp() {
        Trigger trigger = new Trigger();
        trigger.setUuid(UUID.fromString(TEST_TRIGGER_UUID));
        trigger.setName(TEST_TRIGGER_NAME);
        trigger.setResource(Resource.CERTIFICATE);

        triggerRepository.save(trigger);
    }

    @Test
    void updatePlatformSettings() {
        String utilsServiceUrl = "http://util-service:8080";
        String cbomRepositoryUrl = "http://cbom-repository:8080";

        PlatformSettingsDto platformSettings = settingService.getPlatformSettings();
        Assertions.assertNull(platformSettings.getUtils().getUtilsServiceUrl());
        Assertions.assertNull(platformSettings.getUtils().getCbomRepositoryUrl());
        Assertions.assertNotNull(platformSettings.getCertificates());
        Assertions.assertTrue(platformSettings.getCertificates().getValidation().getEnabled());
        Assertions.assertEquals(1, platformSettings.getCertificates().getValidation().getFrequency());

        PlatformSettingsUpdateDto platformSettingsUpdateDto = new PlatformSettingsUpdateDto();
        UtilsSettingsDto utilsSettingsDto = new UtilsSettingsDto();
        utilsSettingsDto.setUtilsServiceUrl(utilsServiceUrl);
        utilsSettingsDto.setCbomRepositoryUrl(cbomRepositoryUrl);
        platformSettingsUpdateDto.setUtils(utilsSettingsDto);
        CertificateSettingsUpdateDto certificateSettingsUpdateDto = new CertificateSettingsUpdateDto();
        CertificateValidationSettingsUpdateDto certificateValidationSettingsUpdateDto = new CertificateValidationSettingsUpdateDto();
        certificateValidationSettingsUpdateDto.setFrequency(5);
        certificateSettingsUpdateDto.setValidation(certificateValidationSettingsUpdateDto);
        platformSettingsUpdateDto.setCertificates(certificateSettingsUpdateDto);
        settingService.updatePlatformSettings(platformSettingsUpdateDto);

        platformSettings = settingService.getPlatformSettings();
        Assertions.assertEquals(utilsServiceUrl, platformSettings.getUtils().getUtilsServiceUrl());
        Assertions.assertEquals(cbomRepositoryUrl, platformSettings.getUtils().getCbomRepositoryUrl());
        Assertions.assertEquals(5, platformSettings.getCertificates().getValidation().getFrequency());
    }

    @Test
    void platformCbomSyncTunablesDefaultToSixtySecondsThreeRunsAndFiftyDocumentsAndAreEditable() {
        // A fresh platform reports the sync policy defaults, so a form shows what the sync will use.
        PlatformSettingsDto seeded = settingService.getPlatformSettings();
        Assertions.assertEquals(60, seeded.getUtils().getCbomSyncOverlapSeconds());
        Assertions.assertEquals(3, seeded.getUtils().getCbomSyncSkippedRetryRuns());
        Assertions.assertEquals(50, seeded.getUtils().getCbomSyncMaxIngestDocuments());
        Assertions.assertEquals(90, seeded.getUtils().getCbomSyncSkipRetentionDays());

        UtilsSettingsDto utils = new UtilsSettingsDto();
        utils.setCbomSyncOverlapSeconds(120);
        utils.setCbomSyncSkippedRetryRuns(0);
        utils.setCbomSyncMaxIngestDocuments(5);
        utils.setCbomSyncSkipRetentionDays(30);
        PlatformSettingsUpdateDto update = new PlatformSettingsUpdateDto();
        update.setUtils(utils);
        settingService.updatePlatformSettings(update);

        PlatformSettingsDto edited = settingService.getPlatformSettings();
        Assertions.assertEquals(120, edited.getUtils().getCbomSyncOverlapSeconds());
        Assertions.assertEquals(0, edited.getUtils().getCbomSyncSkippedRetryRuns());
        Assertions.assertEquals(5, edited.getUtils().getCbomSyncMaxIngestDocuments());
        Assertions.assertEquals(30, edited.getUtils().getCbomSyncSkipRetentionDays());
        // ...and the cache the sync reads its policy from holds the same.
        PlatformSettingsDto cached = SettingsCache.getSettings(SettingsSection.PLATFORM);
        Assertions.assertEquals(0, cached.getUtils().getCbomSyncSkippedRetryRuns());
    }

    @Test
    void aStoredCbomSyncTunableOutsideTheContractBoundsReadsAsItsDefault() {
        // Only a manual edit can put such values there: the API validates the bounds before the write. The read keeps
        // the sync on the defaults rather than failing every run on a corrupt row.
        storeUtilsSetting(SettingServiceImpl.CBOM_SYNC_OVERLAP_SECONDS_NAME, "99999999");
        storeUtilsSetting(SettingServiceImpl.CBOM_SYNC_SKIPPED_RETRY_RUNS_NAME, "-5");
        storeUtilsSetting(SettingServiceImpl.CBOM_SYNC_MAX_INGEST_DOCUMENTS_NAME, "fifty");
        // The retention has a floor of one day: a stored zero is below it and reads as the default too.
        storeUtilsSetting(SettingServiceImpl.CBOM_SYNC_SKIP_RETENTION_DAYS_NAME, "0");

        PlatformSettingsDto read = settingService.getPlatformSettings();

        Assertions.assertEquals(60, read.getUtils().getCbomSyncOverlapSeconds());
        Assertions.assertEquals(3, read.getUtils().getCbomSyncSkippedRetryRuns());
        Assertions.assertEquals(50, read.getUtils().getCbomSyncMaxIngestDocuments());
        Assertions.assertEquals(90, read.getUtils().getCbomSyncSkipRetentionDays());
    }

    /**
     * The read runs on every cache refresh, so a corrupt value is reported when it appears and again only after it was
     * corrected -- not once per refresh, and not never again.
     */
    @Test
    void aCorruptCbomSyncTunableIsReportedWhenItAppearsAndAgainAfterACorrection() {
        ListAppender<ILoggingEvent> logged = new ListAppender<>();
        logged.start();
        Logger settingsLogger = (Logger) LoggerFactory.getLogger(SettingServiceImpl.class);
        settingsLogger.addAppender(logged);
        try {
            // a valid read first, so whatever an earlier test reported for this name is cleared
            storeUtilsSetting(SettingServiceImpl.CBOM_SYNC_MAX_INGEST_DOCUMENTS_NAME, "50");
            settingService.getPlatformSettings();
            Setting stored = utilsRow(SettingServiceImpl.CBOM_SYNC_MAX_INGEST_DOCUMENTS_NAME);

            stored.setValue("fifty");
            settingRepository.save(stored);
            settingService.getPlatformSettings();
            settingService.getPlatformSettings();
            Assertions.assertEquals(1, corruptIngestBudgetReports(logged), "reported once, not once per read");

            stored.setValue("50");
            settingRepository.save(stored);
            Assertions
                    .assertEquals(50, settingService.getPlatformSettings().getUtils().getCbomSyncMaxIngestDocuments());
            stored.setValue("fifty");
            settingRepository.save(stored);
            settingService.getPlatformSettings();
            Assertions.assertEquals(2, corruptIngestBudgetReports(logged), "reported again after a correction");
        } finally {
            settingsLogger.detachAppender(logged);
            logged.stop();
        }
    }

    private Setting utilsRow(String name) {
        return settingRepository
                .findBySection(SettingsSection.PLATFORM)
                .stream()
                .filter(setting -> SettingsSectionCategory.PLATFORM_UTILS.getCode().equals(setting.getCategory())
                        && name.equals(setting.getName()))
                .findFirst()
                .orElseThrow();
    }

    private static long corruptIngestBudgetReports(ListAppender<ILoggingEvent> logged) {
        return logged.list
                .stream()
                .filter(event -> event.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage)
                .filter(message -> message.contains(SettingServiceImpl.CBOM_SYNC_MAX_INGEST_DOCUMENTS_NAME)
                        && message.contains("'fifty'"))
                .count();
    }

    private void storeUtilsSetting(String name, String value) {
        Setting setting = new Setting();
        setting.setSection(SettingsSection.PLATFORM);
        setting.setCategory(SettingsSectionCategory.PLATFORM_UTILS.getCode());
        setting.setName(name);
        setting.setValue(value);
        settingRepository.save(setting);
    }

    @Test
    void anUnsetCbomSyncTunableFallsBackToItsDefaultAndLeavesNoRow() {
        UtilsSettingsDto utils = new UtilsSettingsDto();
        utils.setCbomRepositoryUrl("http://cbom-repository.example");
        utils.setCbomSyncSkippedRetryRuns(1);
        PlatformSettingsUpdateDto update = new PlatformSettingsUpdateDto();
        update.setUtils(utils);
        settingService.updatePlatformSettings(update);
        PlatformSettingsDto set = settingService.getPlatformSettings();
        Assertions.assertEquals("http://cbom-repository.example", set.getUtils().getCbomRepositoryUrl());
        Assertions.assertEquals(1, set.getUtils().getCbomSyncSkippedRetryRuns());

        // The section is replaced as sent. Nothing set: the URL is cleared and every tunable is back to its default.
        update.setUtils(new UtilsSettingsDto());
        settingService.updatePlatformSettings(update);
        PlatformSettingsDto reverted = settingService.getPlatformSettings();
        Assertions.assertNull(reverted.getUtils().getCbomRepositoryUrl());
        Assertions.assertEquals(3, reverted.getUtils().getCbomSyncSkippedRetryRuns());
        Assertions.assertEquals(60, reverted.getUtils().getCbomSyncOverlapSeconds());
        Assertions.assertEquals(50, reverted.getUtils().getCbomSyncMaxIngestDocuments());
        // ...and no row with a null value is left behind to be read on every cache refresh.
        Assertions
                .assertTrue(
                        settingRepository
                                .findBySection(SettingsSection.PLATFORM)
                                .stream()
                                .noneMatch(setting -> SettingsSectionCategory.PLATFORM_UTILS
                                        .getCode()
                                        .equals(setting.getCategory())),
                        "an unset utils value must not leave a row behind");
    }

    /**
     * What the PUT documents (interfaces#974): a section left out of the body is untouched, a present {@code utils} is
     * stored as sent, and inside {@code certificates} each group is untouched when left out and stored as sent when
     * present.
     */
    @Test
    void aSectionOrCertificatesGroupLeftOutOfThePlatformUpdateIsUntouched() {
        // given: the utils section and two certificate groups hold operator values
        UtilsSettingsDto utils = new UtilsSettingsDto();
        utils.setCbomRepositoryUrl("http://cbom-repository.example");
        utils.setCbomSyncSkippedRetryRuns(1);
        CertificateRegistrationSettingsUpdateDto registration = new CertificateRegistrationSettingsUpdateDto();
        registration.setDefaultIssuanceWindowDays(14);
        registration.setMaxFailedAttempts(3);
        CertificateValidationSettingsUpdateDto validation = new CertificateValidationSettingsUpdateDto();
        validation.setEnabled(true);
        validation.setFrequency(5);
        validation.setExpiringThreshold(45);
        CertificateSettingsUpdateDto certificates = new CertificateSettingsUpdateDto();
        certificates.setRegistration(registration);
        certificates.setValidation(validation);
        PlatformSettingsUpdateDto seed = new PlatformSettingsUpdateDto();
        seed.setUtils(utils);
        seed.setCertificates(certificates);
        settingService.updatePlatformSettings(seed);

        // when: a certificates-only update carries only the validation group
        CertificateValidationSettingsUpdateDto validationOnly = new CertificateValidationSettingsUpdateDto();
        validationOnly.setEnabled(true);
        validationOnly.setFrequency(2);
        validationOnly.setExpiringThreshold(45);
        CertificateSettingsUpdateDto validationGroup = new CertificateSettingsUpdateDto();
        validationGroup.setValidation(validationOnly);
        PlatformSettingsUpdateDto certificatesOnly = new PlatformSettingsUpdateDto();
        certificatesOnly.setCertificates(validationGroup);
        settingService.updatePlatformSettings(certificatesOnly);

        // then: the utils section and the registration group are untouched, the validation group is as sent
        PlatformSettingsDto afterCertificates = settingService.getPlatformSettings();
        Assertions.assertEquals("http://cbom-repository.example", afterCertificates.getUtils().getCbomRepositoryUrl());
        Assertions.assertEquals(1, afterCertificates.getUtils().getCbomSyncSkippedRetryRuns());
        Assertions
                .assertEquals(14, afterCertificates.getCertificates().getRegistration().getDefaultIssuanceWindowDays());
        Assertions.assertEquals(3, afterCertificates.getCertificates().getRegistration().getMaxFailedAttempts());
        Assertions.assertEquals(2, afterCertificates.getCertificates().getValidation().getFrequency());

        // when: a utils-only update carries a retry budget and no URL
        UtilsSettingsDto utilsOnly = new UtilsSettingsDto();
        utilsOnly.setCbomSyncSkippedRetryRuns(0);
        PlatformSettingsUpdateDto utilsUpdate = new PlatformSettingsUpdateDto();
        utilsUpdate.setUtils(utilsOnly);
        settingService.updatePlatformSettings(utilsUpdate);

        // then: the certificates section is untouched, the utils section is as sent: URL cleared, budget zero
        PlatformSettingsDto afterUtils = settingService.getPlatformSettings();
        Assertions.assertEquals(14, afterUtils.getCertificates().getRegistration().getDefaultIssuanceWindowDays());
        Assertions.assertEquals(2, afterUtils.getCertificates().getValidation().getFrequency());
        Assertions.assertNull(afterUtils.getUtils().getCbomRepositoryUrl());
        Assertions.assertEquals(0, afterUtils.getUtils().getCbomSyncSkippedRetryRuns());
    }

    @Test
    void platformRegistrationSettingsDefaultToSevenAndFiveAndAreEditable() {
        // A fresh platform reports the registration defaults (7-day issuance window, 5 failed attempts).
        PlatformSettingsDto seeded = settingService.getPlatformSettings();
        Assertions.assertNotNull(seeded.getCertificates().getRegistration());
        Assertions.assertEquals(7, seeded.getCertificates().getRegistration().getDefaultIssuanceWindowDays());
        Assertions.assertEquals(5, seeded.getCertificates().getRegistration().getMaxFailedAttempts());

        CertificateRegistrationSettingsUpdateDto registration = new CertificateRegistrationSettingsUpdateDto();
        registration.setDefaultIssuanceWindowDays(14);
        registration.setMaxFailedAttempts(3);
        CertificateSettingsUpdateDto certificateSettings = new CertificateSettingsUpdateDto();
        certificateSettings.setRegistration(registration);
        PlatformSettingsUpdateDto update = new PlatformSettingsUpdateDto();
        update.setCertificates(certificateSettings);
        settingService.updatePlatformSettings(update);

        // The edited values are read back, and a registration-only update leaves validation untouched.
        PlatformSettingsDto edited = settingService.getPlatformSettings();
        Assertions.assertEquals(14, edited.getCertificates().getRegistration().getDefaultIssuanceWindowDays());
        Assertions.assertEquals(3, edited.getCertificates().getRegistration().getMaxFailedAttempts());
        Assertions.assertNotNull(edited.getCertificates().getValidation());
        Assertions.assertTrue(edited.getCertificates().getValidation().getEnabled());
    }

    @Test
    void platformRequestAttributesDefaultSetIsSeededAndEditable() {
        // given: a fresh platform has no stored default set -> getPlatformSettings seeds it from CsrAttributes
        PlatformSettingsDto seeded = settingService.getPlatformSettings();
        Assertions.assertNotNull(seeded.getCertificates().getRequestAttributes());
        Assertions.assertFalse(seeded.getCertificates().getRequestAttributes().getRequestAttributes().isEmpty());
        Assertions.assertNull(seeded.getCertificates().getRequestAttributes().getExternalCsrValidationStrict());

        // when: the operator edits the default set (one definition + strict flag)
        DataAttributeV3 definition = CsrAttributes.commonNameAttribute();

        CertificateRequestAttributesSettingsUpdateDto requestAttributes = new CertificateRequestAttributesSettingsUpdateDto();
        requestAttributes.setRequestAttributes(List.of(definition));
        requestAttributes.setExternalCsrValidationStrict(Boolean.TRUE);
        CertificateSettingsUpdateDto certificateSettings = new CertificateSettingsUpdateDto();
        certificateSettings.setRequestAttributes(requestAttributes);
        PlatformSettingsUpdateDto update = new PlatformSettingsUpdateDto();
        update.setCertificates(certificateSettings);
        settingService.updatePlatformSettings(update);

        // then: the edited set is read back, and validation settings are unaffected by a request-attributes-only update
        PlatformSettingsDto edited = settingService.getPlatformSettings();
        Assertions.assertEquals(1, edited.getCertificates().getRequestAttributes().getRequestAttributes().size());
        Assertions
                .assertEquals("commonName",
                        edited.getCertificates().getRequestAttributes().getRequestAttributes().get(0).getName());
        Assertions
                .assertEquals(Boolean.TRUE,
                        edited.getCertificates().getRequestAttributes().getExternalCsrValidationStrict());
        Assertions.assertNotNull(edited.getCertificates().getValidation());
    }

    @Test
    void platformRequestAttributesUpdateRejectsInvalidDefinition() {
        // read-only without a default value: the definition can never be satisfied on a request form
        DataAttributeV3 readOnlyNoDefault = CsrAttributes.commonNameAttribute();
        readOnlyNoDefault.getProperties().setReadOnly(true);

        CertificateRequestAttributesSettingsUpdateDto requestAttributes = new CertificateRequestAttributesSettingsUpdateDto();
        requestAttributes.setRequestAttributes(List.of(readOnlyNoDefault));
        CertificateSettingsUpdateDto certificateSettings = new CertificateSettingsUpdateDto();
        certificateSettings.setRequestAttributes(requestAttributes);
        PlatformSettingsUpdateDto update = new PlatformSettingsUpdateDto();
        update.setCertificates(certificateSettings);

        Assertions.assertThrows(ValidationException.class, () -> settingService.updatePlatformSettings(update));

        // nothing was persisted: the read model still serves the seeded default set
        PlatformSettingsDto after = settingService.getPlatformSettings();
        Assertions.assertTrue(after.getCertificates().getRequestAttributes().getRequestAttributes().size() > 1);
    }

    @Test
    void testPlatformSettingsExceptions() {
        Setting setting = new Setting();
        setting.setSection(SettingsSection.PLATFORM);
        setting.setName(SettingServiceImpl.CERTIFICATES_VALIDATION_SETTINGS_NAME);
        setting.setCategory(SettingsSectionCategory.PLATFORM_CERTIFICATES.getCode());
        setting.setValue("invalid");
        settingRepository.save(setting);
        PlatformSettingsDto platformSettingsDto = settingService.getPlatformSettings();
        Assertions.assertNotNull(platformSettingsDto.getCertificates().getValidation());
    }

    @Test
    void testRetrievingJwkSet() throws JsonProcessingException, JOSEException, ParseException {

        RSAKey rsaJwk = new RSAKeyGenerator(2048).generate();

        ECKey ecJwk = new ECKeyGenerator(Curve.P_256).generate();

        OctetSequenceKey aesJwk = new OctetSequenceKeyGenerator(128).generate();

        OctetKeyPair octetKeyPairJwk = OctetKeyPair
                .parse("{\"kty\":\"OKP\",\"d\":\"y85lxYiKx57Dwgs2rH1b0yTVxeLJWmpt48WfivLXBbU\",\"crv\":\"Ed25519\",\"x\":\"tO6vOgx0YOVuWdevkbYzaihxcCLx8DfqRs2nvs3CBxU\", \"kid\": \"123\"}");

        JWKSet jwkSet = new JWKSet(List.of(rsaJwk, ecJwk, aesJwk, octetKeyPairJwk));

        OAuth2ProviderSettingsUpdateDto providerSettings = new OAuth2ProviderSettingsUpdateDto();
        ObjectMapper objectMapper = new ObjectMapper();

        providerSettings
                .setJwkSet(Base64
                        .getEncoder()
                        .encodeToString(objectMapper.writeValueAsString(jwkSet.toJSONObject(false)).getBytes()));
        Setting oauth2Setting = new Setting();
        oauth2Setting.setValue(objectMapper.writeValueAsString(providerSettings));
        oauth2Setting.setName("name");
        oauth2Setting.setSection(SettingsSection.AUTHENTICATION);
        oauth2Setting.setCategory(SettingsSectionCategory.OAUTH2_PROVIDER.getCode());
        settingRepository.save(oauth2Setting);

        OAuth2ProviderSettingsResponseDto oAuth2ProvidersSettingsUpdateDto = settingService
                .getOAuth2ProviderSettings("name", false);
        Assertions
                .assertEquals(Base64.getEncoder().encodeToString(rsaJwk.toPublicKey().getEncoded()),
                        oAuth2ProvidersSettingsUpdateDto
                                .getJwkSetKeys()
                                .stream()
                                .filter(jwk -> jwk.getKeyType().equals("RSA"))
                                .findFirst()
                                .get()
                                .getPublicKey());
        Assertions
                .assertEquals(Base64.getEncoder().encodeToString(ecJwk.toPublicKey().getEncoded()),
                        oAuth2ProvidersSettingsUpdateDto
                                .getJwkSetKeys()
                                .stream()
                                .filter(jwk -> jwk.getKeyType().equals("EC"))
                                .findFirst()
                                .get()
                                .getPublicKey());
        Assertions
                .assertEquals(Base64.getEncoder().encodeToString(aesJwk.toByteArray()),
                        oAuth2ProvidersSettingsUpdateDto
                                .getJwkSetKeys()
                                .stream()
                                .filter(jwk -> jwk.getKeyType().equals("oct"))
                                .findFirst()
                                .get()
                                .getPublicKey());
        Assertions
                .assertEquals(Base64.getEncoder().encodeToString(octetKeyPairJwk.getDecodedX()),
                        oAuth2ProvidersSettingsUpdateDto
                                .getJwkSetKeys()
                                .stream()
                                .filter(jwk -> jwk.getKeyType().equals("OKP"))
                                .findFirst()
                                .get()
                                .getPublicKey());
    }

    @Test
    void getOAuth2ProviderSettings_returnsStoredSettingsWhenJwkSetUrlIsUnreachable() throws Exception {
        String providerName = "unreachable-read";
        OAuth2ProviderSettingsDto providerSettings = createProviderDto(providerName);
        providerSettings.setJwkSet(null);
        providerSettings.setJwkSetUrl(UNREACHABLE_JWK_SET_URL);

        Setting setting = new Setting();
        setting.setValue(new ObjectMapper().writeValueAsString(providerSettings));
        setting.setName(providerName);
        setting.setSection(SettingsSection.AUTHENTICATION);
        setting.setCategory(SettingsSectionCategory.OAUTH2_PROVIDER.getCode());
        settingRepository.save(setting);

        OAuth2ProviderSettingsResponseDto response = Assertions
                .assertDoesNotThrow(() -> settingService.getOAuth2ProviderSettings(providerName, false));

        Assertions.assertEquals(UNREACHABLE_JWK_SET_URL, response.getJwkSetUrl());
        Assertions.assertNotNull(response.getJwkSetKeys());
        Assertions.assertTrue(response.getJwkSetKeys().isEmpty());
    }

    @Test
    void getOAuth2ProviderSettings_rejectsMalformedEmbeddedJwkSet() throws Exception {
        String providerName = "malformed-embedded-read";
        OAuth2ProviderSettingsDto providerSettings = createProviderDto(providerName);
        providerSettings
                .setJwkSet(Base64.getEncoder().encodeToString("not-a-jwk-set".getBytes(StandardCharsets.UTF_8)));

        Setting setting = new Setting();
        setting.setValue(new ObjectMapper().writeValueAsString(providerSettings));
        setting.setName(providerName);
        setting.setSection(SettingsSection.AUTHENTICATION);
        setting.setCategory(SettingsSectionCategory.OAUTH2_PROVIDER.getCode());
        settingRepository.save(setting);

        Assertions
                .assertThrows(ValidationException.class,
                        () -> settingService.getOAuth2ProviderSettings(providerName, false));
    }

    @Test
    void updateOAuth2ProviderSettings_persistsSettingsWhenJwkSetUrlIsUnreachable() throws Exception {
        String providerName = "unreachable-update";
        OAuth2ProviderSettingsUpdateDto providerSettings = createProviderUpdateDto();
        providerSettings.setJwkSet(null);
        providerSettings.setJwkSetUrl(UNREACHABLE_JWK_SET_URL);

        Assertions
                .assertDoesNotThrow(() -> settingService.updateOAuth2ProviderSettings(providerName, providerSettings));

        OAuth2ProviderSettingsDto stored = settingService
                .getAuthenticationSettings(true)
                .getOAuth2Providers()
                .get(providerName);
        Assertions.assertEquals(UNREACHABLE_JWK_SET_URL, stored.getJwkSetUrl());
    }

    @Test
    void updateOAuth2ProviderSettings_rejectsBlankJwkSetUrlWithoutEmbeddedJwkSet() throws Exception {
        OAuth2ProviderSettingsUpdateDto providerSettings = createProviderUpdateDto();
        providerSettings.setJwkSet(null);
        providerSettings.setJwkSetUrl(" ");

        Assertions
                .assertThrows(ValidationException.class,
                        () -> settingService.updateOAuth2ProviderSettings("blank-jwk-url", providerSettings));
    }

    @Test
    void updateOAuth2ProviderSettings_rejectsMalformedJwkSetUrl() throws Exception {
        OAuth2ProviderSettingsUpdateDto providerSettings = createProviderUpdateDto();
        providerSettings.setJwkSet(null);
        providerSettings.setJwkSetUrl("not a url");

        Assertions
                .assertThrows(ValidationException.class,
                        () -> settingService.updateOAuth2ProviderSettings("malformed-jwk-url", providerSettings));
    }

    @Test
    void updateOAuth2ProviderSettings_rejectsMalformedEmbeddedJwkSet() throws Exception {
        OAuth2ProviderSettingsUpdateDto providerSettings = createProviderUpdateDto();
        providerSettings
                .setJwkSet(Base64.getEncoder().encodeToString("not-a-jwk-set".getBytes(StandardCharsets.UTF_8)));

        Assertions
                .assertThrows(ValidationException.class,
                        () -> settingService.updateOAuth2ProviderSettings("malformed-embedded", providerSettings));
    }

    @Test
    void testUpdateAuthenticationSettings() {
        AuthenticationSettingsUpdateDto authenticationSettingsUpdateDto = new AuthenticationSettingsUpdateDto();
        authenticationSettingsUpdateDto.setDisableLocalhostUser(true);
        authenticationSettingsUpdateDto.setOAuth2Providers(List.of());

        Assertions
                .assertDoesNotThrow(() -> settingService.updateAuthenticationSettings(authenticationSettingsUpdateDto),
                        "Updating authentication settings should not throw any exception");
    }

    @Test
    void testUpdateEventSettings() {
        EventsSettingsDto eventSettings = settingService.getEventsSettings();
        Assertions.assertNotNull(eventSettings);

        Assertions
                .assertDoesNotThrow(() -> settingService.updateEventsSettings(eventSettings),
                        "Updating event settings should not throw any exception");

        EventSettingsDto eventSettingsDto = new EventSettingsDto();
        eventSettingsDto.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        eventSettingsDto.setTriggerUuids(List.of(UUID.fromString(TEST_TRIGGER_UUID)));

        Assertions
                .assertDoesNotThrow(() -> settingService.updateEventSettings(eventSettingsDto),
                        "Updating event settings should not throw any exception");
    }

    @Test
    void testUpdateNonExistingTriggerEventSettings() {
        EventsSettingsDto eventsSettings = new EventsSettingsDto();
        Map<ResourceEvent, List<UUID>> eventsMapping = new EnumMap<>(ResourceEvent.class);
        eventsMapping
                .put(ResourceEvent.CERTIFICATE_DISCOVERED,
                        List.of(UUID.fromString("3a1db3f5-f9eb-4fbf-92c9-c4c1499bfca8")));
        eventsSettings.setEventsMapping(eventsMapping);

        Assertions.assertThrows(NotFoundException.class, () -> settingService.updateEventsSettings(eventsSettings));

        EventSettingsDto eventSettingsDto = new EventSettingsDto();
        eventSettingsDto.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        eventSettingsDto.setTriggerUuids(List.of(UUID.fromString("3a1db3f5-f9eb-4fbf-92c9-c4c1499bfca8")));

        Assertions
                .assertThrows(NotFoundException.class, () -> settingService.updateEventSettings(eventSettingsDto),
                        "Updating non-existing trigger event settings should throw NotFoundException");
    }

    @Test
    void updateOAuth2ProviderSettings_duplicateIssuer_rejected() throws Exception {
        OAuth2ProviderSettingsUpdateDto first = createProviderUpdateDto();
        first.setIssuerUrl("https://shared-issuer.example.com");
        settingService.updateOAuth2ProviderSettings("provider-one", first);

        OAuth2ProviderSettingsUpdateDto second = createProviderUpdateDto();
        second.setIssuerUrl("https://shared-issuer.example.com");
        Assertions
                .assertThrows(ValidationException.class,
                        () -> settingService.updateOAuth2ProviderSettings("provider-two", second));
    }

    @Test
    void updateOAuth2ProviderSettings_sameProviderKeepsItsOwnIssuer() throws Exception {
        OAuth2ProviderSettingsUpdateDto dto = createProviderUpdateDto();
        dto.setIssuerUrl("https://unique-issuer.example.com");
        settingService.updateOAuth2ProviderSettings("provider-one", dto);
        Assertions.assertDoesNotThrow(() -> settingService.updateOAuth2ProviderSettings("provider-one", dto));
    }

    @Test
    void updateOAuth2ProviderSettings_changingIssuerIntoExistingOnes_rejected() throws Exception {
        OAuth2ProviderSettingsUpdateDto first = createProviderUpdateDto();
        first.setIssuerUrl("https://issuer-one.example.com");
        settingService.updateOAuth2ProviderSettings("provider-one", first);

        OAuth2ProviderSettingsUpdateDto second = createProviderUpdateDto();
        second.setIssuerUrl("https://issuer-two.example.com");
        settingService.updateOAuth2ProviderSettings("provider-two", second);

        second.setIssuerUrl("https://issuer-one.example.com");
        Assertions
                .assertThrows(ValidationException.class,
                        () -> settingService.updateOAuth2ProviderSettings("provider-two", second));
    }

    @Test
    void updateAuthenticationSettings_batchWithInternalDuplicateIssuer_rejected() throws Exception {
        OAuth2ProviderSettingsDto p1 = createProviderDto("provider-one");
        p1.setIssuerUrl("https://dup.example.com");
        OAuth2ProviderSettingsDto p2 = createProviderDto("provider-two");
        p2.setIssuerUrl("https://dup.example.com");
        AuthenticationSettingsUpdateDto update = new AuthenticationSettingsUpdateDto();
        update.setOAuth2Providers(List.of(p1, p2));
        Assertions.assertThrows(ValidationException.class, () -> settingService.updateAuthenticationSettings(update));
    }

    private static String encodedJwkSet() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic()).keyID("test-key").build();
        return Base64.getEncoder().encodeToString(new JWKSet(rsaKey).toString().getBytes(StandardCharsets.UTF_8));
    }

    private static OAuth2ProviderSettingsUpdateDto createProviderUpdateDto() throws Exception {
        OAuth2ProviderSettingsUpdateDto dto = new OAuth2ProviderSettingsUpdateDto();
        dto.setClientId("client");
        dto.setClientSecret("secret");
        dto.setAuthorizationUrl("http://auth.example.com");
        dto.setTokenUrl("http://token.example.com");
        dto.setJwkSet(encodedJwkSet());
        return dto;
    }

    private static OAuth2ProviderSettingsDto createProviderDto(String name) throws Exception {
        OAuth2ProviderSettingsDto dto = new OAuth2ProviderSettingsDto();
        dto.setName(name);
        dto.setClientId("client");
        dto.setClientSecret("secret");
        dto.setAuthorizationUrl("http://auth.example.com");
        dto.setTokenUrl("http://token.example.com");
        dto.setJwkSet(encodedJwkSet());
        return dto;
    }

}
