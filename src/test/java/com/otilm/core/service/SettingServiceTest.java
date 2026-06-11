package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.settings.*;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsUpdateDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsResponseDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsUpdateDto;
import com.otilm.core.dao.entity.Setting;
import com.otilm.core.dao.entity.workflows.Trigger;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.dao.repository.workflows.TriggerRepository;
import com.otilm.core.service.impl.SettingServiceImpl;
import com.otilm.core.util.BaseSpringBootTest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.text.ParseException;
import java.util.*;

class SettingServiceTest extends BaseSpringBootTest {

    private static final String TEST_TRIGGER_NAME = "testTriggerName";
    private static final String TEST_TRIGGER_UUID = "3a1db3f5-f9eb-4fbf-92c9-c4c1499bfca7";

    @Autowired
    private SettingService settingService;

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

        RSAKey rsaJwk = new RSAKeyGenerator(2048)
                .generate();

        ECKey ecJwk = new ECKeyGenerator(Curve.P_256)
                .generate();

        OctetSequenceKey aesJwk = new OctetSequenceKeyGenerator(128)
                .generate();

        OctetKeyPair octetKeyPairJwk = OctetKeyPair.parse("{\"kty\":\"OKP\",\"d\":\"y85lxYiKx57Dwgs2rH1b0yTVxeLJWmpt48WfivLXBbU\",\"crv\":\"Ed25519\",\"x\":\"tO6vOgx0YOVuWdevkbYzaihxcCLx8DfqRs2nvs3CBxU\", \"kid\": \"123\"}");

        JWKSet jwkSet = new JWKSet(List.of(rsaJwk, ecJwk, aesJwk, octetKeyPairJwk));

        OAuth2ProviderSettingsUpdateDto providerSettings = new OAuth2ProviderSettingsUpdateDto();
        ObjectMapper objectMapper = new ObjectMapper();

        providerSettings.setJwkSet(Base64.getEncoder().encodeToString(objectMapper.writeValueAsString(jwkSet.toJSONObject(false)).getBytes()));
        Setting oauth2Setting = new Setting();
        oauth2Setting.setValue(objectMapper.writeValueAsString(providerSettings));
        oauth2Setting.setName("name");
        oauth2Setting.setSection(SettingsSection.AUTHENTICATION);
        oauth2Setting.setCategory(SettingsSectionCategory.OAUTH2_PROVIDER.getCode());
        settingRepository.save(oauth2Setting);

        OAuth2ProviderSettingsResponseDto oAuth2ProvidersSettingsUpdateDto = settingService.getOAuth2ProviderSettings("name", false);
        Assertions.assertEquals(Base64.getEncoder().encodeToString(rsaJwk.toPublicKey().getEncoded()), oAuth2ProvidersSettingsUpdateDto.getJwkSetKeys().stream().filter(jwk -> jwk.getKeyType().equals("RSA")).findFirst().get().getPublicKey());
        Assertions.assertEquals(Base64.getEncoder().encodeToString(ecJwk.toPublicKey().getEncoded()), oAuth2ProvidersSettingsUpdateDto.getJwkSetKeys().stream().filter(jwk -> jwk.getKeyType().equals("EC")).findFirst().get().getPublicKey());
        Assertions.assertEquals(Base64.getEncoder().encodeToString(aesJwk.toByteArray()), oAuth2ProvidersSettingsUpdateDto.getJwkSetKeys().stream().filter(jwk -> jwk.getKeyType().equals("oct")).findFirst().get().getPublicKey());
        Assertions.assertEquals(Base64.getEncoder().encodeToString(octetKeyPairJwk.getDecodedX()), oAuth2ProvidersSettingsUpdateDto.getJwkSetKeys().stream().filter(jwk -> jwk.getKeyType().equals("OKP")).findFirst().get().getPublicKey());
    }

    @Test
    void testUpdateAuthenticationSettings() {
        AuthenticationSettingsUpdateDto authenticationSettingsUpdateDto = new AuthenticationSettingsUpdateDto();
        authenticationSettingsUpdateDto.setDisableLocalhostUser(true);
        authenticationSettingsUpdateDto.setOAuth2Providers(List.of());

        Assertions.assertDoesNotThrow(() -> settingService.updateAuthenticationSettings(authenticationSettingsUpdateDto), "Updating authentication settings should not throw any exception");
    }

    @Test
    void testUpdateEventSettings() {
        EventsSettingsDto eventSettings = settingService.getEventsSettings();
        Assertions.assertNotNull(eventSettings);

        Assertions.assertDoesNotThrow(() -> settingService.updateEventsSettings(eventSettings), "Updating event settings should not throw any exception");

        EventSettingsDto eventSettingsDto = new EventSettingsDto();
        eventSettingsDto.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        eventSettingsDto.setTriggerUuids(List.of(UUID.fromString(TEST_TRIGGER_UUID)));

        Assertions.assertDoesNotThrow(() -> settingService.updateEventSettings(eventSettingsDto), "Updating event settings should not throw any exception");
    }

    @Test
    void testUpdateNonExistingTriggerEventSettings() {
        EventsSettingsDto eventsSettings = new EventsSettingsDto();
        Map<ResourceEvent, List<UUID>> eventsMapping = new EnumMap<>(ResourceEvent.class);
        eventsMapping.put(ResourceEvent.CERTIFICATE_DISCOVERED, List.of(UUID.fromString("3a1db3f5-f9eb-4fbf-92c9-c4c1499bfca8")));
        eventsSettings.setEventsMapping(eventsMapping);

        Assertions.assertThrows(NotFoundException.class, () -> settingService.updateEventsSettings(eventsSettings));

        EventSettingsDto eventSettingsDto = new EventSettingsDto();
        eventSettingsDto.setEvent(ResourceEvent.CERTIFICATE_DISCOVERED);
        eventSettingsDto.setTriggerUuids(List.of(UUID.fromString("3a1db3f5-f9eb-4fbf-92c9-c4c1499bfca8")));

        Assertions.assertThrows(NotFoundException.class, () -> settingService.updateEventSettings(eventSettingsDto), "Updating non-existing trigger event settings should throw NotFoundException");
    }

}
