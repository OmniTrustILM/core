package com.otilm.core.integration.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.raprofile.AttributeSetMergeMode;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SettingsSectionCategory;
import com.otilm.core.certificate.request.DefaultRequestAttributeSet;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Setting;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.v2.ExtendedAttributeService;
import com.otilm.core.service.writer.RaProfileCertificateRequestAttributeWriter;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CsrGenerationAttributesITest extends BaseSpringBootTest {

    @Autowired
    private CertificateExternalService certificateService;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private RaProfileCertificateRequestAttributeWriter writer;
    @Autowired
    private SettingRepository settingRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;

    // Stub the connector dynamic-set fetch so no test needs a live authority/connector round-trip.
    @MockitoBean
    private ExtendedAttributeService extendedAttributeService;

    private static DataAttributeV3 def(String uuid, String name) {
        DataAttributeV3 attribute = new DataAttributeV3();
        attribute.setUuid(uuid);
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel(name);
        attribute.setProperties(properties);
        return attribute;
    }

    private RaProfile newEnabledRaProfile() {
        RaProfile raProfile = new RaProfile();
        raProfile.setName("rp-" + UUID.randomUUID());
        raProfile.setEnabled(true);
        return raProfileRepository.save(raProfile);
    }

    @Test
    void withProfileReturnsTheResolvedSetNotTheSeed() throws Exception {
        // given: an enabled profile with a stored STATIC_ONLY set; no authority -> no connector fetch
        RaProfile raProfile = newEnabledRaProfile();
        writer.saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("s1", "department"))),
                AttributeSetMergeMode.STATIC_ONLY, null);

        // when
        List<BaseAttribute> resolved = certificateService.getCsrGenerationAttributes(SecuredUUID.fromUUID(raProfile.getUuid()));

        // then: the configured set shapes the response, and the connector was never consulted
        assertThat(resolved).extracting(BaseAttribute::getName).containsExactly("department");
        verify(extendedAttributeService, never()).listIssueCertificateAttributes(any());
    }

    @Test
    void withProfileFallsBackToPlatformDefaultSetWhenNothingConfigured() throws Exception {
        // given: an enabled profile with no static set and no authority
        RaProfile raProfile = newEnabledRaProfile();

        // when
        List<BaseAttribute> resolved = certificateService.getCsrGenerationAttributes(SecuredUUID.fromUUID(raProfile.getUuid()));

        // then: the platform default set (built-in seed while unset)
        assertThat(resolved).extracting(BaseAttribute::getName)
                .containsExactlyElementsOf(DefaultRequestAttributeSet.seed().stream().map(BaseAttribute::getName).toList());
    }

    @Test
    void withProfileMergesPersistedConnectorSet() throws Exception {
        // given: an enabled profile with a persisted authority/connector reference
        Connector connector = new Connector();
        connector.setUrl("http://localhost");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setAuthorityInstanceUuid("1");
        authority.setConnector(connector);
        authority = authorityInstanceReferenceRepository.save(authority);

        RaProfile raProfile = new RaProfile();
        raProfile.setName("rp-" + UUID.randomUUID());
        raProfile.setEnabled(true);
        raProfile.setAuthorityInstanceReference(authority);
        raProfile.setAuthorityInstanceReferenceUuid(authority.getUuid());
        raProfile = raProfileRepository.save(raProfile);

        when(extendedAttributeService.listIssueCertificateAttributes(any()))
                .thenReturn(List.of(def("c1", "connector-attr")));

        // when
        List<BaseAttribute> resolved = certificateService.getCsrGenerationAttributes(SecuredUUID.fromUUID(raProfile.getUuid()));

        // then: the stubbed connector set is projected, and the connector attribute fetch was invoked
        assertThat(resolved).extracting(BaseAttribute::getName).containsExactly("connector-attr");
        verify(extendedAttributeService).listIssueCertificateAttributes(any());
    }

    @Test
    void withDisabledProfileThrowsNotFound() {
        // given
        RaProfile disabled = new RaProfile();
        disabled.setName("rp-disabled-" + UUID.randomUUID());
        disabled.setEnabled(false);
        SecuredUUID uuid = SecuredUUID.fromUUID(raProfileRepository.save(disabled).getUuid());

        // when / then
        assertThatThrownBy(() -> certificateService.getCsrGenerationAttributes(uuid))
                .isInstanceOf(NotFoundException.class);
    }

    @Test
    void withUnknownProfileThrowsNotFound() {
        // when / then
        assertThatThrownBy(() -> certificateService.getCsrGenerationAttributes(SecuredUUID.fromUUID(UUID.randomUUID())))
                .isInstanceOf(NotFoundException.class);
    }

    @Test
    void withProfileAndNothingProjectableAnywhereThrowsValidation() {
        // given: nothing configured on the profile and the default set edited down to an empty list
        RaProfile raProfile = newEnabledRaProfile();
        Setting defaultSet = new Setting();
        defaultSet.setSection(SettingsSection.PLATFORM);
        defaultSet.setCategory(SettingsSectionCategory.PLATFORM_CERTIFICATES.getCode());
        defaultSet.setName(DefaultRequestAttributeSet.SETTING_NAME);
        defaultSet.setValue(AttributeDefinitionUtils.serialize(List.of()));
        settingRepository.save(defaultSet);
        SecuredUUID uuid = SecuredUUID.fromUUID(raProfile.getUuid());

        // when / then: surfaced as ValidationException (HTTP 422) with an actionable message
        assertThatThrownBy(() -> certificateService.getCsrGenerationAttributes(uuid))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("No projectable request attribute definitions");
    }

    @Test
    void withoutProfileReturnsTheBuiltInSeedWhileDefaultSetIsUnset() {
        // when
        List<BaseAttribute> result = certificateService.getCsrGenerationAttributes();

        // then: same attribute names as the historical fixed seed — the unscoped contract is preserved
        assertThat(result).extracting(BaseAttribute::getName)
                .containsExactlyElementsOf(DefaultRequestAttributeSet.seed().stream().map(BaseAttribute::getName).toList());
    }

    @Test
    void withoutProfileHonoursTheEditedDefaultSet() {
        // given: an admin-edited platform default set
        Setting defaultSet = new Setting();
        defaultSet.setSection(SettingsSection.PLATFORM);
        defaultSet.setCategory(SettingsSectionCategory.PLATFORM_CERTIFICATES.getCode());
        defaultSet.setName(DefaultRequestAttributeSet.SETTING_NAME);
        defaultSet.setValue(AttributeDefinitionUtils.serialize(List.of(def("d1", "server-fqdn"))));
        settingRepository.save(defaultSet);

        // when
        List<BaseAttribute> result = certificateService.getCsrGenerationAttributes();

        // then
        assertThat(result).extracting(BaseAttribute::getName).containsExactly("server-fqdn");
    }
}
