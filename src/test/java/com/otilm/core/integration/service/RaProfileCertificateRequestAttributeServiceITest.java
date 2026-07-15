package com.otilm.core.integration.service;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.InfoAttributeV2;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.mapping.SourceParam;
import com.otilm.api.model.common.attribute.v3.mapping.ValueSourceType;
import com.otilm.api.model.core.raprofile.AttributeSetMergeMode;
import com.otilm.api.model.core.raprofile.RaProfileCertificateRequestAttributesDto;
import com.otilm.api.model.core.raprofile.RaProfileCertificateRequestAttributesUpdateDto;
import com.otilm.api.model.core.raprofile.ValueSourceBindingDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SettingsSectionCategory;
import com.otilm.core.certificate.request.DefaultRequestAttributeSet;
import com.otilm.core.certificate.request.IssuanceDefinitionResolver;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RaProfileValueSourceBinding;
import com.otilm.core.dao.entity.Setting;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.service.RaProfileCertificateRequestAttributeService;
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

class RaProfileCertificateRequestAttributeServiceITest extends BaseSpringBootTest {

    @Autowired
    private RaProfileCertificateRequestAttributeService service;
    @Autowired
    private RaProfileCertificateRequestAttributeWriter writer;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private SettingRepository settingRepository;
    @Autowired
    private IssuanceDefinitionResolver issuanceDefinitionResolver;

    // Stub the connector dynamic-set fetch so resolution-order is exercised without a real authority/connector round-trip.
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

    private RaProfile newRaProfile() {
        RaProfile raProfile = new RaProfile();
        raProfile.setName("rp-" + UUID.randomUUID());
        return raProfileRepository.save(raProfile);
    }

    private void attachConnector(RaProfile raProfile) {
        Connector connector = new Connector();
        connector.setUuid(UUID.randomUUID());
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setConnector(connector);
        raProfile.setAuthorityInstanceReference(authority);
    }

    @Test
    void staticOnlyResolvesStoredSetWithValueSourceBindingApplied() throws Exception {
        // given: a stored static set and a value-source binding for it; no authority -> connector set is empty
        RaProfile raProfile = newRaProfile();
        writer.saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("u1", "server"))),
                AttributeSetMergeMode.STATIC_ONLY, null);

        RaProfileValueSourceBinding binding = new RaProfileValueSourceBinding();
        binding.setRaProfileUuid(raProfile.getUuid());
        binding.setAttributeUuid("u1");
        binding.setValueSourceType(ValueSourceType.STATIC_LIST.name());
        binding.setCollectionRef("cmdb.servers");
        writer.replaceValueSourceBindings(raProfile.getUuid(), List.of(binding));

        // when
        List<BaseAttribute> resolved = service.resolveIssueAttributeSet(raProfile, AttributeSetMergeMode.STATIC_ONLY);

        // then
        assertThat(resolved).hasSize(1);
        DataAttributeV3 out = (DataAttributeV3) resolved.get(0);
        assertThat(out.getName()).isEqualTo("server");
        assertThat(out.getValueSource()).isNotNull();
        assertThat(out.getValueSource().getKind()).isEqualTo(ValueSourceType.STATIC_LIST);
    }

    @Test
    void emptyStaticAndConnectorFallsBackToDefaultSet() throws Exception {
        // given: STATIC_ONLY with no stored static set and no authority -> nothing resolves from set/connector
        RaProfile raProfile = newRaProfile();

        // when
        List<BaseAttribute> resolved = service.resolveIssueAttributeSet(raProfile, AttributeSetMergeMode.STATIC_ONLY);

        // then: falls back to the editable platform default set (seeded from CsrAttributes) — assert it is
        // actually the default set, not merely non-empty (which any of the three sources would satisfy).
        List<BaseAttribute> defaultSet = service.getDefaultSet();
        assertThat(defaultSet).isNotEmpty();
        assertThat(resolved).extracting(BaseAttribute::getName)
                .containsExactlyElementsOf(defaultSet.stream().map(BaseAttribute::getName).toList());
    }

    @Test
    void mergeModeConnectorWinsAndStaticContributesRemainder() throws Exception {
        // given: a connector set with c1, and a static set with c1 (conflict) + s2 (static-only)
        RaProfile raProfile = newRaProfile();
        attachConnector(raProfile);
        when(extendedAttributeService.listIssueCertificateAttributes(any()))
                .thenReturn(List.of(def("c1", "connector-name")));
        writer.saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("c1", "static-conflict"), def("s2", "static-only"))),
                AttributeSetMergeMode.MERGE, null);

        // when
        List<BaseAttribute> resolved = service.resolveIssueAttributeSet(raProfile, AttributeSetMergeMode.MERGE);

        // then: connector wins the c1 conflict; static contributes only s2
        assertThat(resolved).extracting(BaseAttribute::getName).containsExactly("connector-name", "static-only");
    }

    @Test
    void connectorUuidSetButConnectorMissingSkipsConnectorSetGracefully() throws Exception {
        // given: the authority carries a connectorUuid, but its Connector is unresolved/deleted (getConnector() == null)
        RaProfile raProfile = newRaProfile();
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setConnectorUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);
        writer.saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("s1", "static-only"))),
                AttributeSetMergeMode.MERGE, null);

        // when
        List<BaseAttribute> resolved = service.resolveIssueAttributeSet(raProfile, AttributeSetMergeMode.MERGE);

        // then: the connector fetch is skipped gracefully (no NotFoundException) and only the static set resolves
        verify(extendedAttributeService, never()).listIssueCertificateAttributes(any());
        assertThat(resolved).extracting(BaseAttribute::getName).containsExactly("static-only");
    }

    @Test
    void resolveUsesMergeModePersistedOnTheProfileWhenNotGivenExplicitly() throws Exception {
        // given: a stored static set whose persisted merge mode is STATIC_ONLY, plus a (would-be-winning) connector set
        RaProfile raProfile = newRaProfile();
        attachConnector(raProfile);
        when(extendedAttributeService.listIssueCertificateAttributes(any()))
                .thenReturn(List.of(def("c1", "connector-name")));
        writer.saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("s1", "static-only"))),
                AttributeSetMergeMode.STATIC_ONLY, null);

        // when: the no-mode overload reads the persisted STATIC_ONLY mode
        List<BaseAttribute> resolved = service.resolveIssueAttributeSet(raProfile);

        // then: connector set is ignored
        assertThat(resolved).extracting(BaseAttribute::getName).containsExactly("static-only");
    }

    @Test
    void buildPathResolverHonoursStoredStaticSet() throws Exception {
        // given — an RA-Profile static set, no authority connector
        RaProfile raProfile = newRaProfile();
        writer.saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("s1", "department"))),
                AttributeSetMergeMode.STATIC_ONLY, null);

        // when — resolving through the bean the issue/register projection uses
        List<DataAttributeV3> resolved = issuanceDefinitionResolver.resolve(raProfile);

        // then — the configured set shapes the projection definitions, not the hardcoded seed
        assertThat(resolved).extracting(DataAttributeV3::getName).containsExactly("department");
    }

    @Test
    void buildPathResolverFallsBackToEditedDefaultSet() throws Exception {
        // given — nothing configured on the profile, but the platform default set has been edited
        RaProfile raProfile = newRaProfile();
        Setting defaultSet = new Setting();
        defaultSet.setSection(SettingsSection.PLATFORM);
        defaultSet.setCategory(SettingsSectionCategory.PLATFORM_CERTIFICATES.getCode());
        defaultSet.setName(DefaultRequestAttributeSet.SETTING_NAME);
        defaultSet.setValue(AttributeDefinitionUtils.serialize(List.of(def("d1", "server-fqdn"))));
        settingRepository.save(defaultSet);

        // when
        List<DataAttributeV3> resolved = issuanceDefinitionResolver.resolve(raProfile);

        // then — the edited default set is projected, not the built-in seed
        assertThat(resolved).extracting(DataAttributeV3::getName).containsExactly("server-fqdn");
    }

    @Test
    void buildPathResolverFallsBackToDefaultSet_whenConnectorSuppliesOnlyNonV3Attributes() throws Exception {
        // given — an unconfigured profile whose v2 authority connector returns only non-v3 attributes
        RaProfile raProfile = newRaProfile();
        attachConnector(raProfile);
        InfoAttributeV2 legacy = new InfoAttributeV2();
        legacy.setName("legacy-info");
        when(extendedAttributeService.listIssueCertificateAttributes(any())).thenReturn(List.of(legacy));

        // when — resolving through the bean the issue/register projection uses
        List<DataAttributeV3> resolved = issuanceDefinitionResolver.resolve(raProfile);

        // then — the platform default set shapes the projection instead of resolving empty
        List<String> defaultV3Names = service.getDefaultSet().stream()
                .filter(DataAttributeV3.class::isInstance)
                .map(BaseAttribute::getName)
                .toList();
        assertThat(defaultV3Names).isNotEmpty();
        assertThat(resolved).extracting(DataAttributeV3::getName).containsExactlyElementsOf(defaultV3Names);
    }

    @Test
    void buildPathFallbackAppliesValueSourceBindings_toDefaultSetDefinitions() throws Exception {
        // given — a v2-only connector forces the default-set fallback, and the profile binds a value
        // source to one of the default-set definitions
        RaProfile raProfile = newRaProfile();
        attachConnector(raProfile);
        InfoAttributeV2 legacy = new InfoAttributeV2();
        legacy.setName("legacy-info");
        when(extendedAttributeService.listIssueCertificateAttributes(any())).thenReturn(List.of(legacy));

        String boundUuid = service.getDefaultSet().get(0).getUuid();
        RaProfileValueSourceBinding binding = new RaProfileValueSourceBinding();
        binding.setRaProfileUuid(raProfile.getUuid());
        binding.setAttributeUuid(boundUuid);
        binding.setValueSourceType(ValueSourceType.STATIC_LIST.name());
        binding.setCollectionRef("cmdb.servers");
        writer.replaceValueSourceBindings(raProfile.getUuid(), List.of(binding));

        // when — resolving through the bean the issue/register projection uses
        List<DataAttributeV3> resolved = issuanceDefinitionResolver.resolve(raProfile);

        // then — the fallback definitions carry the profile's value-source binding, same as the
        // service-level default fallback does
        DataAttributeV3 bound = resolved.stream()
                .filter(definition -> boundUuid.equals(definition.getUuid()))
                .findFirst().orElseThrow();
        assertThat(bound.getValueSource()).isNotNull();
        assertThat(bound.getValueSource().getKind()).isEqualTo(ValueSourceType.STATIC_LIST);
    }

    @Test
    void updateConfigurationRejectsDefinitionMissingProperties() {
        // given: a v3 definition with no properties
        RaProfile raProfile = newRaProfile();
        DataAttributeV3 invalid = new DataAttributeV3();
        invalid.setUuid("bad");
        invalid.setName("bad");
        invalid.setContentType(AttributeContentType.STRING);
        RaProfileCertificateRequestAttributesUpdateDto request = new RaProfileCertificateRequestAttributesUpdateDto();
        request.setRequestAttributes(List.of(invalid));

        // then
        assertThatThrownBy(() -> service.updateConfiguration(raProfile, request))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    void updateConfigurationRoundTripsThroughGetConfiguration() {
        // given
        RaProfile raProfile = newRaProfile();
        RaProfileCertificateRequestAttributesUpdateDto request = new RaProfileCertificateRequestAttributesUpdateDto();
        request.setRequestAttributes(List.of(def("u1", "server")));
        request.setMergeMode(AttributeSetMergeMode.CONNECTOR_ONLY);
        request.setExternalCsrValidationStrict(Boolean.TRUE);
        ValueSourceBindingDto bindingDto = new ValueSourceBindingDto();
        bindingDto.setAttributeUuid("u1");
        bindingDto.setValueSourceType(ValueSourceType.STATIC_LIST);
        bindingDto.setCollectionRef("cmdb.servers");
        SourceParam param = new SourceParam();
        param.setAttributeName("datacenter");
        bindingDto.setParams(List.of(param));
        request.setValueSourceBindings(List.of(bindingDto));

        // when
        service.updateConfiguration(raProfile, request);
        RaProfileCertificateRequestAttributesDto stored = service.getConfiguration(raProfile);

        // then
        assertThat(stored.getRequestAttributes()).extracting(BaseAttribute::getName).containsExactly("server");
        assertThat(stored.getMergeMode()).isEqualTo(AttributeSetMergeMode.CONNECTOR_ONLY);
        assertThat(stored.getExternalCsrValidationStrict()).isTrue();
        assertThat(stored.getValueSourceBindings()).hasSize(1);
        assertThat(stored.getValueSourceBindings().get(0).getValueSourceType()).isEqualTo(ValueSourceType.STATIC_LIST);
        assertThat(stored.getValueSourceBindings().get(0).getCollectionRef()).isEqualTo("cmdb.servers");
        assertThat(stored.getValueSourceBindings().get(0).getParams()).extracting(p -> p.getAttributeName()).containsExactly("datacenter");
    }

    @Test
    void getConfigurationResolvesStoredNullMergeModeToMerge() {
        // given: a stored set whose merge mode was left null
        RaProfile raProfile = newRaProfile();
        writer.saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("u1", "server"))), null, null);

        // when
        RaProfileCertificateRequestAttributesDto stored = service.getConfiguration(raProfile);

        // then: the read view exposes the effective default rather than null
        assertThat(stored.getMergeMode()).isEqualTo(AttributeSetMergeMode.MERGE);
    }

    @Test
    void getConfigurationReturnsMergeWhenNoSetStored() {
        // given: an RA Profile with no request-attribute set at all
        RaProfile raProfile = newRaProfile();

        // when
        RaProfileCertificateRequestAttributesDto stored = service.getConfiguration(raProfile);

        // then: merge mode is still the effective default, never null
        assertThat(stored.getMergeMode()).isEqualTo(AttributeSetMergeMode.MERGE);
    }
}
