package com.otilm.core.integration.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.InfoAttributeV2;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.FieldType;
import com.otilm.api.model.common.attribute.v3.mapping.ObjectType;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
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
import com.otilm.core.service.impl.RaProfileCertificateRequestAttributeServiceImpl;
import com.otilm.core.service.v2.ExtendedAttributeService;
import com.otilm.core.service.writer.RaProfileCertificateRequestAttributeWriter;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
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

    // Stub the connector dynamic-set fetch so resolution-order is exercised without a real authority/connector
    // round-trip.
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

        RdnMappedField field = new RdnMappedField();
        field.setFieldType(FieldType.RDN);
        field.setRdn("2.5.4.3");
        FieldMapping mapping = new FieldMapping();
        mapping.setObjectType(ObjectType.X509_CERTIFICATE);
        mapping.setFields(List.of(field));
        attribute.setFieldMapping(mapping);
        return attribute;
    }

    private RaProfile newRaProfile() {
        RaProfile raProfile = new RaProfile();
        raProfile.setName("rp-" + UUID.randomUUID());
        return raProfileRepository.save(raProfile);
    }

    private ListAppender<ILoggingEvent> captureResolutionLogs() {
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        resolutionLogger().addAppender(appender);
        return appender;
    }

    private static Logger resolutionLogger() {
        return (Logger) LoggerFactory.getLogger(RaProfileCertificateRequestAttributeServiceImpl.class);
    }

    private static List<String> messagesLoggedAt(ListAppender<ILoggingEvent> logged, Level level) {
        return logged.list
                .stream()
                .filter(event -> event.getLevel() == level)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    /** The logger is a process-wide singleton, so a capturing appender left on it would follow the next test. */
    @AfterEach
    void releaseTheResolutionLogger() {
        resolutionLogger().detachAndStopAllAppenders();
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
        writer
                .saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("u1", "server"))),
                        AttributeSetMergeMode.STATIC_ONLY, null);

        RaProfileValueSourceBinding binding = new RaProfileValueSourceBinding();
        binding.setRaProfileUuid(raProfile.getUuid());
        binding.setAttributeUuid("u1");
        binding.setValueSourceType(ValueSourceType.STATIC_LIST.name());
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
        assertThat(resolved)
                .extracting(BaseAttribute::getName)
                .containsExactlyElementsOf(defaultSet.stream().map(BaseAttribute::getName).toList());
    }

    @Test
    void mergeModeConnectorWinsAndStaticContributesRemainder() throws Exception {
        // given: a connector set with c1, and a static set with c1 (conflict) + s2 (static-only)
        RaProfile raProfile = newRaProfile();
        attachConnector(raProfile);
        when(extendedAttributeService.listCertificateRequestAttributes(any()))
                .thenReturn(List.of(def("c1", "connector-name")));
        writer
                .saveStaticSet(raProfile,
                        AttributeDefinitionUtils
                                .serialize(List.of(def("c1", "static-conflict"), def("s2", "static-only"))),
                        AttributeSetMergeMode.MERGE, null);

        // when
        List<BaseAttribute> resolved = service.resolveIssueAttributeSet(raProfile, AttributeSetMergeMode.MERGE);

        // then: connector wins the c1 conflict; static contributes only s2
        assertThat(resolved).extracting(BaseAttribute::getName).containsExactly("connector-name", "static-only");
    }

    @Test
    void connectorUuidSetButConnectorMissingSkipsConnectorSetGracefully() throws Exception {
        // given: the authority carries a connectorUuid, but its Connector is unresolved/deleted (getConnector() ==
        // null)
        RaProfile raProfile = newRaProfile();
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setConnectorUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);
        writer
                .saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("s1", "static-only"))),
                        AttributeSetMergeMode.MERGE, null);

        // when
        List<BaseAttribute> resolved = service.resolveIssueAttributeSet(raProfile, AttributeSetMergeMode.MERGE);

        // then: the connector fetch is skipped gracefully (no NotFoundException) and only the static set resolves
        verify(extendedAttributeService, never()).listCertificateRequestAttributes(any());
        assertThat(resolved).extracting(BaseAttribute::getName).containsExactly("static-only");
    }

    @Test
    void resolveUsesMergeModePersistedOnTheProfileWhenNotGivenExplicitly() throws Exception {
        // given: a stored static set whose persisted merge mode is STATIC_ONLY, plus a (would-be-winning) connector set
        RaProfile raProfile = newRaProfile();
        attachConnector(raProfile);
        when(extendedAttributeService.listCertificateRequestAttributes(any()))
                .thenReturn(List.of(def("c1", "connector-name")));
        writer
                .saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("s1", "static-only"))),
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
        writer
                .saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("s1", "department"))),
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
    void warnsWhenAMergeModeAdmitsTheConnectorButItSuppliesNothing() throws Exception {
        // given — CONNECTOR_ONLY on an authority whose connector serves no request schema (every v2 authority, and
        // any v3 connector answering 404). Resolution silently yields the platform default set, so the operator gets
        // neither the connector set they asked for nor their own static set; the log is the only trace.
        RaProfile raProfile = newRaProfile();
        attachConnector(raProfile);
        writer
                .saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("s1", "static-only"))),
                        AttributeSetMergeMode.CONNECTOR_ONLY, null);
        when(extendedAttributeService.listCertificateRequestAttributes(any())).thenReturn(List.of());
        ListAppender<ILoggingEvent> logged = captureResolutionLogs();

        // when
        service.resolveIssueAttributeSet(raProfile);

        // then
        assertThat(messagesLoggedAt(logged, Level.WARN))
                .anySatisfy(message -> assertThat(message)
                        .contains(raProfile.getName())
                        .contains(AttributeSetMergeMode.CONNECTOR_ONLY.getCode()));
    }

    @Test
    void mergeWithAStaticSetLogsNoWarningWhenTheConnectorServesNoSchema() throws Exception {
        // Every v2 authority serves no request schema by contract, so this is the steady state for a MERGE profile
        // with a static set — and resolution is correct: the static set is what 2.19.x would have resolved. Warning
        // here would fire per certificate request, per EST /csrattrs and per ACME/SCEP/CMP request, forever.
        RaProfile raProfile = newRaProfile();
        attachConnector(raProfile);
        writer
                .saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("s1", "static-only"))),
                        AttributeSetMergeMode.MERGE, null);
        when(extendedAttributeService.listCertificateRequestAttributes(any())).thenReturn(List.of());
        ListAppender<ILoggingEvent> logged = captureResolutionLogs();

        List<BaseAttribute> resolved = service.resolveIssueAttributeSet(raProfile);

        assertThat(resolved).extracting(BaseAttribute::getName).containsExactly("static-only");
        assertThat(messagesLoggedAt(logged, Level.WARN)).isEmpty();
    }

    @Test
    void staticOnlyResolutionLogsNoWarning() {
        // The common path must stay quiet: STATIC_ONLY never asks the connector for anything.
        RaProfile raProfile = newRaProfile();
        attachConnector(raProfile);
        writer
                .saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("s1", "static-only"))),
                        AttributeSetMergeMode.STATIC_ONLY, null);
        ListAppender<ILoggingEvent> logged = captureResolutionLogs();

        assertThatCode(() -> service.resolveIssueAttributeSet(raProfile)).doesNotThrowAnyException();

        assertThat(messagesLoggedAt(logged, Level.WARN)).isEmpty();
    }

    @Test
    void valueSourceBindingBindsToAConnectorSuppliedDefinition() throws Exception {
        // given — the connector supplies the definition, and the profile binds a value source to it by UUID
        RaProfile raProfile = newRaProfile();
        attachConnector(raProfile);
        when(extendedAttributeService.listCertificateRequestAttributes(any()))
                .thenReturn(List.of(def("c1", "connector-cn")));
        writer
                .saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of()),
                        AttributeSetMergeMode.CONNECTOR_ONLY, null);
        RaProfileValueSourceBinding binding = new RaProfileValueSourceBinding();
        binding.setRaProfileUuid(raProfile.getUuid());
        binding.setAttributeUuid("c1");
        binding.setValueSourceType(ValueSourceType.STATIC_LIST.name());
        writer.replaceValueSourceBindings(raProfile.getUuid(), List.of(binding));

        // when
        List<BaseAttribute> resolved = service.resolveIssueAttributeSet(raProfile);

        // then — the binding rides on the connector definition, which is the point of binding by reference
        assertThat(resolved).hasSize(1);
        DataAttributeV3 bound = (DataAttributeV3) resolved.get(0);
        assertThat(bound.getName()).isEqualTo("connector-cn");
        assertThat(bound.getValueSource()).isNotNull();
        assertThat(bound.getValueSource().getKind()).isEqualTo(ValueSourceType.STATIC_LIST);
    }

    @Test
    void buildPathProjectsConnectorSuppliedDefinitionsUnderAMergeMode() throws Exception {
        // given — a profile whose merge mode admits the connector set, and a connector definition carrying a mapping
        RaProfile raProfile = newRaProfile();
        attachConnector(raProfile);
        when(extendedAttributeService.listCertificateRequestAttributes(any()))
                .thenReturn(List.of(def("c1", "connector-cn")));
        writer
                .saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("s1", "static-only"))),
                        AttributeSetMergeMode.MERGE, null);

        // when — resolving through the bean that feeds the structured requestContent projection
        List<DataAttributeV3> resolved = issuanceDefinitionResolver.resolve(raProfile);

        // then — the connector definition is what the projection will map onto the wire; a merge-mode change is
        // therefore a change to the structured content a CERTIFICATE_REQUEST_STRUCTURED connector receives
        assertThat(resolved).extracting(DataAttributeV3::getName).containsExactly("connector-cn", "static-only");
        assertThat(resolved.get(0).getFieldMapping()).isNotNull();
    }

    @Test
    void buildPathResolverFallsBackToDefaultSet_whenConnectorSuppliesOnlyNonV3Attributes() throws Exception {
        // given — an unconfigured profile whose connector request schema carries only non-v3 attributes
        RaProfile raProfile = newRaProfile();
        attachConnector(raProfile);
        InfoAttributeV2 legacy = new InfoAttributeV2();
        legacy.setName("legacy-info");
        when(extendedAttributeService.listCertificateRequestAttributes(any())).thenReturn(List.of(legacy));

        // when — resolving through the bean the issue/register projection uses
        List<DataAttributeV3> resolved = issuanceDefinitionResolver.resolve(raProfile);

        // then — the platform default set shapes the projection instead of resolving empty
        List<String> defaultV3Names = service
                .getDefaultSet()
                .stream()
                .filter(DataAttributeV3.class::isInstance)
                .map(BaseAttribute::getName)
                .toList();
        assertThat(defaultV3Names).isNotEmpty();
        assertThat(resolved).extracting(DataAttributeV3::getName).containsExactlyElementsOf(defaultV3Names);
    }

    @Test
    void buildPathFallbackAppliesValueSourceBindings_toDefaultSetDefinitions() throws Exception {
        // given — a non-v3 connector schema forces the default-set fallback, and the profile binds a value
        // source to one of the default-set definitions
        RaProfile raProfile = newRaProfile();
        attachConnector(raProfile);
        InfoAttributeV2 legacy = new InfoAttributeV2();
        legacy.setName("legacy-info");
        when(extendedAttributeService.listCertificateRequestAttributes(any())).thenReturn(List.of(legacy));

        String boundUuid = service.getDefaultSet().get(0).getUuid();
        RaProfileValueSourceBinding binding = new RaProfileValueSourceBinding();
        binding.setRaProfileUuid(raProfile.getUuid());
        binding.setAttributeUuid(boundUuid);
        binding.setValueSourceType(ValueSourceType.STATIC_LIST.name());
        writer.replaceValueSourceBindings(raProfile.getUuid(), List.of(binding));

        // when — resolving through the bean the issue/register projection uses
        List<DataAttributeV3> resolved = issuanceDefinitionResolver.resolve(raProfile);

        // then — the fallback definitions carry the profile's value-source binding, same as the
        // service-level default fallback does
        DataAttributeV3 bound = resolved
                .stream()
                .filter(definition -> boundUuid.equals(definition.getUuid()))
                .findFirst()
                .orElseThrow();
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
        String boundUuid = UUID.randomUUID().toString();
        RaProfileCertificateRequestAttributesUpdateDto request = new RaProfileCertificateRequestAttributesUpdateDto();
        request.setRequestAttributes(List.of(def(boundUuid, "server")));
        request.setMergeMode(AttributeSetMergeMode.CONNECTOR_ONLY);
        request.setExternalCsrValidationStrict(Boolean.TRUE);
        ValueSourceBindingDto bindingDto = new ValueSourceBindingDto();
        bindingDto.setAttributeUuid(boundUuid);
        bindingDto.setValueSourceType(ValueSourceType.STATIC_LIST);
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
        assertThat(stored.getValueSourceBindings().get(0).getParams())
                .extracting(SourceParam::getAttributeName)
                .containsExactly("datacenter");
    }

    @ParameterizedTest
    @EnumSource(AttributeSetMergeMode.class)
    void updateConfigurationStoresEveryMergeMode(AttributeSetMergeMode mode) {
        RaProfile raProfile = newRaProfile();
        RaProfileCertificateRequestAttributesUpdateDto request = new RaProfileCertificateRequestAttributesUpdateDto();
        request.setRequestAttributes(List.of(def(UUID.randomUUID().toString(), "server")));
        request.setMergeMode(mode);

        service.updateConfiguration(raProfile, request);

        assertThat(service.getConfiguration(raProfile).getMergeMode()).isEqualTo(mode);
    }

    @Test
    void omittedMergeModeStoredAsStaticOnly() {
        RaProfile raProfile = newRaProfile();
        RaProfileCertificateRequestAttributesUpdateDto request = new RaProfileCertificateRequestAttributesUpdateDto();
        request.setRequestAttributes(List.of(def(UUID.randomUUID().toString(), "server")));
        service.updateConfiguration(raProfile, request);
        assertEquals(AttributeSetMergeMode.STATIC_ONLY, service.getConfiguration(raProfile).getMergeMode());
    }

    @Test
    void updateConfigurationLeavesBindingsAloneWhenTheFieldIsAbsent() {
        // given — a profile with a stored binding
        RaProfile raProfile = newRaProfile();
        RaProfileCertificateRequestAttributesUpdateDto withBinding = new RaProfileCertificateRequestAttributesUpdateDto();
        withBinding.setValueSourceBindings(List.of(binding("kept")));
        service.updateConfiguration(raProfile, withBinding);

        // when — an unrelated edit that does not mention bindings at all
        RaProfileCertificateRequestAttributesUpdateDto staticSetOnly = new RaProfileCertificateRequestAttributesUpdateDto();
        staticSetOnly.setRequestAttributes(List.of(def(UUID.randomUUID().toString(), "server")));
        staticSetOnly.setValueSourceBindings(null);
        service.updateConfiguration(raProfile, staticSetOnly);

        // then — the binding survives; the static set was still written
        RaProfileCertificateRequestAttributesDto stored = service.getConfiguration(raProfile);
        assertThat(stored.getValueSourceBindings())
                .extracting(ValueSourceBindingDto::getAttributeName)
                .containsExactly("kept");
        assertThat(stored.getRequestAttributes()).extracting(BaseAttribute::getName).containsExactly("server");
    }

    @Test
    void updateConfigurationClearsBindingsWhenTheFieldIsAnEmptyList() {
        RaProfile raProfile = newRaProfile();
        RaProfileCertificateRequestAttributesUpdateDto withBinding = new RaProfileCertificateRequestAttributesUpdateDto();
        withBinding.setValueSourceBindings(List.of(binding("dropped")));
        service.updateConfiguration(raProfile, withBinding);

        RaProfileCertificateRequestAttributesUpdateDto cleared = new RaProfileCertificateRequestAttributesUpdateDto();
        cleared.setValueSourceBindings(List.of());
        service.updateConfiguration(raProfile, cleared);

        assertThat(service.getConfiguration(raProfile).getValueSourceBindings()).isEmpty();
    }

    @Test
    void updateConfigurationReplacesValueSourceBindings() {
        // given — a profile whose bindings are already stored
        RaProfile raProfile = newRaProfile();
        RaProfileCertificateRequestAttributesUpdateDto first = new RaProfileCertificateRequestAttributesUpdateDto();
        first.setValueSourceBindings(List.of(binding("first")));
        service.updateConfiguration(raProfile, first);

        // when — a second update carries a different binding
        RaProfileCertificateRequestAttributesUpdateDto second = new RaProfileCertificateRequestAttributesUpdateDto();
        second.setValueSourceBindings(List.of(binding("second")));
        service.updateConfiguration(raProfile, second);

        // then — bindings are replaced, not accumulated
        assertThat(service.getConfiguration(raProfile).getValueSourceBindings())
                .extracting(ValueSourceBindingDto::getAttributeName)
                .containsExactly("second");
    }

    @Test
    void updateConfigurationRejectsABindingWithoutAValueSourceType() {
        // The HTTP path is covered by @Valid + @NotNull, but this is a public service method and the rejection that
        // used to short-circuit every non-empty binding list is gone.
        RaProfile raProfile = newRaProfile();
        ValueSourceBindingDto incomplete = new ValueSourceBindingDto();
        incomplete.setAttributeName("server");
        RaProfileCertificateRequestAttributesUpdateDto request = new RaProfileCertificateRequestAttributesUpdateDto();
        request.setValueSourceBindings(List.of(incomplete));

        assertThatThrownBy(() -> service.updateConfiguration(raProfile, request))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("value source");
    }

    private static ValueSourceBindingDto binding(String attributeName) {
        ValueSourceBindingDto binding = new ValueSourceBindingDto();
        binding.setAttributeName(attributeName);
        binding.setValueSourceType(ValueSourceType.CONNECTOR_CALLBACK);
        return binding;
    }

    @Test
    void getConfigurationResolvesStoredNullMergeModeToStaticOnly() {
        // given: a stored set whose merge mode was left null
        RaProfile raProfile = newRaProfile();
        writer.saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(def("u1", "server"))), null, null);

        // when
        RaProfileCertificateRequestAttributesDto stored = service.getConfiguration(raProfile);

        // then: the read view exposes the effective default rather than null
        assertThat(stored.getMergeMode()).isEqualTo(AttributeSetMergeMode.STATIC_ONLY);
    }

    @Test
    void getConfigurationReturnsStaticOnlyWhenNoSetStored() {
        // given: an RA Profile with no request-attribute set at all
        RaProfile raProfile = newRaProfile();

        // when
        RaProfileCertificateRequestAttributesDto stored = service.getConfiguration(raProfile);

        // then: the read view exposes the effective default rather than null
        assertThat(stored.getMergeMode()).isEqualTo(AttributeSetMergeMode.STATIC_ONLY);
    }

    @Test
    void updateConfigurationRejectsReadOnlyDefinitionWithoutDefault() {
        RaProfile raProfile = newRaProfile();
        DataAttributeV3 readOnlyNoDefault = def("00000000-0000-0000-0000-0000000000aa", "locked-field");
        readOnlyNoDefault.getProperties().setReadOnly(true);

        RaProfileCertificateRequestAttributesUpdateDto request = new RaProfileCertificateRequestAttributesUpdateDto();
        request.setRequestAttributes(List.of(readOnlyNoDefault));

        assertThatThrownBy(() -> service.updateConfiguration(raProfile, request))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Read only attribute must define its content");
    }
}
