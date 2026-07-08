package com.otilm.core.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
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
import com.otilm.core.certificate.request.RequestAttributeSetResolver;
import com.otilm.core.certificate.request.RequestAttributeSetResolver.ValueSourceBindingSpec;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RaProfileCertificateRequestAttribute;
import com.otilm.core.dao.entity.RaProfileValueSourceBinding;
import com.otilm.core.dao.entity.Setting;
import com.otilm.core.dao.repository.RaProfileCertificateRequestAttributeRepository;
import com.otilm.core.dao.repository.RaProfileValueSourceBindingRepository;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.service.RaProfileCertificateRequestAttributeService;
import com.otilm.core.service.v2.ExtendedAttributeService;
import com.otilm.core.service.writer.RaProfileCertificateRequestAttributeWriter;
import com.otilm.core.util.AttributeDefinitionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
public class RaProfileCertificateRequestAttributeServiceImpl implements RaProfileCertificateRequestAttributeService {

    private final RaProfileCertificateRequestAttributeRepository requestAttributeRepository;
    private final RaProfileValueSourceBindingRepository valueSourceBindingRepository;
    private final RaProfileCertificateRequestAttributeWriter writer;
    private final ExtendedAttributeService extendedAttributeService;
    private final SettingRepository settingRepository;
    private final ObjectMapper objectMapper;

    @Autowired
    public RaProfileCertificateRequestAttributeServiceImpl(RaProfileCertificateRequestAttributeRepository requestAttributeRepository,
                                                           RaProfileValueSourceBindingRepository valueSourceBindingRepository,
                                                           RaProfileCertificateRequestAttributeWriter writer,
                                                           ExtendedAttributeService extendedAttributeService,
                                                           SettingRepository settingRepository,
                                                           ObjectMapper objectMapper) {
        this.requestAttributeRepository = requestAttributeRepository;
        this.valueSourceBindingRepository = valueSourceBindingRepository;
        this.writer = writer;
        this.extendedAttributeService = extendedAttributeService;
        this.settingRepository = settingRepository;
        this.objectMapper = objectMapper;
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<BaseAttribute> resolveIssueAttributeSet(RaProfile raProfile, AttributeSetMergeMode mode)
            throws ConnectorException, NotFoundException {
        return resolve(raProfile, loadStoredSet(raProfile), mode);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<BaseAttribute> resolveIssueAttributeSet(RaProfile raProfile) throws ConnectorException, NotFoundException {
        RaProfileCertificateRequestAttribute stored = loadStoredSet(raProfile);
        return resolve(raProfile, stored, stored == null ? null : stored.getMergeMode());
    }

    private List<BaseAttribute> resolve(RaProfile raProfile, RaProfileCertificateRequestAttribute stored, AttributeSetMergeMode mode)
            throws ConnectorException, NotFoundException {
        List<BaseAttribute> staticSet = stored == null ? new ArrayList<>() : deserializeOrEmpty(stored.getRequestAttributes());
        List<BaseAttribute> connectorSet =
                RequestAttributeSetResolver.effectiveMode(mode) == AttributeSetMergeMode.STATIC_ONLY
                        ? List.of()
                        : listConnectorIssueAttributes(raProfile);

        List<BaseAttribute> merged = RequestAttributeSetResolver.merge(staticSet, connectorSet, mode);
        if (merged.isEmpty()) {
            // fall back to the editable platform default set when nothing resolved.
            merged = new ArrayList<>(getDefaultSet());
        }

        return RequestAttributeSetResolver.applyValueSourceBindings(merged, loadValueSourceBindings(raProfile));
    }

    private RaProfileCertificateRequestAttribute loadStoredSet(RaProfile raProfile) {
        return requestAttributeRepository.findByRaProfileUuid(raProfile.getUuid()).orElse(null);
    }

    private List<BaseAttribute> listConnectorIssueAttributes(RaProfile raProfile) throws ConnectorException, NotFoundException {
        if (raProfile.getAuthorityInstanceReference() == null || raProfile.getAuthorityInstanceReference().getConnector() == null) {
            return List.of(); // offline/external authority: no dynamic set
        }
        return extendedAttributeService.listIssueCertificateAttributes(raProfile);
    }

    @Override
    public List<BaseAttribute> getStaticSet(RaProfile raProfile) {
        return requestAttributeRepository.findByRaProfileUuid(raProfile.getUuid())
                .map(set -> deserializeOrEmpty(set.getRequestAttributes()))
                .orElseGet(ArrayList::new);
    }

    @Override
    public RaProfileCertificateRequestAttributesDto getConfiguration(RaProfile raProfile) {
        RaProfileCertificateRequestAttributesDto dto = new RaProfileCertificateRequestAttributesDto();
        RaProfileCertificateRequestAttribute set = requestAttributeRepository.findByRaProfileUuid(raProfile.getUuid())
                .orElse(null);
        dto.setRequestAttributes(set == null ? new ArrayList<>() : deserializeOrEmpty(set.getRequestAttributes()));
        if (set != null) {
            dto.setExternalCsrValidationStrict(set.getExternalCsrValidationStrict());
        }
        // Read view always exposes the effective merge mode (resolved even when no set is stored), so clients never
        // see null; the null -> MERGE default lives once in RequestAttributeSetResolver.
        dto.setMergeMode(RequestAttributeSetResolver.effectiveMode(set == null ? null : set.getMergeMode()));
        dto.setValueSourceBindings(toBindingDtos(valueSourceBindingRepository.findByRaProfileUuid(raProfile.getUuid())));
        return dto;
    }

    @Override
    public void updateConfiguration(RaProfile raProfile, RaProfileCertificateRequestAttributesUpdateDto request) {
        validateDefinitionShape(request.getRequestAttributes());
        writer.saveStaticSet(
                raProfile,
                AttributeDefinitionUtils.serialize(request.getRequestAttributes()),
                request.getMergeMode(),
                request.getExternalCsrValidationStrict());
        writer.replaceValueSourceBindings(raProfile.getUuid(), toBindingEntities(raProfile, request.getValueSourceBindings()));
    }

    @Override
    public List<BaseAttribute> getDefaultSet() {
        Setting setting = settingRepository.findBySectionAndCategoryAndName(
                SettingsSection.PLATFORM,
                SettingsSectionCategory.PLATFORM_CERTIFICATES.getCode(),
                DefaultRequestAttributeSet.SETTING_NAME);
        return DefaultRequestAttributeSet.resolve(setting == null ? null : setting.getValue());
    }

    @Override
    public boolean resolveExternalCsrValidationStrict(RaProfile raProfile) {
        Boolean perProfile = getConfiguration(raProfile).getExternalCsrValidationStrict();
        if (perProfile != null) {
            return perProfile;
        }
        Setting strict = settingRepository.findBySectionAndCategoryAndName(
                SettingsSection.PLATFORM,
                SettingsSectionCategory.PLATFORM_CERTIFICATES.getCode(),
                DefaultRequestAttributeSet.STRICT_SETTING_NAME);
        return strict != null && strict.getValue() != null && Boolean.parseBoolean(strict.getValue().trim());
    }

    private List<BaseAttribute> deserializeOrEmpty(String serialized) {
        if (serialized == null || serialized.isBlank()) {
            return new ArrayList<>();
        }
        List<BaseAttribute> parsed = AttributeDefinitionUtils.deserialize(serialized, BaseAttribute.class);
        return parsed == null ? new ArrayList<>() : parsed;
    }

    private ValueSourceType parseValueSourceType(String stored) {
        try {
            return ValueSourceType.valueOf(stored);
        } catch (IllegalArgumentException e) {
            throw new ValidationException(ValidationError.create("Stored value-source binding kind is not recognised."));
        }
    }

    private List<ValueSourceBindingSpec> loadValueSourceBindings(RaProfile raProfile) {
        List<RaProfileValueSourceBinding> rows = valueSourceBindingRepository.findByRaProfileUuid(raProfile.getUuid());
        List<ValueSourceBindingSpec> specs = new ArrayList<>();
        for (RaProfileValueSourceBinding row : rows) {
            specs.add(new ValueSourceBindingSpec(
                    row.getAttributeUuid(),
                    row.getAttributeName(),
                    parseValueSourceType(row.getValueSourceType()),
                    row.getCollectionRef(),
                    deserializeParams(row.getParams())));
        }
        return specs;
    }

    private List<ValueSourceBindingDto> toBindingDtos(List<RaProfileValueSourceBinding> rows) {
        List<ValueSourceBindingDto> dtos = new ArrayList<>();
        for (RaProfileValueSourceBinding row : rows) {
            ValueSourceBindingDto dto = new ValueSourceBindingDto();
            dto.setAttributeUuid(row.getAttributeUuid());
            dto.setAttributeName(row.getAttributeName());
            dto.setValueSourceType(parseValueSourceType(row.getValueSourceType()));
            dto.setCollectionRef(row.getCollectionRef());
            dto.setParams(deserializeParams(row.getParams()));
            dtos.add(dto);
        }
        return dtos;
    }

    private List<RaProfileValueSourceBinding> toBindingEntities(RaProfile raProfile, List<ValueSourceBindingDto> bindings) {
        List<RaProfileValueSourceBinding> entities = new ArrayList<>();
        if (bindings == null) {
            return entities;
        }
        for (ValueSourceBindingDto binding : bindings) {
            RaProfileValueSourceBinding entity = new RaProfileValueSourceBinding();
            entity.setRaProfileUuid(raProfile.getUuid());
            entity.setAttributeUuid(binding.getAttributeUuid());
            entity.setAttributeName(binding.getAttributeName());
            entity.setValueSourceType(binding.getValueSourceType().name());
            entity.setCollectionRef(binding.getCollectionRef());
            entity.setParams(serializeParams(binding.getParams()));
            entities.add(entity);
        }
        return entities;
    }

    private List<SourceParam> deserializeParams(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, objectMapper.getTypeFactory().constructCollectionType(List.class, SourceParam.class));
        } catch (JsonProcessingException e) {
            // Do not surface the raw parser message (may echo stored JSON fragments).
            throw new ValidationException(ValidationError.create("Stored value-source binding parameters are not readable."));
        }
    }

    private String serializeParams(List<SourceParam> params) {
        if (params == null || params.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(params);
        } catch (JsonProcessingException e) {
            throw new ValidationException(ValidationError.create("Value-source binding parameters could not be stored."));
        }
    }

    /**
     * Validates that the platform-owned definitions are coherent. Platform-owned, so {@code connectorUuid = null};
     * request values are never part of these definitions.
     */
    private void validateDefinitionShape(List<BaseAttribute> definitions) {
        if (definitions == null) {
            return;
        }
        for (BaseAttribute def : definitions) {
            if (def instanceof DataAttributeV3 v3 && v3.getProperties() == null) {
                throw new ValidationException(ValidationError.create(
                        "Request attribute definition '{}' is missing properties", v3.getName()));
            }
        }
    }
}
