package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.otilm.api.model.common.attribute.v2.content.ObjectAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.security.authz.SecuredResource;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CoreCallbackService;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.ResourceExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;

@Service
@Transactional
public class CoreCallbackServiceImpl implements CoreCallbackService {

    public static final String CREDENTIAL_KIND_PATH_VARIABLE = "credentialKind";

    private CredentialInternalService credentialService;

    private ResourceExternalService resourceService;

    @Autowired
    public void setResourceService(ResourceExternalService resourceService) {
        this.resourceService = resourceService;
    }

    @Autowired
    public void setCredentialService(CredentialInternalService credentialService) {
        this.credentialService = credentialService;
    }

    @Override
    public List<ObjectAttributeContentV2> coreGetCredentials(RequestAttributeCallback callback) throws ValidationException {
        if (callback.getPathVariable() == null ||
                callback.getPathVariable().get(CREDENTIAL_KIND_PATH_VARIABLE) == null) {
            throw new ValidationException(ValidationError.create("Required path variable credentialKind not found in callback."));
        }

        String kind = callback.getPathVariable().get(CREDENTIAL_KIND_PATH_VARIABLE).toString();
        List<NameAndUuidDto> credentialDataList = credentialService.listCredentialsCallback(SecurityFilter.create(), kind);

        List<ObjectAttributeContentV2> jsonContent = new ArrayList<>();
        for (NameAndUuidDto credentialData : credentialDataList) {
            ObjectAttributeContentV2 content = new ObjectAttributeContentV2(credentialData.getName(), credentialData);
            jsonContent.add(content);
        }

        return jsonContent;
    }

    /**
     * Lists candidate resource objects for an attribute-callback dropdown.
     * <p>
     * Routes through {@link ResourceExternalService#getResourceObjects} rather than the internal
     * {@code getResourceObjectsInternal} so the {@code @ExternalAuthorizationDynamic(LIST)} guard on
     * {@code getResourceObjects} applies the caller's per-object ACL. This closes the CERTIFICATE
     * listing gap (whose own {@code listResourceObjects} carries no {@code @ExternalAuthorization}) and
     * installs uniform defense-in-depth so any future unannotated per-kind listing stays scoped.
     * <p>
     * Same-connector narrowing of the dropdown is deliberately not applied here (cross-connector
     * references are legitimate); it is deferred to core #1643.
     */
    @Override
    public List<ResourceObjectContent> coreGetResources(RequestAttributeCallback callback, AttributeResource resource) throws NotFoundException {
        // Filters are in form: property_name.operator
        List<SearchFilterRequestDto> filters = new ArrayList<>();
        if (callback.getFilter() != null) {
            for (String filterDefinition : callback.getFilter().keySet()) {
                String filterFieldString;
                FilterConditionOperator operator;
                try {
                    filterFieldString = filterDefinition.split("\\.")[0];
                    String filterOperatorString = filterDefinition.split("\\.")[1];
                    operator = FilterConditionOperator.valueOf(filterOperatorString);
                } catch (Exception e) {
                    throw new ValidationException("Filter %s for callback mapping is invalid: %s".formatted(filterDefinition, e.getMessage()));
                }
                filters.add(new SearchFilterRequestDto(FilterFieldSource.PROPERTY, filterFieldString, operator, callback.getFilter().get(filterDefinition)));
            }
        }
        return resourceService.getResourceObjects(
                        SecuredResource.fromResource(Resource.findByCode(resource.getCode())),
                        SecurityFilter.create(),
                        filters,
                        callback.getPagination())
                .stream()
                .map(id -> {
                    ResourceObjectContentData data = new ResourceObjectContentData(resource);
                    data.setUuid(id.getUuid());
                    data.setName(id.getName());
                    return new ResourceObjectContent(id.getName(), data);
                })
                .toList();
    }

}
