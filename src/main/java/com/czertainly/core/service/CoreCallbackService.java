package com.czertainly.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.otilm.api.model.common.attribute.v2.content.ObjectAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.core.auth.AttributeResource;


import java.util.List;

public interface CoreCallbackService {

    List<ObjectAttributeContentV2> coreGetCredentials(RequestAttributeCallback callback) throws ValidationException;

    List<ResourceObjectContent> coreGetResources(RequestAttributeCallback callback, AttributeResource resource) throws NotFoundException;

}
