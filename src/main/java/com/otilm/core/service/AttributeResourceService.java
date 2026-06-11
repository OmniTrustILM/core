package com.otilm.core.service;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;

import java.util.UUID;

public interface AttributeResourceService {

    ResourceObjectContentData getResourceObjectContent(UUID uuid) throws NotFoundException, AttributeException, ConnectorException;

}
