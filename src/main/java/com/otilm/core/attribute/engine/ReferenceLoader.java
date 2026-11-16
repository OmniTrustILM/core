package com.otilm.core.attribute.engine;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.core.auth.AttributeResource;
import java.util.UUID;

/** Loads the content of one referenced object, authorizing it as the resolution requires. */
@FunctionalInterface
public interface ReferenceLoader {

    /**
     * @return the object's content, or {@code null} for a kind that is sent as a bare reference
     */
    ResourceObjectContentData load(AttributeResource kind, UUID uuid)
            throws NotFoundException, AttributeException, ConnectorException;
}
