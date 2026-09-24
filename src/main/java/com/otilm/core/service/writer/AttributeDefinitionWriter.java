package com.otilm.core.service.writer;

import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AttributeDefinitionWriter {

    private final AttributeDefinitionRepository attributeDefinitionRepository;

    @Autowired
    public AttributeDefinitionWriter(AttributeDefinitionRepository attributeDefinitionRepository) {
        this.attributeDefinitionRepository = attributeDefinitionRepository;
    }

    /** Returns whether this call set the operation of a definition that had none. */
    @Transactional
    public boolean claimOperation(UUID definitionUuid, String operation) {
        return attributeDefinitionRepository.claimOperation(definitionUuid, operation) == 1;
    }
}
