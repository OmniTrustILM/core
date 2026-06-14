package com.otilm.core.service.writer.signing;

import com.otilm.core.dao.entity.signing.TspProfileBasicCredential;
import com.otilm.core.dao.repository.signing.TspProfileBasicCredentialRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Component
public class TspProfileBasicCredentialWriter {

    private final TspProfileBasicCredentialRepository repository;

    public TspProfileBasicCredentialWriter(TspProfileBasicCredentialRepository repository) {
        this.repository = repository;
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public TspProfileBasicCredential insert(TspProfileBasicCredential row) {
        return repository.saveAndFlush(row);
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public TspProfileBasicCredential update(TspProfileBasicCredential row) {
        return repository.saveAndFlush(row);
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public void deleteByUuid(UUID uuid) {
        repository.deleteByUuid(uuid);
    }
}
