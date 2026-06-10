package com.czertainly.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventHistoryDto;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.czertainly.core.dao.entity.CryptographicKeyEventHistory;
import com.czertainly.core.dao.entity.CryptographicKeyItem;
import com.czertainly.core.dao.repository.CryptographicKeyEventHistoryRepository;
import com.czertainly.core.dao.repository.CryptographicKeyItemRepository;
import com.czertainly.core.service.CryptographicKeyEventHistoryService;
import com.czertainly.core.util.MetaDefinitions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Transactional
public class CryptographicKeyEventHistoryServiceImpl implements CryptographicKeyEventHistoryService {

    private static final Logger logger = LoggerFactory.getLogger(CryptographicKeyEventHistoryServiceImpl.class);

    @Autowired
    private CryptographicKeyEventHistoryRepository keyEventHistoryRepository;

    @Autowired
    private CryptographicKeyItemRepository keyItemRepository;

    @Override
    public List<KeyEventHistoryDto> getKeyEventHistory(UUID uuid) throws NotFoundException {
        CryptographicKeyItem key = keyItemRepository
                .findByUuid(uuid)
                .orElseThrow(
                        () ->
                                new NotFoundException(
                                        CryptographicKeyItem.class,
                                        uuid
                                )
                );
        return keyEventHistoryRepository
                .findByKeyOrderByCreatedDesc(key)
                .stream()
                .map(CryptographicKeyEventHistory::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    public CryptographicKeyEventHistory getEventHistory(KeyEvent event, KeyEventStatus status, String message, String additionalInformation, CryptographicKeyItem key) {
        CryptographicKeyEventHistory history = new CryptographicKeyEventHistory();
        history.setEvent(event);
        history.setKey(key);
        history.setStatus(status);
        history.setAdditionalInformation(additionalInformation);
        history.setMessage(message);
        return history;
    }


    @Override
    public void addEventHistory(KeyEvent event, KeyEventStatus status, String message, Map<String, Object> additionalInformation, CryptographicKeyItem key) {
        CryptographicKeyEventHistory history = new CryptographicKeyEventHistory();
        history.setEvent(event);
        history.setKey(key);
        history.setStatus(status);
        history.setAdditionalInformation(MetaDefinitions.serialize(additionalInformation));
        history.setMessage(message);
        keyEventHistoryRepository.save(history);
    }

    @Override
    public void addEventHistory(KeyEvent event, KeyEventStatus status, String message, Map<String, Object> additionalInformation, UUID keyUuid) {
        CryptographicKeyEventHistory history = new CryptographicKeyEventHistory();
        history.setEvent(event);
        history.setKeyUuid(keyUuid);
        history.setStatus(status);
        history.setAdditionalInformation(MetaDefinitions.serialize(additionalInformation));
        history.setMessage(message);
        keyEventHistoryRepository.save(history);
    }

    @Override
    @Async
    public void asyncSaveAllInBatch(List<CryptographicKeyEventHistory> certificateEventHistories) {
        keyEventHistoryRepository.saveAll(certificateEventHistories);
        logger.info("Inserted {} record into the database", certificateEventHistories.size());
    }
}
