package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventHistoryDto;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.core.dao.entity.CryptographicKeyEventHistory;
import com.otilm.core.dao.entity.CryptographicKeyItem;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface CryptographicKeyEventHistoryService {
    /**
     * Function to get the List of events on the key
     *
     * @param uuid UUID of the key item
     * @return List of events on the key
     * @throws NotFoundException when then item with uuid is not found
     */
    List<KeyEventHistoryDto> getKeyEventHistory(UUID uuid) throws NotFoundException;

    /**
     * Get a single event for an associated Key
     *
     * @param event                 Event
     * @param status                Status of the event
     * @param message               Message for the event
     * @param additionalInformation Additional Information associated with the event
     * @param key                   Key Entity
     * @return Key History Event
     */
    CryptographicKeyEventHistory getEventHistory(KeyEvent event, KeyEventStatus status, String message, String additionalInformation, CryptographicKeyItem key);

    /**
     * Function to save multiple Events for a key in async
     *
     * @param keyEventHistories List of events
     */
    void asyncSaveAllInBatch(List<CryptographicKeyEventHistory> keyEventHistories);

    /**
     * Method to add event into the Certificate history.
     *
     * @param event                 Certificate event
     * @param status                Event result
     * @param message               Short message for the event
     * @param additionalInformation Additional information as key-value pairs
     * @param key                   key entity that should record the event
     */
    void addEventHistory(KeyEvent event, KeyEventStatus status, String message, Map<String, Object> additionalInformation, CryptographicKeyItem key);

    /**
     * Method to add event into the Certificate history.
     *
     * @param event                 Certificate event
     * @param status                Event result
     * @param message               Short message for the event
     * @param additionalInformation Additional information as key-value pairs
     * @param keyUuid               key entity that should record the event
     */
    void addEventHistory(KeyEvent event, KeyEventStatus status, String message, Map<String, Object> additionalInformation, UUID keyUuid);
}
