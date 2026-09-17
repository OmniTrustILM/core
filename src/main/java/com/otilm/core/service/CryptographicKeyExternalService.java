package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.cryptography.CryptographicKeyResponseDto;
import com.otilm.api.model.client.cryptography.key.BulkCompromiseKeyItemRequestDto;
import com.otilm.api.model.client.cryptography.key.BulkCompromiseKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.BulkKeyItemUsageRequestDto;
import com.otilm.api.model.client.cryptography.key.BulkKeyUsageRequestDto;
import com.otilm.api.model.client.cryptography.key.CompromiseKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.EditKeyItemDto;
import com.otilm.api.model.client.cryptography.key.EditKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.cryptography.key.UpdateKeyUsageRequestDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyDto;
import com.otilm.api.model.core.cryptography.key.KeyEventHistoryDto;
import com.otilm.api.model.core.cryptography.key.KeyItemDetailDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface CryptographicKeyExternalService {

    /**
     * List of all available keys
     *
     * @param filter - Security Filter for Access Control
     * @return List of Key details {@Link KeyDto}
     */
    CryptographicKeyResponseDto listCryptographicKeys(SecurityFilter filter, SearchRequestDto request);

    /**
     * List of all available keys that contains full key pair
     *
     * @param tokenProfileUuid UUID of the token profile
     * @param filter Security Filter for Access Control
     * @return List of Key details {@Link KeyDto}
     */
    List<KeyDto> listKeyPairs(Optional<String> tokenProfileUuid, SecurityFilter filter);

    /**
     * @param uuid UUID of the concerned Key
     * @return Detail of the key {@Link KeyDetailDto}
     * @throws NotFoundException when the token profile or key is not found
     */
    KeyDetailDto getKey(SecuredUUID uuid) throws NotFoundException;

    /**
     * Get the detail of the key item
     *
     * @param uuid UUID of the parent key object
     * @param keyItemUuid UUID of the key item
     * @return Key Item detail
     * @throws NotFoundException when the key or token instance is not found
     */
    KeyItemDetailDto getKeyItem(SecuredUUID uuid, String keyItemUuid) throws NotFoundException;

    /**
     * @param request DTO containing the information for creating a new key
     * @param tokenInstanceUuid UUID of the token instance
     * @param type Type of the key to be created
     * @return Details of the newly created key
     * @throws AlreadyExistException when the key with same data already exists
     * @throws ValidationException when the validation of the data or attributes fails
     * @throws ConnectorException when there are issues with connector communication
     */
    KeyDetailDto createKey(UUID tokenInstanceUuid, SecuredParentUUID tokenProfileUuid, KeyRequestType type,
            KeyRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException,
            AttributeException, NotFoundException;

    /**
     * Function to update the key details
     *
     * @param uuid UUID of the key
     * @param request Information regarding the update key
     * @return Updated token Instance details
     */
    KeyDetailDto editKey(SecuredUUID uuid, EditKeyRequestDto request) throws NotFoundException, AttributeException;

    /**
     * Disables selected items of a key. Duplicate item UUIDs are processed once.
     *
     * @param uuid UUID of the key
     * @param keyUuids UUID strings of items belonging to the key; null or empty selects all its items
     * @throws NotFoundException when the key is not found
     * @throws ValidationException when a selected item is missing or belongs to another key; no items are updated
     */
    void disableKey(UUID uuid, List<String> keyUuids) throws NotFoundException, ValidationException;

    /**
     * Enables selected items of a key. Duplicate item UUIDs are processed once.
     *
     * @param uuid UUID of the key
     * @param keyUuids UUID strings of items belonging to the key; null or empty selects all its items
     * @throws NotFoundException when the key with given uuid is not found
     * @throws ValidationException when a selected item is missing or belongs to another key; no items are updated
     */
    void enableKey(UUID uuid, List<String> keyUuids) throws NotFoundException, ValidationException;

    /**
     * Function to disable multiple keys
     *
     * @param uuids UUIDs of the keys
     */
    void disableKey(List<String> uuids);

    /**
     * Function to enable multiple keys
     *
     * @param uuids UUIDs of the keys
     */
    void enableKey(List<String> uuids);

    /**
     * Deletes selected items of a key. Duplicate item UUIDs are processed once. A null or empty selection deletes the
     * key and all its items.
     *
     * @param uuid UUID of the key
     * @param keyUuids UUID strings of items belonging to the key, or null or empty to delete the entire key
     * @throws NotFoundException when the key is not found
     * @throws ValidationException when a selected item is missing or belongs to another key; nothing is deleted
     * @throws ConnectorException when remote deletion fails
     */
    void deleteKey(UUID uuid, List<String> keyUuids) throws ConnectorException, NotFoundException;

    /**
     * Function to delete multiple key
     *
     * @param uuids Key UUIDs
     * @throws ConnectorException
     */
    void deleteKey(List<String> uuids) throws ConnectorException;

    /**
     * Function to delete multiple key items
     *
     * @param filter security filter for object-level access filtering
     * @param keyItemUuids Key Item UUIDs
     * @throws ConnectorException
     */
    void deleteKeyItems(SecurityFilter filter, List<String> keyItemUuids) throws ConnectorException;

    /**
     * Destroys selected items of a key after validating the complete selection and its authorization. Duplicate item
     * UUIDs are processed once. Every selected item is considered even when another item has an invalid lifecycle state
     * or fails during destruction. Failures are reported together with the completed count after processing;
     * successfully completed destruction is not undone when another item fails.
     *
     * @param uuid non-null UUID of the key
     * @param keyUuids UUID strings of items belonging to the key; null or empty selects all its items
     * @throws NotFoundException when the key or its token is not found before destruction
     * @throws IllegalArgumentException when an item UUID is malformed; no items are destroyed
     * @throws ValidationException when an item is missing or belongs to another key, before any destruction, or when an
     * item's state prevents destruction or its destruction fails, after processing the entire selection
     */
    void destroyKey(UUID uuid, List<String> keyUuids) throws ConnectorException, NotFoundException;

    /**
     * Destroys the items of the specified keys after loading and authorizing all selected keys. Duplicate key UUIDs are
     * processed once, in order of first occurrence. Every selected item across all keys is considered even when another
     * item has an invalid lifecycle state or fails during destruction. Failures are reported together with the
     * completed count after processing; successfully completed destruction is not undone when another item fails.
     *
     * @param uuids non-null list of key UUID strings; an empty list performs no destruction
     * @throws NotFoundException when a key or its token is not found; no items are destroyed
     * @throws IllegalArgumentException when a key UUID is malformed; no items are destroyed
     * @throws ValidationException when an item's state prevents destruction or its destruction fails, after processing
     * all selected keys
     */
    void destroyKey(List<String> uuids) throws ConnectorException, NotFoundException;

    /**
     * List attributes to create a new key
     *
     * @param tokenInstanceUuid UUID of the token instance
     * @param type Type of the key to be created
     * @return List of attributes to create a new key
     * @throws NotFoundException when the token profile is not found
     * @throws ConnectorException when there are issues with connector communication
     */
    List<BaseAttribute> listCreateKeyAttributes(UUID tokenInstanceUuid, SecuredParentUUID tokenProfileUuid,
            KeyRequestType type) throws ConnectorException, NotFoundException;

    /**
     * Function to sync the list of keys from the connector
     *
     * @param tokenInstanceUuid UUID of the token instance to sync the keys
     * @throws ConnectorException
     */
    void syncKeys(SecuredParentUUID tokenInstanceUuid) throws ConnectorException, AttributeException, NotFoundException;

    /**
     * Marks selected items of a key as compromised. Duplicate item UUIDs are processed once.
     *
     * @param uuid UUID of the key
     * @param request non-null request containing the reason and item UUIDs; a null or empty UUID list selects all items
     * @throws NotFoundException when the key is not found
     * @throws ValidationException when an item is missing or belongs to another key, before any updates, or when an
     * item's state prevents compromise, after processing the selection
     */
    void compromiseKey(UUID uuid, CompromiseKeyRequestDto request) throws NotFoundException;

    /**
     * Function to mark the keys as compromised
     *
     * @param request UUIDs of the key
     */
    void compromiseKey(BulkCompromiseKeyRequestDto request);

    /**
     * Function to update the usages for the key
     *
     * @param request Request containing the details for updating the usages
     */
    void updateKeyUsages(BulkKeyUsageRequestDto request);

    /**
     * Replaces the usages of selected items of a key. Duplicate item UUIDs are processed once.
     *
     * @param uuid UUID of the key
     * @param request non-null request containing the usages and item UUIDs; a null or empty UUID list selects all items
     * @throws NotFoundException when the key is not found
     * @throws ValidationException when an item is missing or belongs to another key, before any updates, or when an
     * item's usage update fails, after processing the selection
     */
    void updateKeyUsages(UUID uuid, UpdateKeyUsageRequestDto request) throws NotFoundException;

    /**
     * Returns the event history of an item belonging to the specified key.
     *
     * @param uuid UUID of the parent key
     * @param keyItemUuid UUID of the item belonging to that key
     * @return item events ordered from most recent to oldest
     * @throws NotFoundException when the key or item is missing, or the item belongs to another key
     */
    List<KeyEventHistoryDto> getEventHistory(UUID uuid, UUID keyItemUuid) throws NotFoundException;

    /**
     * Edit Key Item
     *
     * @param keyUuid UUID of parent Key of Key Item
     * @param keyItemUuid UUID of Key Item
     * @param editKeyItemDto Request for editing the Key Item
     * @return Key Item which has been edited
     * @throws NotFoundException Key has not been found
     */
    KeyItemDetailDto editKeyItem(SecuredUUID keyUuid, UUID keyItemUuid, EditKeyItemDto editKeyItemDto)
            throws NotFoundException;

    List<SearchFieldDataByGroupDto> getSearchableFieldInformation();

    /**
     * Function to enable multiple key items
     *
     * @param uuids UUIDs of the key items
     */
    void enableKeyItems(List<String> uuids) throws NotFoundException;

    /**
     * Function to disable multiple key items
     *
     * @param uuids UUIDs of the key items
     */
    void disableKeyItems(List<String> uuids) throws NotFoundException;

    /**
     * Destroys selected key items after validating the complete selection and authorizing their parent keys. Duplicate
     * item UUIDs are processed once. Every selected item across all parent keys is considered even when another item
     * has an invalid lifecycle state or fails during destruction. Failures are reported together with the completed
     * count after processing; successfully completed destruction is not undone when another item fails.
     *
     * @param keyItemUuids UUID strings of the items to destroy; null or empty performs no destruction
     * @throws NotFoundException when a parent key or its token is not found before destruction
     * @throws IllegalArgumentException when an item UUID is malformed; no items are destroyed
     * @throws ValidationException when an item is missing, before any destruction, or when an item's state prevents
     * destruction or its destruction fails, after processing the entire selection
     */
    void destroyKeyItems(List<String> keyItemUuids) throws ConnectorException, NotFoundException;

    /**
     * Function to mark the key items as compromised
     *
     * @param request UUIDs of the key items
     */
    void compromiseKeyItems(BulkCompromiseKeyItemRequestDto request) throws NotFoundException;

    /**
     * Function to update the usages for the key items
     *
     * @param request Request containing the details for updating the usages
     */
    void updateKeyItemUsages(BulkKeyItemUsageRequestDto request) throws NotFoundException;
}
