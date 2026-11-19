package com.otilm.core.service;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.cryptography.key.OnboardTokenKeysRequestDto;
import com.otilm.api.model.core.cryptography.key.OnboardTokenKeysResponseDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyListResponseDto;
import java.util.UUID;

public interface TokenKeyOnboardingExternalService {

    /**
     * A page of the profile's token keys, one entry per key in the token's order.
     *
     * @param pageNumber page to return, starting at 1
     * @param itemsPerPage largest number of entries on the page, whether or not an entry carries a key pair
     * @throws NotFoundException if the token has no such profile
     * @throws com.otilm.api.exception.ValidationException if key listing is unavailable on the profile, or the page is
     * out of range
     */
    TokenKeyListResponseDto listTokenKeys(UUID tokenInstanceUuid, UUID tokenProfileUuid, int pageNumber,
            int itemsPerPage) throws ConnectorException, NotFoundException;

    /**
     * Onboards the selected key pairs with their key data read again from the token: each as a key of its own, or into
     * the public-key-only record that holds its public key.
     *
     * @return one result per selected key pair, in the order selected
     * @throws NotFoundException if the token has no such profile
     * @throws com.otilm.api.exception.ValidationException if key listing is unavailable on the profile, or the request
     * is invalid
     */
    OnboardTokenKeysResponseDto onboardTokenKeys(UUID tokenInstanceUuid, UUID tokenProfileUuid,
            OnboardTokenKeysRequestDto request) throws ConnectorException, NotFoundException, AttributeException;
}
