package com.otilm.core.service.handler.key;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.KeyOperationScope;

/** Supplies the scope of a v2 operation on the key item, which the adapter takes before resolving any attribute. */
@FunctionalInterface
interface KeyOperationScopeSource {

    KeyOperationScope scopeOf(CryptographicKeyItemOperationModel keyItem) throws NotFoundException;
}
