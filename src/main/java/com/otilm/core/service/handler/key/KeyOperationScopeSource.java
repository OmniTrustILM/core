package com.otilm.core.service.handler.key;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.KeyOperationScope;

/** The scope of a v2 operation on the key item. The adapter takes it before resolving any attribute. */
@FunctionalInterface
interface KeyOperationScopeSource {

    KeyOperationScope scopeOf(CryptographicKeyItemOperationModel keyItem) throws NotFoundException;
}
