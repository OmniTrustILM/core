package com.otilm.core.events.handlers;

import com.otilm.api.exception.EventException;
import com.otilm.api.model.common.events.data.CryptoAssetPqcNotReadyEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.evaluator.CryptoAssetTriggerEvaluator;
import com.otilm.core.events.EventContext;
import com.otilm.core.events.EventHandler;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.security.authz.SecuredUUID;
import java.util.UUID;
import org.springframework.stereotype.Component;

@Component(ResourceEvent.Codes.CRYPTO_ASSET_PQC_NOT_READY)
public class CryptoAssetPqcNotReadyEventHandler extends EventHandler<CryptoAsset> {

    public CryptoAssetPqcNotReadyEventHandler(CryptoAssetRepository repository, CryptoAssetTriggerEvaluator evaluator) {
        super(repository, evaluator);
    }

    @Override
    protected EventContext<CryptoAsset> prepareContext(EventMessage message) throws EventException {
        CryptoAssetPqcNotReadyEventData data = getEventData(null, message.getData());
        if (data == null || data.getCryptoAssetUuid() == null
                || !data.getCryptoAssetUuid().equals(message.getObjectUuid())) {
            throw new IllegalArgumentException("PQC event snapshot must identify the event's cryptographic asset");
        }
        CryptoAsset asset = repository.findByUuid(SecuredUUID.fromUUID(message.getObjectUuid())).orElse(null);
        EventContext<CryptoAsset> context = new EventContext<>(message, triggerEvaluator, asset, data);
        if (asset != null) {
            fetchEventTriggers(context, null, null);
        }
        return context;
    }

    @Override
    protected CryptoAssetPqcNotReadyEventData getEventData(CryptoAsset asset, Object snapshot) {
        return objectMapper.convertValue(snapshot, CryptoAssetPqcNotReadyEventData.class);
    }

    public static EventMessage constructEventMessage(CryptoAssetPqcNotReadyEventData snapshot, UUID userUuid) {
        return new EventMessage(ResourceEvent.CRYPTO_ASSET_PQC_NOT_READY, Resource.CRYPTO_ASSET,
                snapshot.getCryptoAssetUuid(), null, null, snapshot, userUuid, null);
    }
}
