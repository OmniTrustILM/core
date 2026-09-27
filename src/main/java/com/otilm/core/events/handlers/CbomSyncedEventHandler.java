package com.otilm.core.events.handlers;

import com.otilm.api.exception.EventException;
import com.otilm.api.model.common.events.data.CbomSyncedEventData;
import com.otilm.api.model.common.events.data.CryptoAssetAddedEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.evaluator.TriggerEvaluator;
import com.otilm.core.events.EventHandler;
import com.otilm.core.messaging.model.EventMessage;
import java.util.List;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Processes new asset triggers before the corresponding CBOM synced triggers. */
@Slf4j
@Component(ResourceEvent.Codes.CBOM_SYNCED)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
public class CbomSyncedEventHandler extends EventHandler<Cbom> {

    private final CryptoAssetAddedEventHandler assetAddedHandler;

    public CbomSyncedEventHandler(CbomRepository repository, TriggerEvaluator<Cbom> evaluator,
            CryptoAssetAddedEventHandler assetAddedHandler) {
        super(repository, evaluator);
        this.assetAddedHandler = assetAddedHandler;
    }

    @Override
    public void handleEvent(EventMessage message) throws EventException {
        CbomSyncedEventPayload payload = objectMapper.convertValue(message.getData(), CbomSyncedEventPayload.class);
        if (!payload.assets().isEmpty()) {
            try {
                assetAddedHandler
                        .handleEvent(CryptoAssetAddedEventHandler
                                .constructEventMessage(message.getObjectUuid(), payload.assets(),
                                        message.getUserUuid()));
            } catch (Exception e) {
                log.error("Could not process added asset events for CBOM {}", message.getObjectUuid(), e);
            }
        }
        super.handleEvent(message);
    }

    @Override
    protected CbomSyncedEventData getEventData(Cbom cbom, Object messageData) {
        if (messageData != null) {
            return objectMapper.convertValue(messageData, CbomSyncedEventPayload.class).cbom();
        }
        return snapshot(cbom);
    }

    public static CbomSyncedEventData snapshot(Cbom cbom) {
        CbomSyncedEventData data = new CbomSyncedEventData();
        data.setCbomUuid(cbom.getUuid());
        data.setSerialNumber(cbom.getSerialNumber());
        data.setVersion(cbom.getVersion());
        data.setSource(cbom.getSource());
        data.setTotalAssets(cbom.getTotalAssetsCount());
        data.setAssetsSyncedAt(cbom.getAssetsSyncedAt());
        return data;
    }

    public static EventMessage constructEventMessage(UUID cbomUuid, CbomSyncedEventData cbom,
            List<CryptoAssetAddedEventData> newAssets, UUID userUuid) {
        return new EventMessage(ResourceEvent.CBOM_SYNCED, Resource.CBOM, cbomUuid, null, null,
                new CbomSyncedEventPayload(cbom, newAssets), userUuid, null);
    }
}
