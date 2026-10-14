package com.otilm.core.events.handlers;

import com.otilm.api.model.common.events.data.CbomSyncedEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.evaluator.CbomTriggerEvaluator;
import com.otilm.core.events.EventHandler;
import com.otilm.core.messaging.model.EventMessage;
import java.util.UUID;
import org.springframework.stereotype.Component;

@Component(ResourceEvent.Codes.CBOM_SYNCED)
public class CbomSyncedEventHandler extends EventHandler<Cbom> {

    public CbomSyncedEventHandler(CbomRepository repository, CbomTriggerEvaluator evaluator) {
        super(repository, evaluator);
    }

    @Override
    protected CbomSyncedEventData getEventData(Cbom cbom, Object messageData) {
        CbomSyncedEventData data = new CbomSyncedEventData();
        data.setCbomUuid(cbom.getUuid());
        data.setSerialNumber(cbom.getSerialNumber());
        data.setVersion(cbom.getVersion());
        data.setSource(cbom.getSource());
        data.setTotalAssets(cbom.getTotalAssetsCount());
        data.setAssetsSyncedAt(cbom.getAssetsSyncedAt());
        return data;
    }

    public static EventMessage constructEventMessage(UUID cbomUuid, UUID userUuid) {
        return new EventMessage(ResourceEvent.CBOM_SYNCED, Resource.CBOM, cbomUuid, null, null, null, userUuid, null);
    }
}
