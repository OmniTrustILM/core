package com.otilm.core.events.handlers;

import com.fasterxml.jackson.core.type.TypeReference;
import com.otilm.api.exception.EventException;
import com.otilm.api.model.common.events.data.CryptoAssetAddedEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.evaluator.TriggerEvaluator;
import com.otilm.core.events.EventContext;
import com.otilm.core.events.EventContextTriggers;
import com.otilm.core.events.EventHandler;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.security.authz.SecuredUUID;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Evaluates all assets added by one CBOM ingest from one message. */
@Component(ResourceEvent.Codes.CRYPTO_ASSET_ADDED)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
public class CryptoAssetAddedEventHandler extends EventHandler<CryptoAsset> {

    public CryptoAssetAddedEventHandler(CryptoAssetRepository repository, TriggerEvaluator<CryptoAsset> evaluator) {
        super(repository, evaluator);
    }

    @Override
    protected EventContext<CryptoAsset> prepareContext(EventMessage message) throws EventException {
        EventContext<CryptoAsset> context = new EventContext<>(message, triggerEvaluator, null, null);
        fetchEventTriggers(context, null, null);
        List<CryptoAssetAddedEventData> snapshots = objectMapper.convertValue(message.getData(), new TypeReference<>() {
        });
        for (CryptoAssetAddedEventData snapshot : snapshots) {
            repository.findByUuid(SecuredUUID.fromUUID(snapshot.getCryptoAssetUuid())).ifPresent(asset -> {
                context.getResourceObjects().add(asset);
                context.getResourceObjectsEventData().add(snapshot);
            });
        }
        return context;
    }

    @Override
    protected CryptoAssetAddedEventData getEventData(CryptoAsset asset, Object cbomUuid) {
        return snapshot(asset, (UUID) cbomUuid);
    }

    public static CryptoAssetAddedEventData snapshot(CryptoAsset asset, UUID cbomUuid) {
        CryptoAssetAddedEventData data = new CryptoAssetAddedEventData();
        data.setCryptoAssetUuid(asset.getUuid());
        data.setCbomUuid(cbomUuid);
        data.setAssetType(asset.getAssetType());
        data.setName(asset.getName());
        data.setAlgorithmFamily(asset.getAlgorithmFamily());
        data.setPqcVerdict(asset.getPqcVerdict());
        return data;
    }

    @Override
    protected List<EventContextTriggers> getOverridingTriggers(EventContext<CryptoAsset> context, CryptoAsset asset)
            throws EventException {
        UUID cbomUuid = context.getAssociationObjectUuid();
        if (cbomUuid == null) {
            return List.of();
        }
        String key = Resource.CBOM + "." + cbomUuid;
        EventContextTriggers triggers = context.getOverridingResourceTriggers().get(key);
        if (triggers == null) {
            triggers = fetchEventTriggers(context, Resource.CBOM, cbomUuid);
        }
        return List.of(triggers);
    }

    public static EventMessage constructEventMessage(UUID cbomUuid, List<CryptoAssetAddedEventData> assets,
            UUID userUuid) {
        return new EventMessage(ResourceEvent.CRYPTO_ASSET_ADDED, Resource.CRYPTO_ASSET, null, Resource.CBOM, cbomUuid,
                assets, userUuid, null);
    }
}
