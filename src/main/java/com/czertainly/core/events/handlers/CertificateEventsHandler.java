package com.czertainly.core.events.handlers;

import com.czertainly.api.exception.EventException;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.Group;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.evaluator.CertificateTriggerEvaluator;
import com.czertainly.core.events.EventContext;
import com.czertainly.core.events.EventContextTriggers;
import com.czertainly.core.events.EventHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Component
@Transactional
public abstract class CertificateEventsHandler extends EventHandler<Certificate> {

    protected CertificateEventsHandler(CertificateRepository repository, CertificateTriggerEvaluator ruleEvaluator) {
        super(repository, ruleEvaluator);
    }

    @Override
    protected List<EventContextTriggers> getOverridingTriggers(EventContext<Certificate> eventContext, Certificate object) throws EventException {
        List<EventContextTriggers> eventContextTriggers = new ArrayList<>();

        if (object.getGroups() != null && !object.getGroups().isEmpty()) {
            for (Group group : object.getGroups()) {
                eventContextTriggers.add(fetchEventTriggers(eventContext, Resource.GROUP, group.getUuid()));
            }
        }
        if (object.getRaProfileUuid() != null) {
            eventContextTriggers.add(fetchEventTriggers(eventContext, Resource.RA_PROFILE, object.getRaProfileUuid()));
        }

        return eventContextTriggers;
    }
}
