package com.czertainly.core.events;

import com.czertainly.api.exception.EventException;
import com.czertainly.core.messaging.model.EventMessage;

public interface IEventHandler {

    void handleEvent(EventMessage eventMessage) throws EventException;

}
