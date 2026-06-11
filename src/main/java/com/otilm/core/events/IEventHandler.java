package com.otilm.core.events;

import com.otilm.api.exception.EventException;
import com.otilm.core.messaging.model.EventMessage;

public interface IEventHandler {

    void handleEvent(EventMessage eventMessage) throws EventException;

}
