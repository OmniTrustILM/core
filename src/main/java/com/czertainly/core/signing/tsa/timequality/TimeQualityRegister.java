package com.czertainly.core.signing.tsa.timequality;

import com.czertainly.api.model.messaging.timequality.TimeQualityStatus;
import com.czertainly.core.model.signing.timequality.TimeQualityConfigurationModel;

public interface TimeQualityRegister {

    TimeQualityStatus getStatus(TimeQualityConfigurationModel profile);

    void update(TimeQualityResult result);
}
