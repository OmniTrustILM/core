package com.czertainly.core.messaging.model;

import com.czertainly.api.model.core.logging.enums.AuditLogOutput;
import com.czertainly.api.model.core.logging.records.*;
import lombok.*;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class AuditLogMessage {

    private LogRecord logRecord;
    private AuditLogOutput auditLogOutput;

}
