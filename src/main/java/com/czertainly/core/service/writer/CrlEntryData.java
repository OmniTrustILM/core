package com.czertainly.core.service.writer;

import java.util.Date;

public record CrlEntryData(String serialNumber, Date revocationDate, String revocationReason) {
}
