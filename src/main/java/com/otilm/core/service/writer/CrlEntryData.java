package com.otilm.core.service.writer;

import java.util.Date;

public record CrlEntryData(String serialNumber, Date revocationDate, String revocationReason) {
}
