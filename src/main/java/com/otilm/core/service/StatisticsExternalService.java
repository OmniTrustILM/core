package com.otilm.core.service;

import com.otilm.api.model.client.dashboard.StatisticsDto;

public interface StatisticsExternalService {
    StatisticsDto getStatistics(boolean includeArchived);
}
