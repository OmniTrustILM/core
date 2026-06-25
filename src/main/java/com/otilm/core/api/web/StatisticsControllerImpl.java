package com.otilm.core.api.web;

import com.otilm.api.interfaces.core.web.StatisticsController;
import com.otilm.api.model.client.dashboard.SigningRecordStatisticsDto;
import com.otilm.api.model.client.dashboard.SigningRecordStatisticsPeriod;
import com.otilm.api.model.client.dashboard.StatisticsDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.SigningRecordExternalService;
import com.otilm.core.service.StatisticsExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatisticsControllerImpl implements StatisticsController {

	private StatisticsExternalService statisticsService;
	private SigningRecordExternalService signingRecordService;

	@Autowired
	public void setStatisticsService(StatisticsExternalService statisticsService) {
		this.statisticsService = statisticsService;
	}

	@Autowired
	public void setSigningRecordService(SigningRecordExternalService signingRecordService) {
		this.signingRecordService = signingRecordService;
	}

	@Override
	@AuditLogged(module = Module.CORE, resource = Resource.DASHBOARD, operation = Operation.STATISTICS)
	public StatisticsDto getStatistics(boolean includeArchived) {
		return statisticsService.getStatistics(includeArchived);
	}

	@Override
	@AuditLogged(module = Module.SIGNING, resource = Resource.SIGNING_RECORD, operation = Operation.STATISTICS)
	public SigningRecordStatisticsDto getSigningRecordStatistics(SigningRecordStatisticsPeriod period) {
		return signingRecordService.getSigningRecordStatistics(period, SecurityFilter.create());
	}
}
