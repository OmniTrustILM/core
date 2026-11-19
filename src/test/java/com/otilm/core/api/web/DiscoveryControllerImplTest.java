package com.otilm.core.api.web;

import com.otilm.api.model.client.discovery.DiscoveryDto;
import com.otilm.api.model.core.scheduler.ScheduleDiscoveryDto;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.service.SchedulerExternalService;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class DiscoveryControllerImplTest {

    private final DiscoveryExternalService discoveryService = mock(DiscoveryExternalService.class);
    private final SchedulerExternalService schedulerService = mock(SchedulerExternalService.class);
    private final DiscoveryControllerImpl controller = new DiscoveryControllerImpl();

    DiscoveryControllerImplTest() {
        controller.setDiscoveryService(discoveryService);
        controller.setSchedulerService(schedulerService);
    }

    @Test
    void createsDiscoveryAsUnscheduled_whenCreatedDirectly() throws Exception {
        // given
        var request = new DiscoveryDto();
        when(discoveryService.createDiscovery(any(DiscoveryDto.class), anyBoolean(), anyBoolean()))
                .thenThrow(new IllegalStateException("stop after creation"));

        // when
        ThrowingCallable create = () -> controller.createDiscovery(request);

        // then
        assertThatThrownBy(create).isInstanceOf(IllegalStateException.class);
        verify(discoveryService).createDiscovery(request, true, false);
    }

    @Test
    void validatesDiscoveryAsScheduled_whenScheduled() throws Exception {
        // given
        var request = new DiscoveryDto();
        var schedule = new ScheduleDiscoveryDto();
        schedule.setRequest(request);
        when(discoveryService.createDiscovery(any(DiscoveryDto.class), anyBoolean(), anyBoolean()))
                .thenThrow(new IllegalStateException("stop after validation"));

        // when
        ThrowingCallable scheduleDiscovery = () -> controller.scheduleDiscovery(schedule);

        // then
        assertThatThrownBy(scheduleDiscovery).isInstanceOf(IllegalStateException.class);
        verify(discoveryService).createDiscovery(request, false, true);
        verifyNoInteractions(schedulerService);
    }
}
