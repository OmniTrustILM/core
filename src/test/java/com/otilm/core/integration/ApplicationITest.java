package com.otilm.core.integration;

import org.junit.jupiter.api.Test;
import org.quartz.Scheduler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class ApplicationITest {

    @Autowired
    private ApplicationContext applicationContext;

    @Test
    void contextLoads() {
    }

    /** See {@link com.otilm.core.Application}. */
    @Test
    void doesNotStartAQuartzScheduler() {
        assertEquals(0, applicationContext.getBeanNamesForType(Scheduler.class).length);
    }

}
