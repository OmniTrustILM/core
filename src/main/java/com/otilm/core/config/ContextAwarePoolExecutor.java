package com.otilm.core.config;

import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.concurrent.DelegatingSecurityContextCallable;
import org.springframework.util.concurrent.ListenableFuture;
import org.springframework.web.context.request.RequestContextHolder;

import java.util.concurrent.Callable;
import java.util.concurrent.Future;

public class ContextAwarePoolExecutor extends ThreadPoolTaskExecutor {
    @Override
    public <T> Future<T> submit(Callable<T> task) {
        return super.submit(new DelegatingSecurityContextCallable(new ContextAwareCallable(task, RequestContextHolder.currentRequestAttributes())));
    }

    @Override
    public <T> ListenableFuture<T> submitListenable(Callable<T> task) {
        return super.submitListenable(new DelegatingSecurityContextCallable(new ContextAwareCallable(task, RequestContextHolder.currentRequestAttributes())));
    }
}
