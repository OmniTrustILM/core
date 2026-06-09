package com.otilm.core.api;

import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.ValidationException;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Aspect
@Component
public class LoggingAdvice {

    Logger log = LoggerFactory.getLogger(this.getClass());

    @Pointcut("within(@org.springframework.stereotype.Controller *)")
    public void controller() {
    }

    @Pointcut("within(@org.springframework.web.bind.annotation.RestController *)")
    public void restController() {
    }

    @Pointcut("execution(* *.*(..))")
    protected void allMethod() {
    }

    @Pointcut("execution(public * *(..))")
    protected void loggingPublicOperation() {
    }

    @Pointcut("execution(* *.*(..))")
    protected void loggingAllOperation() {
    }

    @Pointcut("within(com.czertainly.core.api..*)")
    private void logAnyFunctionWithinResource() {
    }

    @Around("logAnyFunctionWithinResource() && (restController() || controller()) && loggingPublicOperation()")
    public Object logAround(ProceedingJoinPoint joinPoint) throws Throwable {

        String className = joinPoint.getSignature().getDeclaringTypeName();
        String methodName = joinPoint.getSignature().getName();
        String path = className + "." + methodName + "()";
        if (!log.isTraceEnabled()) {
            return joinPoint.proceed();
        }
        log.trace("Entering in method {} with arguments {}", path, Arrays.toString(joinPoint.getArgs()));
        long start = System.currentTimeMillis();
        try {
            Object result = joinPoint.proceed();
            log.trace("Method {} result: {}", path, getValue(result));
            return result;
        } catch (AcmeProblemDocumentException | ValidationException | AlreadyExistException e) {
            log.error(e.getClass().getSimpleName() + " when calling " + path + " Exception: " + e.getLocalizedMessage());
            throw e;
        } catch (Exception e) {
            log.error("Exception when calling " + path, e);
            throw e;
        } finally {
            long elapsedTime = System.currentTimeMillis() - start;
            log.trace("Method {} execution time: {} ms", path, elapsedTime);
        }
    }

    private String getValue(Object result) {
        String returnValue = null;
        if (null != result) {
            if (result.toString().endsWith("@" + Integer.toHexString(result.hashCode()))) {
                returnValue = ReflectionToStringBuilder.toString(result);
            } else {
                returnValue = result.toString();
            }
        }
        return returnValue;
    }
}
