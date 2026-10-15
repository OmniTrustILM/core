package com.otilm.core.api;

import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.core.logging.LogRedaction;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

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

    @Pointcut("within(com.otilm.core.api..*)")
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
        log.trace("Entering in method {} with arguments {}", path, formatArguments(joinPoint));
        long start = System.currentTimeMillis();
        try {
            Object result = joinPoint.proceed();
            log.trace("Method {} result: {}", path, getValue(result));
            return result;
        } catch (AcmeProblemDocumentException | ValidationException | AlreadyExistException e) {
            log
                    .error(e.getClass().getSimpleName() + " when calling " + path + " Exception: "
                            + e.getLocalizedMessage());
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
                returnValue = result.getClass().getSimpleName();
            } else {
                returnValue = result.toString();
            }
        }
        return returnValue;
    }

    /**
     * No argument or result is ever serialized: an argument whose parameter is {@link Sensitive} logs as {@code ***},
     * every other argument logs by {@code String.valueOf}, and a result logs by its own {@code toString()}, or its
     * simple class name when it has Object's default one.
     */
    private static String formatArguments(ProceedingJoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Parameter[] parameters = signature.getMethod().getParameters();
        Object[] args = joinPoint.getArgs();
        String[] formatted = new String[args.length];
        for (int i = 0; i < args.length; i++) {
            formatted[i] = i < parameters.length && parameters[i].isAnnotationPresent(Sensitive.class)
                    ? LogRedaction.REDACTED
                    : String.valueOf(args[i]);
        }
        return Arrays.toString(formatted);
    }
}
