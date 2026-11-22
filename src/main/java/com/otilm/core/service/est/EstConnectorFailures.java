package com.otilm.core.service.est;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import java.util.ArrayList;
import java.util.List;
import org.springframework.web.reactive.function.client.WebClientException;

/**
 * Tells a failure that came from calling a connector, whose text must not be logged: the request carries the
 * credentials of the authority, what the connector reports can echo them, and the client's message about an answer it
 * cannot decode quotes that answer. Only the classes of such a failure are logged.
 */
public final class EstConnectorFailures {

    private static final int MAX_CAUSES = 16;

    private EstConnectorFailures() {
    }

    /**
     * @param failure the failure, which may be {@code null}
     * @return whether the failure or one of its causes is a connector, validation or web client exception
     */
    public static boolean isConnectorFailure(Throwable failure) {
        Throwable current = failure;
        for (int depth = 0; current != null && depth < MAX_CAUSES; depth++) {
            if (current instanceof ConnectorException || current instanceof ValidationException
                    || current instanceof WebClientException) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    /**
     * @param failure the failure
     * @return the class names of the failure and its causes, outermost first, without any message
     */
    public static String classNames(Throwable failure) {
        List<String> names = new ArrayList<>();
        Throwable current = failure;
        for (int depth = 0; current != null && depth < MAX_CAUSES; depth++) {
            names.add(current.getClass().getName());
            current = current.getCause();
        }
        return String.join(" <- ", names);
    }
}
