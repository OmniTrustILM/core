package com.otilm.core.service.est.message;

import com.otilm.api.model.core.est.EstMediaTypes;
import com.otilm.api.model.core.est.EstPaths;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpMethod;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;

/**
 * The checks an EST request passes before it is dispatched. They need only its method, its path, its content type and
 * its declared length. They run before dispatch because Spring answers a wrong method or content type itself, before an
 * EST advice could write the refusal.
 */
public final class EstRequestGuard {

    /**
     * The largest request body in bytes. A request is base64 text, and 128 KiB leaves room for one signed with SLH-DSA,
     * whose signature alone is up to about 50 KB before base64 encoding.
     */
    public static final int MAX_BODY_BYTES = 131_072;

    private static final String GET = HttpMethod.GET.name();
    private static final String POST = HttpMethod.POST.name();
    private static final Map<String, String> METHOD_OF_OPERATION = Map
            .of(EstPaths.CACERTS, GET, EstPaths.CSRATTRS, GET, EstPaths.SIMPLE_ENROLL, POST, EstPaths.SIMPLE_REENROLL,
                    POST, EstPaths.SERVER_KEYGEN, POST);
    private static final MediaType PKCS10 = MediaType.parseMediaType(EstMediaTypes.PKCS10);

    private EstRequestGuard() {
    }

    /**
     * Applies these rules in order and returns the first refusal:
     * <ol>
     * <li>the path is an operation, with or without a label before it, else {@link EstError#NOT_FOUND};</li>
     * <li>the method is the one the operation takes, else {@link EstError#METHOD_NOT_ALLOWED};</li>
     * <li>a POST carries {@code application/pkcs10}, whatever its parameters and letter case, else
     * {@link EstError#UNSUPPORTED_MEDIA_TYPE};</li>
     * <li>the declared length is within {@link #MAX_BODY_BYTES}, else {@link EstError#PAYLOAD_TOO_LARGE}.</li>
     * </ol>
     * The label is not checked here, the route resolver does that.
     *
     * @param method the HTTP method
     * @param operationPath the request path after {@code /.well-known/est/}
     * @param contentType the {@code Content-Type} header, {@code null} when the request has none
     * @param contentLength the declared body length, {@code -1} when it is not known, as with a chunked body, which
     * {@link EstBoundedRequest} limits while it is read
     * @return the refusal, empty when the request is admitted
     */
    public static Optional<EstError> check(String method, String operationPath, String contentType,
            long contentLength) {
        String allowed = allowedMethod(operationPath);
        if (allowed == null) {
            return Optional.of(EstError.NOT_FOUND);
        }
        if (!allowed.equals(method)) {
            return Optional.of(EstError.METHOD_NOT_ALLOWED);
        }
        if (POST.equals(method) && !isPkcs10(contentType)) {
            return Optional.of(EstError.UNSUPPORTED_MEDIA_TYPE);
        }
        if (contentLength > MAX_BODY_BYTES) {
            return Optional.of(EstError.PAYLOAD_TOO_LARGE);
        }
        return Optional.empty();
    }

    /**
     * @param operationPath the request path after {@code /.well-known/est/}
     * @return the only method the operation takes, {@code null} when the path is not an operation
     */
    public static String allowedMethod(String operationPath) {
        String[] segments = operationPath.split("/", -1);
        boolean withoutLabel = segments.length == 1;
        boolean withLabel = segments.length == 2 && !segments[0].isEmpty();
        return withoutLabel || withLabel ? METHOD_OF_OPERATION.get(segments[segments.length - 1]) : null;
    }

    private static boolean isPkcs10(String contentType) {
        if (contentType == null) {
            return false;
        }
        try {
            return PKCS10.equalsTypeAndSubtype(MediaType.parseMediaType(contentType));
        } catch (InvalidMediaTypeException e) {
            return false;
        }
    }
}
