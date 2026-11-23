package com.otilm.core.service.ai;

import com.otilm.api.exception.PlatformException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/** Bounds servlet input without taking ownership of the container's stream. */
final class AiRuntimeRequestBody {
    private static final int MAXIMUM = 1_500_000;

    private AiRuntimeRequestBody() {
    }

    static byte[] read(InputStream body, int maximum, AiRuntimeOperationBudget budget) throws IOException {
        if (body == null || budget == null || maximum <= 0 || maximum > MAXIMUM) {
            throw new IllegalArgumentException("Runtime request body limits are invalid");
        }
        byte[] bytes = new byte[maximum + 1];
        int size = 0;
        while (size < bytes.length) {
            budget.remaining();
            int count = body.read(bytes, size, bytes.length - size);
            budget.remaining();
            if (count < 0) {
                return Arrays.copyOf(bytes, size);
            }
            if (count == 0) {
                int value = body.read();
                budget.remaining();
                if (value < 0) {
                    return Arrays.copyOf(bytes, size);
                }
                bytes[size++] = (byte) value;
            } else {
                size += count;
            }
        }
        throw new LimitExceeded();
    }

    static final class LimitExceeded extends RuntimeException implements PlatformException {
        private static final long serialVersionUID = 1L;

        private LimitExceeded() {
            super("Runtime request body exceeds the limit", null, false, false);
        }
    }
}
