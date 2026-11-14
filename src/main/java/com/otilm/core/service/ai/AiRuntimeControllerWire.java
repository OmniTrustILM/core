package com.otilm.core.service.ai;

import com.otilm.ai.controller.ControllerWire;
import com.otilm.api.exception.PlatformException;
import java.util.UUID;

/** Fixed physical routes select only their closed operations; decoded metadata grants no authority. */
final class AiRuntimeControllerWire {
    private AiRuntimeControllerWire() {
    }

    enum Route {
        RECONCILE,
        REGISTER,
        STATUS,
        CLEANUP
    }

    enum Kind {
        LAUNCH,
        ELIGIBLE,
        REGISTER,
        STATUS,
        RESUME,
        FENCE,
        TERMINAL,
        CLEANUP
    }

    record Request(Kind kind, ControllerWire.Locator locator, UUID podUid, ControllerWire.Control expected) {
    }

    static Request read(byte[] body, Route route) {
        if (route == null) {
            throw new Invalid();
        }
        try {
            return switch (route) {
                case RECONCILE -> reconcile(body);
                case REGISTER -> observation(body, ControllerWire.Operation.REGISTER, Kind.REGISTER);
                case STATUS -> status(body);
                case CLEANUP -> cleanup(body);
            };
        } catch (RuntimeException invalid) {
            throw new Invalid();
        }
    }

    private static Request reconcile(byte[] body) {
        try {
            return new Request(Kind.LAUNCH, ControllerWire.readLaunchRequest(body), null, null);
        } catch (RuntimeException invalidLaunch) {
            return observation(body, ControllerWire.Operation.ELIGIBLE, Kind.ELIGIBLE);
        }
    }

    private static Request observation(byte[] body, ControllerWire.Operation operation, Kind kind) {
        var request = ControllerWire.readObservationRequest(body, operation);
        return new Request(kind, request.locator(), request.podUid(), null);
    }

    private static Request status(byte[] body) {
        try {
            return new Request(Kind.RESUME, ControllerWire.readCleanupResumeRequest(body), null, null);
        } catch (RuntimeException invalidResume) {
            try {
                return control(body, ControllerWire.ControlOperation.STATUS, Kind.STATUS);
            } catch (RuntimeException invalidStatus) {
                return control(body, ControllerWire.ControlOperation.TERMINAL, Kind.TERMINAL);
            }
        }
    }

    private static Request cleanup(byte[] body) {
        try {
            return control(body, ControllerWire.ControlOperation.FENCE, Kind.FENCE);
        } catch (RuntimeException invalidFence) {
            return control(body, ControllerWire.ControlOperation.CLEANUP, Kind.CLEANUP);
        }
    }

    private static Request control(byte[] body, ControllerWire.ControlOperation operation, Kind kind) {
        var request = ControllerWire.readControlRequest(body, operation);
        return new Request(kind, request.locator(), null, request.expected());
    }

    static final class Invalid extends RuntimeException implements PlatformException {
        Invalid() {
            super("INVALID_CONTROLLER_METADATA", null, false, false);
        }
    }
}
