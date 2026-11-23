package com.otilm.core.security.ai;

import java.util.Map;

/** One closed role/path/method catalog for physical native connectors. */
final class CoreRuntimeRoutes {
    private CoreRuntimeRoutes() {
    }

    static Map<String, String> forRole(RuntimePeerRole role, String contextPath) {
        String runtime = contextPath + "/internal/ai-runtime/v1/";
        String management = contextPath + "/internal/ai-management/v1/";
        return switch (role) {
            case RUNNER_PROXY ->
                Map.of(runtime + "runner/bootstrap", "POST", runtime + "runner/claims/heartbeat", "POST");
            case CONTROLLER -> Map
                    .of(runtime + "controller/launches/reconcile", "POST", runtime + "controller/workloads/register",
                            "POST", runtime + "controller/workloads/status", "POST",
                            runtime + "controller/cleanup/reconcile", "POST",
                            runtime + "controller/gateways/run/observe", "POST",
                            management + "controller/gateway/observe", "POST");
            case GATEWAY_RUN -> Map
                    .of(runtime + "gateway/run/registration", "GET", runtime + "gateway/run/redeem", "POST",
                            runtime + "gateway/run/outcomes", "POST");
            case GATEWAY_MANAGEMENT -> Map
                    .of(management + "gateway/registration", "GET", management + "gateway/redeem", "POST",
                            management + "gateway/outcomes", "POST");
        };
    }
}
