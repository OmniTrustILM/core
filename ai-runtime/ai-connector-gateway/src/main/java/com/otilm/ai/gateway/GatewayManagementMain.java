package com.otilm.ai.gateway;

/** Fixed finite management probe; actual actor/session/CONNECT authority remains in Core. */
public final class GatewayManagementMain {
    private GatewayManagementMain() {
    }

    public static void main(String[] arguments) {
        GatewayRunMain.run(arguments, System.nanoTime(), GatewayRun.Audience.MANAGEMENT);
    }
}
