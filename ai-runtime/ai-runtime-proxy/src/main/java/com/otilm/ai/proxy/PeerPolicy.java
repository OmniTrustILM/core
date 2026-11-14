package com.otilm.ai.proxy;

import java.io.IOException;
import java.nio.channels.SocketChannel;
import java.nio.file.FileSystems;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.util.Objects;
import jdk.net.ExtendedSocketOptions;

/** Checks kernel peer principals. Native runtime support and deployed identity remain separate proofs. */
public final class PeerPolicy {
    private final UserPrincipal expectedUser;
    private final GroupPrincipal expectedGroup;

    PeerPolicy(UserPrincipal expectedUser, GroupPrincipal expectedGroup) {
        this.expectedUser = Objects.requireNonNull(expectedUser);
        this.expectedGroup = Objects.requireNonNull(expectedGroup);
    }

    /**
     * Requires an immutable trusted account/NSS mapping where the numeric lookup resolves UID and GID 65532. The public
     * API exposes principal objects, not raw numeric IDs; native qualification must establish that mapping and
     * SO_PEERCRED support in the deployed runtime. The qualified image must reject numeric-named aliases and dynamic or
     * unqualified name services.
     */
    public static PeerPolicy fixedRunner() throws IOException {
        var lookup = FileSystems.getDefault().getUserPrincipalLookupService();
        return new PeerPolicy(lookup.lookupPrincipalByName("65532"), lookup.lookupPrincipalByGroupName("65532"));
    }

    java.nio.file.attribute.GroupPrincipal socketGroup() {
        return expectedGroup;
    }

    public boolean allowed(SocketChannel channel) {
        try {
            if (channel == null || !channel.isConnected()
                    || !channel.supportedOptions().contains(ExtendedSocketOptions.SO_PEERCRED)) {
                return false;
            }
            var credentials = channel.getOption(ExtendedSocketOptions.SO_PEERCRED);
            return credentials != null && expectedUser.equals(credentials.user())
                    && expectedGroup.equals(credentials.group());
        } catch (IOException | RuntimeException unavailable) {
            return false;
        }
    }
}
