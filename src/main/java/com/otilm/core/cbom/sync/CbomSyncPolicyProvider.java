package com.otilm.core.cbom.sync;

import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.settings.SettingsCache;
import org.springframework.stereotype.Component;

/**
 * Hands out the CBOM sync policy as the settings cache holds it now.
 *
 * <p>
 * A collaborator rather than a static read, so that the services that depend on a tunable take it as a dependency and
 * can be unit-tested against a policy that changes between calls -- which is the property core#2268 is about: an
 * operator's edit reaches a running node when its cache next refreshes, with no restart. The alternative, reading the
 * static cache from inside each service, would make that property assertable only through a Spring context.
 *
 * <p>
 * Callers ask once where their work starts and carry the answer: a sync run snapshots it for the whole run, a
 * withdrawal for the whole withdrawal. Nothing re-reads it mid-unit, so a refresh cannot apply to half of one.
 */
@Component
public class CbomSyncPolicyProvider {

    /** The cache is empty before the platform settings were ever read, which reads as "all defaults". */
    public CbomSyncPolicy current() {
        PlatformSettingsDto platform = SettingsCache.getSettings(SettingsSection.PLATFORM);
        return CbomSyncPolicy.fromSettings(platform == null ? null : platform.getUtils());
    }
}
