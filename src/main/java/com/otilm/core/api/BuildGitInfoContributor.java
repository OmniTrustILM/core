package com.otilm.core.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.boot.info.GitProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Component
@Profile("!test")
public class BuildGitInfoContributor implements InfoContributor {

    private final GitProperties gitProperties;
    private final String version;

    public BuildGitInfoContributor(
            @Value("${app.version}") String version,
            @Autowired(required = false) GitProperties gitProperties) {
        this.version = version;
        this.gitProperties = gitProperties;
    }

    @Override
    public void contribute(Info.Builder builder) {
        if (version != null && gitProperties != null) {
            Map<String, Object> gitInfo = new HashMap<>();

            String buildEpoch = gitProperties.get("build.time");
            if (buildEpoch != null) {
                try {
                    gitInfo.put("timestamp", Instant.ofEpochMilli(Long.parseLong(buildEpoch)));
                } catch (NumberFormatException var4) {
                    // Ignore invalid build time format
                }
            }

            if (version.contains("SNAPSHOT")) {
                gitInfo.put("commitId", gitProperties.getShortCommitId());
                gitInfo.put("branch", gitProperties.getBranch());
            }

            builder.withDetail("build", gitInfo);
        }
    }
}
