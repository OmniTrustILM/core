package com.otilm.core.intune.scepvalidation;

import com.otilm.core.dao.entity.scep.ScepProfile;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Properties;

/**
 * Factory for building the {@link Properties} object required by {@link IntuneScepServiceClient}
 * and {@link IntuneRevocationClient}.
 *
 * <p>Centralises the app-identity fields ({@code app.version}, {@code info.app.name}) so they
 * do not need to be injected separately in every caller.
 */
@Component
public class IntuneConfigProperties {

    @Value("${app.version:unknown}")
    private String appVersion;

    @Value("${info.app.name:ILM Core}")
    private String appName;

    public Properties forScepProfile(ScepProfile scepProfile) {
        Properties props = new Properties();
        props.put("AAD_APP_ID", scepProfile.getIntuneApplicationId());
        props.put("AAD_APP_KEY", scepProfile.getIntuneApplicationKey());
        props.put("TENANT", scepProfile.getIntuneTenant());
        props.put("PROVIDER_NAME_AND_VERSION", appName.replace(" ", "-") + "-V" + appVersion);
        return props;
    }
}
