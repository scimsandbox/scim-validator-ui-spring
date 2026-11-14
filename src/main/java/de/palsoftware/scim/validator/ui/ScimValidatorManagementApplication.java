package de.palsoftware.scim.validator.ui;

import de.palsoftware.scim.validator.ui.security.PinnedTargetHttpSupport;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.security.Security;

@SpringBootApplication
@EnableScheduling
public class ScimValidatorManagementApplication {

    static {
        Security.setProperty("networkaddress.cache.ttl", "0");
        Security.setProperty("networkaddress.cache.negative.ttl", "0");
    }

    public static void main(String[] args) {
        PinnedTargetHttpSupport.initializeJvmDnsPinning();
        SpringApplication.run(ScimValidatorManagementApplication.class, args);
    }
}
