package de.palsoftware.scim.validator.ui;

import de.palsoftware.scim.validator.ui.security.PinnedTargetHttpSupport;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class ScimValidatorManagementApplication {

    public static void main(String[] args) {
        PinnedTargetHttpSupport.initializeJvmDnsPinning();
        SpringApplication.run(ScimValidatorManagementApplication.class, args);
    }
}
