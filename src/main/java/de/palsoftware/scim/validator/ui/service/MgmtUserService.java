package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.ui.model.ValidationMgmtUser;
import de.palsoftware.scim.validator.ui.repo.ValidationMgmtUserRepository;
import de.palsoftware.scim.validator.ui.security.AuthenticatedUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

@Service
public class MgmtUserService {

    private final ValidationMgmtUserRepository mgmtUserRepository;

    public MgmtUserService(ValidationMgmtUserRepository mgmtUserRepository) {
        this.mgmtUserRepository = mgmtUserRepository;
    }

    @Transactional
    public void provisionUser(String email) {
        String normalizedEmail = requireEmail(email);
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        ValidationMgmtUser user = mgmtUserRepository.findById(normalizedEmail)
                .orElseGet(() -> new ValidationMgmtUser(normalizedEmail, now));
        user.setEmail(normalizedEmail);
        user.setLastLoginAt(now);
        mgmtUserRepository.save(user);
    }

    @Transactional(readOnly = true)
    public String resolveDisplayName(String email, String fallbackDisplayName) {
        String normalizedEmail = AuthenticatedUser.normalizeEmail(email);
        if (normalizedEmail == null) {
            return fallbackDisplayName;
        }
        return mgmtUserRepository.findById(normalizedEmail)
                .map(ValidationMgmtUser::getEmail)
            .filter(storedEmail -> storedEmail != null && !storedEmail.isBlank())
                .orElse(fallbackDisplayName);
    }

    private String requireEmail(String email) {
        String normalizedEmail = AuthenticatedUser.normalizeEmail(email);
        if (normalizedEmail == null) {
            throw new IllegalArgumentException("Management user email is required");
        }
        return normalizedEmail;
    }
}
