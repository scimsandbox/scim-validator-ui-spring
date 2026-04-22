package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.ui.model.ValidationMgmtUser;
import de.palsoftware.scim.validator.ui.repo.ValidationMgmtUserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MgmtUserServiceTest {

    @Mock
    private ValidationMgmtUserRepository mgmtUserRepository;

    @InjectMocks
    private MgmtUserService mgmtUserService;

    @Test
    void provisionUser_newUser_createsWithNormalizedEmailAndTimestamp() {
        when(mgmtUserRepository.findById("user@example.com")).thenReturn(Optional.empty());
        when(mgmtUserRepository.save(any(ValidationMgmtUser.class))).thenAnswer(i -> i.getArgument(0));

        mgmtUserService.provisionUser(" User@Example.com ");

        verify(mgmtUserRepository).save(argThat(user ->
                "user@example.com".equals(user.getEmail()) &&
                user.getLastLoginAt() != null));
    }

    @Test
    void provisionUser_existingUser_updatesLoginTime() {
        ValidationMgmtUser existing = new ValidationMgmtUser("user@example.com",
                OffsetDateTime.of(2025, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC));
        when(mgmtUserRepository.findById("user@example.com")).thenReturn(Optional.of(existing));
        when(mgmtUserRepository.save(any(ValidationMgmtUser.class))).thenAnswer(i -> i.getArgument(0));

        mgmtUserService.provisionUser("USER@example.com");

        verify(mgmtUserRepository).save(argThat(user -> "user@example.com".equals(user.getEmail()) &&
                user.getLastLoginAt().isAfter(
                        OffsetDateTime.of(2025, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC))));
    }

    @Test
    void provisionUser_missingEmail_throws() {
        assertThatThrownBy(() -> mgmtUserService.provisionUser("not-an-email"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("email is required");
    }

    @Test
    void resolveDisplayName_nullSub_returnsFallback() {
        String result = mgmtUserService.resolveDisplayName(null, "fallback-name");

        assertThat(result).isEqualTo("fallback-name");
    }

    @Test
    void resolveDisplayName_blankEmail_returnsFallback() {
        String result = mgmtUserService.resolveDisplayName("   ", "fallback-name");

        assertThat(result).isEqualTo("fallback-name");
    }

    @Test
    void resolveDisplayName_userNotFound_returnsFallback() {
        when(mgmtUserRepository.findById("missing@example.com")).thenReturn(Optional.empty());

        String result = mgmtUserService.resolveDisplayName("missing@example.com", "fallback-name");

        assertThat(result).isEqualTo("fallback-name");
    }

    @Test
    void resolveDisplayName_userWithEmail_returnsStoredEmail() {
        ValidationMgmtUser user = new ValidationMgmtUser("user@example.com", OffsetDateTime.now(ZoneOffset.UTC));
        when(mgmtUserRepository.findById("user@example.com")).thenReturn(Optional.of(user));

        String result = mgmtUserService.resolveDisplayName("USER@example.com", "fallback-name");

        assertThat(result).isEqualTo("user@example.com");
    }
}
