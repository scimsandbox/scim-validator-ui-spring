package de.palsoftware.scim.validator.ui.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.OffsetDateTime;

@Entity
@Table(name = "validator_mgmt_users")
public class ValidationMgmtUser {

    @Id
    @Column(length = 500, nullable = false)
    private String email;

    @Column(name = "last_login_at", columnDefinition = "TIMESTAMP WITH TIME ZONE", nullable = false)
    private OffsetDateTime lastLoginAt;

    public ValidationMgmtUser() {
    }

    public ValidationMgmtUser(String email, OffsetDateTime lastLoginAt) {
        this.email = email;
        this.lastLoginAt = lastLoginAt;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public OffsetDateTime getLastLoginAt() {
        return lastLoginAt;
    }

    public void setLastLoginAt(OffsetDateTime lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }
}
