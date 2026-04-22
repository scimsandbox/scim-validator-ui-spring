package de.palsoftware.scim.validator.ui.repo;

import de.palsoftware.scim.validator.ui.model.ValidationMgmtUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ValidationMgmtUserRepository extends JpaRepository<ValidationMgmtUser, String> {
}
