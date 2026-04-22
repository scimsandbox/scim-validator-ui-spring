package de.palsoftware.scim.validator.ui.repo;

import de.palsoftware.scim.validator.ui.model.ValidationRun;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ValidationRunRepository extends JpaRepository<ValidationRun, UUID> {
    @Query("""
        select run from ValidationRun run
        where run.createdByUser.email = :actorEmail
        """)
    List<ValidationRun> findOwnedRuns(@Param("actorEmail") String actorEmail, Sort sort);

    @Query("""
        select run from ValidationRun run
        where run.id = :id
          and run.createdByUser.email = :actorEmail
        """)
    Optional<ValidationRun> findAccessibleById(@Param("id") UUID id,
                                              @Param("actorEmail") String actorEmail);
}
