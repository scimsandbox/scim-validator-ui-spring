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
        left join run.publication pub
        where lower(run.createdByUser.email) = lower(:actorEmail)
          and (pub is null or pub.prUrl = 'PENDING_RESERVATION')
        """)
    List<ValidationRun> findOwnedRuns(@Param("actorEmail") String actorEmail, Sort sort);

    @Query("""
        select count(run) from ValidationRun run
        left join run.publication pub
        where lower(run.createdByUser.email) = lower(:actorEmail)
          and (pub is null or pub.prUrl = 'PENDING_RESERVATION')
        """)
    long countOwnedRuns(@Param("actorEmail") String actorEmail);

    @Query("""
        select run from ValidationRun run
        where run.id = :id
          and lower(run.createdByUser.email) = lower(:actorEmail)
        """)
    Optional<ValidationRun> findAccessibleById(@Param("id") UUID id,
                                              @Param("actorEmail") String actorEmail);
}
