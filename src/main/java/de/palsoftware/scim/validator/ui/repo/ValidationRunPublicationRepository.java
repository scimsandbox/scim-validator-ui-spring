package de.palsoftware.scim.validator.ui.repo;

import de.palsoftware.scim.validator.ui.model.ValidationRunPublication;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ValidationRunPublicationRepository extends JpaRepository<ValidationRunPublication, UUID> {

    /**
     * Count published runs for a given email (Spring Data derived query).
     */
    long countByCreatedByEmail(String email);

    /**
     * Count published runs with case-insensitive email match.
     */
    long countByCreatedByEmailIgnoreCase(String email);

    /**
     * Find all publications created by an email ordered by publication date descending.
     */
    List<ValidationRunPublication> findByCreatedByEmailOrderByPublishedAtDesc(String email);

    /**
     * Find all publications created by an email ordered by publication date descending (case-insensitive).
     */
    List<ValidationRunPublication> findByCreatedByEmailIgnoreCaseOrderByPublishedAtDesc(String email);

    /**
     * Query published runs owned by user with dynamic sorting (excluding pending reservations).
     */
    @Query("""
        select p from ValidationRunPublication p
        where lower(p.createdByEmail) = lower(:actorEmail)
          and (p.prUrl is null or p.prUrl <> 'PENDING_RESERVATION')
        """)
    List<ValidationRunPublication> findOwnedPublications(@Param("actorEmail") String actorEmail, Sort sort);

    /**
     * Query count of published runs owned by user (excluding pending reservations).
     */
    @Query("""
        select count(p) from ValidationRunPublication p
        where lower(p.createdByEmail) = lower(:actorEmail)
          and (p.prUrl is null or p.prUrl <> 'PENDING_RESERVATION')
        """)
    long countOwnedPublications(@Param("actorEmail") String actorEmail);

    /**
     * Find pending reservations older than or equal to the specified cutoff timestamp.
     */
    @Query("""
        select p from ValidationRunPublication p
        where p.prUrl = :pendingStatus
          and p.publishedAt <= :cutoff
        """)
    List<ValidationRunPublication> findStalePendingReservations(
            @Param("pendingStatus") String pendingStatus,
            @Param("cutoff") java.time.OffsetDateTime cutoff);

    default List<ValidationRunPublication> findStalePendingReservations(java.time.OffsetDateTime cutoff) {
        return findStalePendingReservations(ValidationRunPublication.PENDING_RESERVATION_PR_URL, cutoff);
    }

    /**
     * Conditionally delete a pending reservation only if it is still in pending state and older than cutoff.
     */
    @Modifying
    @Query("""
        delete from ValidationRunPublication p
        where p.runId = :runId
          and p.prUrl = :pendingStatus
          and p.publishedAt <= :cutoff
        """)
    default int deleteStalePendingReservationById(
            @Param("runId") UUID runId,
            @Param("pendingStatus") String pendingStatus,
            @Param("cutoff") java.time.OffsetDateTime cutoff) {
        Optional<ValidationRunPublication> existing = findById(runId);
        if (existing.isPresent()
                && pendingStatus.equals(existing.get().getPrUrl())
                && (existing.get().getPublishedAt() == null || !existing.get().getPublishedAt().isAfter(cutoff))) {
            deleteById(runId);
            return 1;
        }
        return 0;
    }

    /**
     * Find all publications for a product slug ordered by publication date descending (uses idx_validation_run_publication_slug_version).
     */
    List<ValidationRunPublication> findByProductSlugIgnoreCaseOrderByPublishedAtDesc(String productSlug);

    /**
     * Convenience lookup by runId (delegating to findById since runId is the @Id).
     */
    default Optional<ValidationRunPublication> findByRunId(UUID runId) {
        return findById(runId);
    }
}
