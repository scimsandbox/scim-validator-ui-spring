package de.palsoftware.scim.validator.ui.repo;

import de.palsoftware.scim.validator.ui.model.ValidationHttpExchange;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface ValidationHttpExchangeRepository extends JpaRepository<ValidationHttpExchange, UUID> {

    List<ValidationHttpExchange> findByTestResultIdOrderBySequenceNumberAsc(UUID testResultId);

    @Query("select e from ValidationHttpExchange e where e.run.id = :runId and e.url like '%/ServiceProviderConfig%' order by e.sequenceNumber asc")
    List<ValidationHttpExchange> findServiceProviderConfigExchangesByRunId(@Param("runId") UUID runId);
}
