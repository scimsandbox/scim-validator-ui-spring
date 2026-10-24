package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.ui.dto.ValidationRunForm;
import de.palsoftware.scim.validator.ui.model.ValidationMgmtUser;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationRunPublication;
import de.palsoftware.scim.validator.ui.repo.ValidationMgmtUserRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationRunPublicationRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationRunRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestExecutionListener;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.repository.query.FluentQuery;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.lang.reflect.Field;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ValidationRunServiceRetentionTest {

    private InMemoryRunRepository runRepository;
    private InMemoryPublicationRepository publicationRepository;
    private InMemoryUserRepository userRepository;
    private TestableValidationRunService service;

    private static final String USER_EMAIL = "developer@example.com";
    private static final String ADMIN_EMAIL = "admin@example.com";
    private ValidationMgmtUser testUser;

    @BeforeEach
    void setUp() {
        runRepository = new InMemoryRunRepository();
        publicationRepository = new InMemoryPublicationRepository();
        userRepository = new InMemoryUserRepository();

        testUser = new ValidationMgmtUser(USER_EMAIL, OffsetDateTime.now());
        userRepository.save(testUser);
        userRepository.save(new ValidationMgmtUser(ADMIN_EMAIL, OffsetDateTime.now()));

        service = new TestableValidationRunService(runRepository, userRepository, publicationRepository);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tier 1: Core Feature Tests (F2-T1)
    // ─────────────────────────────────────────────────────────────────────────
    @Nested
    @DisplayName("Tier 1: Feature Tests")
    class Tier1FeatureTests {

        @Test
        @DisplayName("F2-T1-1: Under 10 unpublished runs does not trigger auto-pruning")
        void executeRun_under10Unpublished_noPruning() {
            createUnpublishedRuns(5);

            ValidationRunService.ExecutionResult result = service.executeRun(
                    new ValidationRunForm("Run 6", "https://scim.example.com/v2", "token"), USER_EMAIL);

            assertThat(result.isOldRunDeleted()).isFalse();
            assertThat(runRepository.findOwnedRuns(USER_EMAIL, Sort.unsorted())).hasSize(6);
        }

        @Test
        @DisplayName("F2-T1-2: Exactly 10 unpublished runs auto-prunes oldest unpublished run")
        void executeRun_at10Unpublished_prunesOldestUnpublished() {
            List<ValidationRun> runs = createUnpublishedRuns(10);
            UUID oldestId = runs.get(0).getId();

            ValidationRunService.ExecutionResult result = service.executeRun(
                    new ValidationRunForm("Run 11", "https://scim.example.com/v2", "token"), USER_EMAIL);

            assertThat(result.isOldRunDeleted()).isTrue();
            assertThat(runRepository.findById(oldestId)).isEmpty();
            assertThat(runRepository.findOwnedRuns(USER_EMAIL, Sort.unsorted())).hasSize(10);
        }

        @Test
        @DisplayName("F2-T1-3: Published runs are NEVER auto-pruned when starting 11th run")
        void executeRun_withPublishedRuns_neverPrunesPublished() {
            List<ValidationRun> unpublished = createUnpublishedRuns(10);
            UUID oldestUnpublishedId = unpublished.get(0).getId();

            ValidationRun publishedRun = createPublishedRun("Published Run 1");
            UUID publishedRunId = publishedRun.getId();

            ValidationRunService.ExecutionResult result = service.executeRun(
                    new ValidationRunForm("Run 11", "https://scim.example.com/v2", "token"), USER_EMAIL);

            assertThat(result.isOldRunDeleted()).isTrue();
            // Oldest unpublished is deleted
            assertThat(runRepository.findById(oldestUnpublishedId)).isEmpty();
            // Published run is completely untouched
            assertThat(runRepository.findById(publishedRunId)).isPresent();
            assertThat(publicationRepository.findById(publishedRunId)).isPresent();
        }

        @Test
        @DisplayName("F2-T1-4: Non-admin can delete their own unpublished run")
        void deleteRun_nonAdmin_unpublished_success() {
            ValidationRun run = createRun("Draft Run", false);
            UUID runId = run.getId();

            service.deleteRun(runId, USER_EMAIL, false);

            assertThat(runRepository.findById(runId)).isEmpty();
        }

        @Test
        @DisplayName("F2-T1-5: Non-admin deleting published run is blocked with 409 Conflict")
        void deleteRun_nonAdmin_published_throws403() {
            ValidationRun run = createPublishedRun("Certified 1.0");
            UUID runId = run.getId();

            assertThatThrownBy(() -> service.deleteRun(runId, USER_EMAIL, false))
                    .isInstanceOf(ResponseStatusException.class)
                    .satisfies(ex -> {
                        ResponseStatusException rse = (ResponseStatusException) ex;
                        assertThat(rse.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
                        assertThat(rse.getReason()).contains("Published");
                    });

            // Ensure run was NOT deleted
            assertThat(runRepository.findById(runId)).isPresent();
            assertThat(publicationRepository.findById(runId)).isPresent();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tier 2: Boundary Value Tests (F2-T2)
    // ─────────────────────────────────────────────────────────────────────────
    @Nested
    @DisplayName("Tier 2: Boundary Tests")
    class Tier2BoundaryTests {

        @Test
        @DisplayName("F2-T2-1: Transition from 9 to 10 unpublished runs does not prune")
        void executeRun_boundary9To10_noPruning() {
            createUnpublishedRuns(9);

            ValidationRunService.ExecutionResult result = service.executeRun(
                    new ValidationRunForm("Run 10", "https://scim.example.com/v2", "token"), USER_EMAIL);

            assertThat(result.isOldRunDeleted()).isFalse();
            assertThat(runRepository.findOwnedRuns(USER_EMAIL, Sort.unsorted())).hasSize(10);
        }

        @Test
        @DisplayName("F2-T2-2: User with 0 unpublished and 10 published runs starts 1st run without pruning")
        void executeRun_onlyPublishedRuns_noPruning() {
            for (int i = 1; i <= 10; i++) {
                createPublishedRun("Published " + i);
            }

            ValidationRunService.ExecutionResult result = service.executeRun(
                    new ValidationRunForm("New Run", "https://scim.example.com/v2", "token"), USER_EMAIL);

            assertThat(result.isOldRunDeleted()).isFalse();
            assertThat(runRepository.findOwnedRuns(USER_EMAIL, Sort.unsorted())).hasSize(1);
            assertThat(publicationRepository.countOwnedPublications(USER_EMAIL)).isEqualTo(10L);
        }

        @Test
        @DisplayName("F2-T2-3: Excess unpublished runs (12) prunes multiple to reach 10")
        void executeRun_excessUnpublished_prunesMultiple() {
            createUnpublishedRuns(12);

            ValidationRunService.ExecutionResult result = service.executeRun(
                    new ValidationRunForm("Run 13", "https://scim.example.com/v2", "token"), USER_EMAIL);

            assertThat(result.isOldRunDeleted()).isTrue();
            assertThat(runRepository.findOwnedRuns(USER_EMAIL, Sort.unsorted())).hasSize(10);
        }

        @Test
        @DisplayName("F2-T2-4: Admin deleting a published run is also blocked with 409 Conflict")
        void deleteRun_admin_published_success() {
            ValidationRun run = createPublishedRun("Certified 1.0");
            UUID runId = run.getId();

            assertThatThrownBy(() -> service.deleteRun(runId, ADMIN_EMAIL, true))
                    .isInstanceOf(ResponseStatusException.class)
                    .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode()).isEqualTo(HttpStatus.CONFLICT));

            assertThat(runRepository.findById(runId)).isPresent();
            assertThat(publicationRepository.findById(runId)).isPresent();
        }

        @Test
        @DisplayName("F2-T2-5: Published runs cap of 50 is enforced")
        void publishQuota_at50Published_blocks51st() {
            for (int i = 1; i <= 50; i++) {
                createPublishedRun("Published " + i);
            }

            assertThat(service.countOwnedPublications(USER_EMAIL)).isEqualTo(50L);
            assertThat(service.getMaxPublishedRunsPerUser()).isEqualTo(50);

            assertThatThrownBy(() -> service.validatePublishQuota(USER_EMAIL))
                    .isInstanceOf(ResponseStatusException.class)
                    .satisfies(ex -> {
                        ResponseStatusException rse = (ResponseStatusException) ex;
                        assertThat(rse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(rse.getReason()).contains("50");
                    });
        }

        @Test
        @DisplayName("F2-T2-6: Deleting another user's run throws 404 Not Found")
        void deleteRun_wrongUser_throws404() {
            ValidationRun otherRun = createRun("Other User Run", false);
            otherRun.setCreatedByUser(new ValidationMgmtUser("stranger@example.com", OffsetDateTime.now()));

            assertThatThrownBy(() -> service.deleteRun(otherRun.getId(), USER_EMAIL, false))
                    .isInstanceOf(ResponseStatusException.class)
                    .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tier 3: Cross-Feature Interaction Tests (F2-T3)
    // ─────────────────────────────────────────────────────────────────────────
    @Nested
    @DisplayName("Tier 3: Cross-Feature Tests")
    class Tier3CrossFeatureTests {

        @Test
        @DisplayName("F2-T3-1: Publishing an unpublished run removes it from the 10-run limit")
        void lifecycle_publishThenCreateRun() {
            List<ValidationRun> runs = createUnpublishedRuns(10);
            ValidationRun runToPublish = runs.get(0);

            // Publish run #1
            ValidationRunPublication pub = new ValidationRunPublication();
            setField(pub, "runId", runToPublish.getId());
            setField(pub, "run", runToPublish);
            setField(pub, "createdByEmail", USER_EMAIL);
            setField(pub, "publishedAt", OffsetDateTime.now());
            runToPublish.setPublication(pub);
            publicationRepository.save(pub);

            // Now user has 9 unpublished runs and 1 published run
            assertThat(runRepository.findOwnedRuns(USER_EMAIL, Sort.unsorted())).hasSize(9);

            // Starting a new run should NOT prune
            ValidationRunService.ExecutionResult result = service.executeRun(
                    new ValidationRunForm("Run 11", "https://scim.example.com/v2", "token"), USER_EMAIL);

            assertThat(result.isOldRunDeleted()).isFalse();
            assertThat(runRepository.findOwnedRuns(USER_EMAIL, Sort.unsorted())).hasSize(10);
            assertThat(runRepository.findById(runToPublish.getId())).isPresent();
        }

        @Test
        @DisplayName("F2-T3-2: Deleting an unpublished run frees space for a new run without pruning")
        void lifecycle_deleteUnpublishedThenCreateRun() {
            List<ValidationRun> runs = createUnpublishedRuns(10);
            UUID run10Id = runs.get(9).getId();

            service.deleteRun(run10Id, USER_EMAIL, false);
            assertThat(runRepository.findOwnedRuns(USER_EMAIL, Sort.unsorted())).hasSize(9);

            ValidationRunService.ExecutionResult result = service.executeRun(
                    new ValidationRunForm("Run New", "https://scim.example.com/v2", "token"), USER_EMAIL);

            assertThat(result.isOldRunDeleted()).isFalse();
            assertThat(runRepository.findOwnedRuns(USER_EMAIL, Sort.unsorted())).hasSize(10);
        }

        @Test
        @DisplayName("F2-T3-3: Asynchronous execution prunes identical to synchronous")
        void asyncRun_pruningIdenticalToSync() {
            List<ValidationRun> runs = createUnpublishedRuns(10);
            UUID oldestId = runs.get(0).getId();

            ValidationRunService.ExecutionResult result = service.executeRunAsync(
                    new ValidationRunForm("Async Run 11", "https://scim.example.com/v2", "token"), USER_EMAIL);

            assertThat(result.isOldRunDeleted()).isTrue();
            assertThat(runRepository.findById(oldestId)).isEmpty();
            assertThat(runRepository.findOwnedRuns(USER_EMAIL, Sort.unsorted())).hasSize(10);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tier 4: Real-World Scenarios (TEST_INFRA Scenario 2)
    // ─────────────────────────────────────────────────────────────────────────
    @Nested
    @DisplayName("Tier 4: Real-World Scenarios")
    class Tier4RealWorldScenarioTests {

        @Test
        @DisplayName("Scenario 2: Retention Boundary Enforcement End-to-End Lifecycle")
        void scenario2_retentionBoundaryEnforcement() {
            // 1. User executes 10 validation runs
            List<ValidationRun> initialRuns = createUnpublishedRuns(10);
            assertThat(runRepository.findOwnedRuns(USER_EMAIL, Sort.unsorted())).hasSize(10);
            assertThat(publicationRepository.countOwnedPublications(USER_EMAIL)).isEqualTo(0L);

            // 2. User publishes 2 runs
            ValidationRun pubRun1 = initialRuns.get(0);
            ValidationRun pubRun2 = initialRuns.get(1);

            ValidationRunPublication p1 = new ValidationRunPublication();
            setField(p1, "runId", pubRun1.getId());
            setField(p1, "run", pubRun1);
            setField(p1, "createdByEmail", USER_EMAIL);
            setField(p1, "productName", "Test Product 1");
            setField(p1, "productSlug", "test-product-1");
            setField(p1, "productVersion", "1.0.0");
            setField(p1, "licenseType", "Apache-2.0");
            setField(p1, "reportUrl", "https://scimsandbox.net/reports/1");
            setField(p1, "badgeUrl", "https://scimsandbox.net/badges/1.svg");
            setField(p1, "publishedAt", OffsetDateTime.now().minusHours(2));
            pubRun1.setPublication(p1);
            publicationRepository.save(p1);

            ValidationRunPublication p2 = new ValidationRunPublication();
            setField(p2, "runId", pubRun2.getId());
            setField(p2, "run", pubRun2);
            setField(p2, "createdByEmail", USER_EMAIL);
            setField(p2, "productName", "Test Product 2");
            setField(p2, "productSlug", "test-product-2");
            setField(p2, "productVersion", "2.0.0");
            setField(p2, "licenseType", "MIT");
            setField(p2, "reportUrl", "https://scimsandbox.net/reports/2");
            setField(p2, "badgeUrl", "https://scimsandbox.net/badges/2.svg");
            setField(p2, "publishedAt", OffsetDateTime.now().minusHours(1));
            pubRun2.setPublication(p2);
            publicationRepository.save(p2);

            // Verify publication counts and unpublished runs
            assertThat(publicationRepository.countOwnedPublications(USER_EMAIL)).isEqualTo(2L);
            assertThat(runRepository.findOwnedRuns(USER_EMAIL, Sort.unsorted())).hasSize(8);

            // 3. User executes 2 more runs -> fills up to 10 unpublished runs without pruning
            ValidationRunService.ExecutionResult r9 = service.executeRun(
                    new ValidationRunForm("Run 9", "https://scim.example.com/v2", "token"), USER_EMAIL);
            assertThat(r9.isOldRunDeleted()).isFalse();

            ValidationRunService.ExecutionResult r10 = service.executeRun(
                    new ValidationRunForm("Run 10", "https://scim.example.com/v2", "token"), USER_EMAIL);
            assertThat(r10.isOldRunDeleted()).isFalse();
            assertThat(runRepository.findOwnedRuns(USER_EMAIL, Sort.unsorted())).hasSize(10);

            // 4. User starts 11th unpublished run -> auto-prunes oldest unpublished run (initialRuns.get(2))
            UUID oldestUnpublishedId = initialRuns.get(2).getId();
            ValidationRunService.ExecutionResult r11 = service.executeRun(
                    new ValidationRunForm("Run 11", "https://scim.example.com/v2", "token"), USER_EMAIL);
            assertThat(r11.isOldRunDeleted()).isTrue();
            assertThat(runRepository.findById(oldestUnpublishedId)).isEmpty();
            assertThat(runRepository.findOwnedRuns(USER_EMAIL, Sort.unsorted())).hasSize(10);

            // Ensure published runs are completely immune to pruning
            assertThat(runRepository.findById(pubRun1.getId())).isPresent();
            assertThat(runRepository.findById(pubRun2.getId())).isPresent();
            assertThat(publicationRepository.findById(pubRun1.getId())).isPresent();
            assertThat(publicationRepository.findById(pubRun2.getId())).isPresent();

            // 5. Non-admin user attempts deletion of published run -> 409 Conflict
            assertThatThrownBy(() -> service.deleteRun(pubRun1.getId(), USER_EMAIL, false))
                    .isInstanceOf(ResponseStatusException.class)
                    .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode()).isEqualTo(HttpStatus.CONFLICT));

            // 6. Admin user attempts deletion of published run -> also blocked with 409 Conflict
            assertThatThrownBy(() -> service.deleteRun(pubRun1.getId(), ADMIN_EMAIL, true))
                    .isInstanceOf(ResponseStatusException.class)
                    .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode()).isEqualTo(HttpStatus.CONFLICT));
            assertThat(runRepository.findById(pubRun1.getId())).isPresent();
            assertThat(publicationRepository.findById(pubRun1.getId())).isPresent();

            // pubRun2 also remains
            assertThat(runRepository.findById(pubRun2.getId())).isPresent();
            assertThat(publicationRepository.findById(pubRun2.getId())).isPresent();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers & In-Memory Test Doubles
    // ─────────────────────────────────────────────────────────────────────────

    private List<ValidationRun> createUnpublishedRuns(int count) {
        List<ValidationRun> list = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            ValidationRun run = createRun("Run " + i, false);
            run.setExecutedAt(OffsetDateTime.now().minusMinutes(count - i + 1));
            list.add(run);
        }
        return list;
    }

    private ValidationRun createPublishedRun(String name) {
        ValidationRun run = createRun(name, true);
        ValidationRunPublication pub = new ValidationRunPublication();
        setField(pub, "runId", run.getId());
        setField(pub, "run", run);
        setField(pub, "createdByEmail", USER_EMAIL);
        setField(pub, "productName", name);
        setField(pub, "productSlug", name.toLowerCase().replace(" ", "-"));
        setField(pub, "productVersion", "1.0.0");
        setField(pub, "licenseType", "Apache-2.0");
        setField(pub, "reportUrl", "https://scimsandbox.net/reports/" + run.getId());
        setField(pub, "badgeUrl", "https://scimsandbox.net/badges/" + run.getId() + ".svg");
        setField(pub, "publishedAt", OffsetDateTime.now());
        run.setPublication(pub);
        publicationRepository.save(pub);
        return run;
    }

    private ValidationRun createRun(String name, boolean published) {
        ValidationRun run = new ValidationRun();
        run.setName(name);
        run.setTargetUrl("https://scim.example.com/v2");
        run.setExecutedAt(OffsetDateTime.now());
        run.setStatus("PASSED");
        run.setCreatedByUser(testUser);
        setField(run, "id", UUID.randomUUID());
        return runRepository.save(run);
    }

    private static void setField(Object target, String fieldName, Object value) {
        try {
            Field f = target.getClass().getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Testable subclass overriding launcher execution to execute in-memory
    private static class TestableValidationRunService extends ValidationRunService {

        public TestableValidationRunService(
                ValidationRunRepository runRepository,
                ValidationMgmtUserRepository userRepository,
                ValidationRunPublicationRepository publicationRepository) {
            super(runRepository, userRepository, null, null, publicationRepository, null, Executors.newCachedThreadPool());
        }

        @Override
        int discoverTestCount(String baseUrl, String authToken) {
            return 50;
        }

        @Override
        void executeLauncher(Launcher launcher, LauncherDiscoveryRequest request, TestExecutionListener listener) {
            // In-memory test execution double: no external HTTP/network calls
        }
    }

    // In-Memory Repository Double for ValidationRunRepository
    static class InMemoryRunRepository implements ValidationRunRepository {
        private final Map<UUID, ValidationRun> db = new LinkedHashMap<>();

        @Override
        public List<ValidationRun> findOwnedRuns(String actorEmail, Sort sort) {
            return db.values().stream()
                    .filter(r -> r.getCreatedByUser() != null && r.getCreatedByUser().getEmail().equalsIgnoreCase(actorEmail))
                    .filter(r -> !r.isPublished())
                    .sorted(Comparator.comparing(ValidationRun::getExecutedAt))
                    .toList();
        }

        @Override
        public long countOwnedRuns(String actorEmail) {
            return findOwnedRuns(actorEmail, Sort.unsorted()).size();
        }

        @Override
        public Optional<ValidationRun> findAccessibleById(UUID id, String actorEmail) {
            ValidationRun r = db.get(id);
            if (r != null && r.getCreatedByUser() != null && r.getCreatedByUser().getEmail().equalsIgnoreCase(actorEmail)) {
                return Optional.of(r);
            }
            return Optional.empty();
        }

        @Override
        public Optional<ValidationRun> findById(UUID uuid) {
            return Optional.ofNullable(db.get(uuid));
        }

        @Override
        public <S extends ValidationRun> S save(S entity) {
            if (entity.getId() == null) {
                setField(entity, "id", UUID.randomUUID());
            }
            db.put(entity.getId(), entity);
            return entity;
        }

        @Override
        public <S extends ValidationRun> S saveAndFlush(S entity) {
            return save(entity);
        }

        @Override
        public void delete(ValidationRun entity) {
            db.remove(entity.getId());
        }

        @Override
        public void deleteById(UUID uuid) {
            db.remove(uuid);
        }

        @Override public List<ValidationRun> findAll(Sort sort) { return new ArrayList<>(db.values()); }
        @Override public List<ValidationRun> findAll() { return new ArrayList<>(db.values()); }
        @Override public boolean existsById(UUID uuid) { return db.containsKey(uuid); }
        @Override public long count() { return db.size(); }
        @Override public void flush() {}
        @Override public <S extends ValidationRun> List<S> saveAllAndFlush(Iterable<S> entities) { return List.of(); }
        @Override public void deleteAllInBatch(Iterable<ValidationRun> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<UUID> uuids) {}
        @Override public void deleteAllInBatch() {}
        @Override public ValidationRun getOne(UUID uuid) { return db.get(uuid); }
        @Override public ValidationRun getById(UUID uuid) { return db.get(uuid); }
        @Override public ValidationRun getReferenceById(UUID uuid) { return db.get(uuid); }
        @Override public <S extends ValidationRun> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends ValidationRun> List<S> findAll(Example<S> example) { return List.of(); }
        @Override public <S extends ValidationRun> List<S> findAll(Example<S> example, Sort sort) { return List.of(); }
        @Override public <S extends ValidationRun> Page<S> findAll(Example<S> example, Pageable pageable) { return null; }
        @Override public <S extends ValidationRun> long count(Example<S> example) { return 0; }
        @Override public <S extends ValidationRun> boolean exists(Example<S> example) { return false; }
        @Override public <S extends ValidationRun, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public <S extends ValidationRun> List<S> saveAll(Iterable<S> entities) { return List.of(); }
        @Override public List<ValidationRun> findAllById(Iterable<UUID> uuids) { return List.of(); }
        @Override public void deleteAllById(Iterable<? extends UUID> uuids) {}
        @Override public void deleteAll(Iterable<? extends ValidationRun> entities) {}
        @Override public void deleteAll() { db.clear(); }
        @Override public Page<ValidationRun> findAll(Pageable pageable) { return null; }
    }

    // In-Memory Repository Double for ValidationRunPublicationRepository
    static class InMemoryPublicationRepository implements ValidationRunPublicationRepository {
        private final Map<UUID, ValidationRunPublication> db = new LinkedHashMap<>();

        @Override
        public long countByCreatedByEmail(String email) {
            return db.values().stream()
                    .filter(p -> p.getCreatedByEmail() != null && p.getCreatedByEmail().equals(email))
                    .count();
        }

        @Override
        public long countByCreatedByEmailIgnoreCase(String email) {
            return countOwnedPublications(email);
        }

        @Override
        public List<ValidationRunPublication> findByCreatedByEmailOrderByPublishedAtDesc(String email) {
            return db.values().stream()
                    .filter(p -> p.getCreatedByEmail() != null && p.getCreatedByEmail().equals(email))
                    .sorted(Comparator.comparing(ValidationRunPublication::getPublishedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                    .toList();
        }

        @Override
        public List<ValidationRunPublication> findByCreatedByEmailIgnoreCaseOrderByPublishedAtDesc(String email) {
            return findOwnedPublications(email, Sort.unsorted());
        }

        @Override
        public List<ValidationRunPublication> findOwnedPublications(String actorEmail, Sort sort) {
            return db.values().stream()
                    .filter(p -> p.getCreatedByEmail() != null && p.getCreatedByEmail().equalsIgnoreCase(actorEmail))
                    .filter(p -> !p.isPendingReservation())
                    .sorted(Comparator.comparing(ValidationRunPublication::getPublishedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                    .toList();
        }

        @Override
        public long countOwnedPublications(String actorEmail) {
            return findOwnedPublications(actorEmail, Sort.unsorted()).size();
        }

        @Override
        public List<ValidationRunPublication> findStalePendingReservations(String pendingStatus, OffsetDateTime cutoff) {
            return db.values().stream()
                    .filter(p -> pendingStatus.equals(p.getPrUrl()) && (p.getPublishedAt() == null || !p.getPublishedAt().isAfter(cutoff)))
                    .toList();
        }

        @Override
        public int deleteStalePendingReservationById(UUID runId, String pendingStatus, OffsetDateTime cutoff) {
            ValidationRunPublication existing = db.get(runId);
            if (existing != null
                    && pendingStatus.equals(existing.getPrUrl())
                    && (existing.getPublishedAt() == null || !existing.getPublishedAt().isAfter(cutoff))) {
                db.remove(runId);
                return 1;
            }
            return 0;
        }

        @Override
        public int claimStalePendingReservationById(UUID runId, String pendingStatus, OffsetDateTime cutoff, OffsetDateTime newTimestamp) {
            ValidationRunPublication existing = db.get(runId);
            if (existing != null
                    && pendingStatus.equals(existing.getPrUrl())
                    && (existing.getPublishedAt() == null || !existing.getPublishedAt().isAfter(cutoff))) {
                existing.setPublishedAt(newTimestamp);
                return 1;
            }
            return 0;
        }

        @Override
        public List<ValidationRunPublication> findByProductSlugIgnoreCaseOrderByPublishedAtDesc(String productSlug) {
            return db.values().stream()
                    .filter(p -> p.getProductSlug() != null && p.getProductSlug().equalsIgnoreCase(productSlug))
                    .sorted(Comparator.comparing(ValidationRunPublication::getPublishedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                    .toList();
        }

        @Override
        public Optional<ValidationRunPublication> findByRunId(UUID runId) {
            return Optional.ofNullable(db.get(runId));
        }

        @Override
        public Optional<ValidationRunPublication> findById(UUID uuid) {
            return Optional.ofNullable(db.get(uuid));
        }

        @Override
        public <S extends ValidationRunPublication> S save(S entity) {
            db.put(entity.getRunId(), entity);
            return entity;
        }

        @Override
        public void delete(ValidationRunPublication entity) {
            db.remove(entity.getRunId());
        }

        @Override
        public void deleteById(UUID uuid) {
            db.remove(uuid);
        }

        @Override public List<ValidationRunPublication> findAll(Sort sort) { return new ArrayList<>(db.values()); }
        @Override public List<ValidationRunPublication> findAll() { return new ArrayList<>(db.values()); }
        @Override public boolean existsById(UUID uuid) { return db.containsKey(uuid); }
        @Override public long count() { return db.size(); }
        @Override public void flush() {}
        @Override public <S extends ValidationRunPublication> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends ValidationRunPublication> List<S> saveAllAndFlush(Iterable<S> entities) { return List.of(); }
        @Override public void deleteAllInBatch(Iterable<ValidationRunPublication> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<UUID> uuids) {}
        @Override public void deleteAllInBatch() {}
        @Override public ValidationRunPublication getOne(UUID uuid) { return db.get(uuid); }
        @Override public ValidationRunPublication getById(UUID uuid) { return db.get(uuid); }
        @Override public ValidationRunPublication getReferenceById(UUID uuid) { return db.get(uuid); }
        @Override public <S extends ValidationRunPublication> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends ValidationRunPublication> List<S> findAll(Example<S> example) { return List.of(); }
        @Override public <S extends ValidationRunPublication> List<S> findAll(Example<S> example, Sort sort) { return List.of(); }
        @Override public <S extends ValidationRunPublication> Page<S> findAll(Example<S> example, Pageable pageable) { return null; }
        @Override public <S extends ValidationRunPublication> long count(Example<S> example) { return 0; }
        @Override public <S extends ValidationRunPublication> boolean exists(Example<S> example) { return false; }
        @Override public <S extends ValidationRunPublication, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public <S extends ValidationRunPublication> List<S> saveAll(Iterable<S> entities) { return List.of(); }
        @Override public List<ValidationRunPublication> findAllById(Iterable<UUID> uuids) { return List.of(); }
        @Override public void deleteAllById(Iterable<? extends UUID> uuids) {}
        @Override public void deleteAll(Iterable<? extends ValidationRunPublication> entities) {}
        @Override public void deleteAll() { db.clear(); }
        @Override public Page<ValidationRunPublication> findAll(Pageable pageable) { return null; }
    }

    // In-Memory Repository Double for ValidationMgmtUserRepository
    static class InMemoryUserRepository implements ValidationMgmtUserRepository {
        private final Map<String, ValidationMgmtUser> db = new HashMap<>();

        @Override public Optional<ValidationMgmtUser> findById(String s) { return Optional.ofNullable(db.get(s)); }
        @Override public <S extends ValidationMgmtUser> S save(S entity) { db.put(entity.getEmail(), entity); return entity; }
        @Override public boolean existsById(String s) { return db.containsKey(s); }
        @Override public List<ValidationMgmtUser> findAll() { return new ArrayList<>(db.values()); }
        @Override public List<ValidationMgmtUser> findAll(Sort sort) { return new ArrayList<>(db.values()); }
        @Override public void flush() {}
        @Override public <S extends ValidationMgmtUser> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends ValidationMgmtUser> List<S> saveAllAndFlush(Iterable<S> entities) { return List.of(); }
        @Override public void deleteAllInBatch(Iterable<ValidationMgmtUser> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<String> strings) {}
        @Override public void deleteAllInBatch() {}
        @Override public ValidationMgmtUser getOne(String s) { return db.get(s); }
        @Override public ValidationMgmtUser getById(String s) { return db.get(s); }
        @Override public ValidationMgmtUser getReferenceById(String s) { return db.get(s); }
        @Override public <S extends ValidationMgmtUser> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends ValidationMgmtUser> List<S> findAll(Example<S> example) { return List.of(); }
        @Override public <S extends ValidationMgmtUser> List<S> findAll(Example<S> example, Sort sort) { return List.of(); }
        @Override public <S extends ValidationMgmtUser> Page<S> findAll(Example<S> example, Pageable pageable) { return null; }
        @Override public <S extends ValidationMgmtUser> long count(Example<S> example) { return 0; }
        @Override public <S extends ValidationMgmtUser> boolean exists(Example<S> example) { return false; }
        @Override public <S extends ValidationMgmtUser, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public <S extends ValidationMgmtUser> List<S> saveAll(Iterable<S> entities) { return List.of(); }
        @Override public List<ValidationMgmtUser> findAllById(Iterable<String> strings) { return List.of(); }
        @Override public long count() { return db.size(); }
        @Override public void deleteById(String s) { db.remove(s); }
        @Override public void delete(ValidationMgmtUser entity) { db.remove(entity.getEmail()); }
        @Override public void deleteAllById(Iterable<? extends String> strings) {}
        @Override public void deleteAll(Iterable<? extends ValidationMgmtUser> entities) {}
        @Override public void deleteAll() { db.clear(); }
        @Override public Page<ValidationMgmtUser> findAll(Pageable pageable) { return null; }
    }
}
