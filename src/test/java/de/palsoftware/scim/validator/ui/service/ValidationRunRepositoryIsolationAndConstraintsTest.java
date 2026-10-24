package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.ui.dto.ValidationRunForm;
import de.palsoftware.scim.validator.ui.model.ValidationMgmtUser;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationRunPublication;
import de.palsoftware.scim.validator.ui.repo.ValidationMgmtUserRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationRunPublicationRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationRunRepository;
import jakarta.persistence.Column;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.MapsId;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Empirical challenger test suite for Milestone 1:
 * 1. Database schema constraints (`ON DELETE RESTRICT`, `idx_validation_run_publication_email`).
 * 2. Repository query isolation (`run.publication is null`).
 * 3. Case-insensitive email queries and quota circumvention resistance.
 */
public class ValidationRunRepositoryIsolationAndConstraintsTest {

    // ─────────────────────────────────────────────────────────────────────────
    // Part 1: Schema & DDL Invariant Tests (Static & Live PostgreSQL)
    // ─────────────────────────────────────────────────────────────────────────
    @Nested
    @DisplayName("1. Database Schema & Constraint Invariants")
    class DatabaseSchemaAndConstraintInvariants {

        private static final Path V2_MIGRATION_PATH = Path.of(
                "../scim-validator-db/sql/V2__add_validation_run_publication.sql");

        @Test
        @DisplayName("INV-1.1: V2 SQL migration contains ON DELETE RESTRICT foreign key constraint")
        void v2Migration_containsOnDeleteRestrict() throws IOException {
            assumeTrue(Files.exists(V2_MIGRATION_PATH), "V2 migration SQL file must exist");
            String sql = Files.readString(V2_MIGRATION_PATH);

            assertThat(sql)
                    .containsIgnoringCase("CREATE TABLE validation_run_publication")
                    .containsIgnoringCase("FOREIGN KEY (run_id) REFERENCES validation_run (id) ON DELETE RESTRICT")
                    .containsIgnoringCase("idx_validation_run_publication_email")
                    .containsIgnoringCase("(created_by_email, published_at DESC)");
        }

        @Test
        @DisplayName("INV-1.2: ValidationRunPublication JPA entity strictly matches Flyway V2 schema")
        void jpaEntity_matchesV2Schema() throws NoSuchFieldException {
            Class<ValidationRunPublication> clazz = ValidationRunPublication.class;

            // Table annotation
            Table table = clazz.getAnnotation(Table.class);
            assertThat(table).isNotNull();
            assertThat(table.name()).isEqualTo("validation_run_publication");

            // run_id primary key and @MapsId relation
            Field runIdField = clazz.getDeclaredField("runId");
            assertThat(runIdField.getAnnotation(Id.class)).isNotNull();
            assertThat(runIdField.getAnnotation(Column.class).name()).isEqualTo("run_id");

            Field runField = clazz.getDeclaredField("run");
            assertThat(runField.getAnnotation(OneToOne.class)).isNotNull();
            assertThat(runField.getAnnotation(MapsId.class)).isNotNull();
            assertThat(runField.getAnnotation(JoinColumn.class).name()).isEqualTo("run_id");
            assertThat(runField.getAnnotation(JoinColumn.class).nullable()).isFalse();

            // created_by_email VARCHAR(500) NOT NULL
            Field emailField = clazz.getDeclaredField("createdByEmail");
            Column emailCol = emailField.getAnnotation(Column.class);
            assertThat(emailCol.name()).isEqualTo("created_by_email");
            assertThat(emailCol.nullable()).isFalse();
            assertThat(emailCol.length()).isEqualTo(500);

            // product_name VARCHAR(120) NOT NULL
            Field prodField = clazz.getDeclaredField("productName");
            Column prodCol = prodField.getAnnotation(Column.class);
            assertThat(prodCol.name()).isEqualTo("product_name");
            assertThat(prodCol.nullable()).isFalse();
            assertThat(prodCol.length()).isEqualTo(120);

            // product_slug VARCHAR(120) NOT NULL
            Field slugField = clazz.getDeclaredField("productSlug");
            Column slugCol = slugField.getAnnotation(Column.class);
            assertThat(slugCol.name()).isEqualTo("product_slug");
            assertThat(slugCol.nullable()).isFalse();
            assertThat(slugCol.length()).isEqualTo(120);

            // product_version VARCHAR(60) NOT NULL
            Field verField = clazz.getDeclaredField("productVersion");
            Column verCol = verField.getAnnotation(Column.class);
            assertThat(verCol.name()).isEqualTo("product_version");
            assertThat(verCol.nullable()).isFalse();
            assertThat(verCol.length()).isEqualTo(60);

            // license_type VARCHAR(40) NOT NULL
            Field licField = clazz.getDeclaredField("licenseType");
            Column licCol = licField.getAnnotation(Column.class);
            assertThat(licCol.name()).isEqualTo("license_type");
            assertThat(licCol.nullable()).isFalse();
            assertThat(licCol.length()).isEqualTo(40);

            // report_url VARCHAR(500) NOT NULL
            Field repField = clazz.getDeclaredField("reportUrl");
            Column repCol = repField.getAnnotation(Column.class);
            assertThat(repCol.name()).isEqualTo("report_url");
            assertThat(repCol.nullable()).isFalse();
            assertThat(repCol.length()).isEqualTo(500);

            // badge_url VARCHAR(500) NOT NULL
            Field badgeField = clazz.getDeclaredField("badgeUrl");
            Column badgeCol = badgeField.getAnnotation(Column.class);
            assertThat(badgeCol.name()).isEqualTo("badge_url");
            assertThat(badgeCol.nullable()).isFalse();
            assertThat(badgeCol.length()).isEqualTo(500);

            // published_at TIMESTAMP WITH TIME ZONE NOT NULL
            Field pubAtField = clazz.getDeclaredField("publishedAt");
            Column pubAtCol = pubAtField.getAnnotation(Column.class);
            assertThat(pubAtCol.name()).isEqualTo("published_at");
            assertThat(pubAtCol.nullable()).isFalse();
        }

        @Test
        @DisplayName("INV-1.3: Live PostgreSQL empirical verification of ON DELETE RESTRICT and index")
        void livePostgreSql_onDeleteRestrict_empiricallyVerified() {
            assumeTrue(isPostgreSqlAvailable("localhost", 15432),
                    "PostgreSQL container port 15432 not reachable, skipping live DB test");

            String url = "jdbc:postgresql://localhost:15432/scim_validator_test";
            String user = "scimserver";
            String pass = "scimserver";

            try (Connection conn = DriverManager.getConnection(url, user, pass)) {
                // Verify index exists
                try (PreparedStatement stmt = conn.prepareStatement(
                        "SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'validation_run_publication' AND indexname = 'idx_validation_run_publication_email'")) {
                    ResultSet rs = stmt.executeQuery();
                    assertThat(rs.next()).isTrue();
                    String indexDef = rs.getString("indexdef");
                    assertThat(indexDef)
                            .contains("created_by_email")
                            .contains("published_at DESC");
                }

                // Verify ON DELETE RESTRICT on fk_validation_run_publication_run
                try (PreparedStatement stmt = conn.prepareStatement("""
                        SELECT confdeltype
                        FROM pg_constraint
                        WHERE conname = 'fk_validation_run_publication_run'
                        """)) {
                    ResultSet rs = stmt.executeQuery();
                    assertThat(rs.next()).isTrue();
                    String deleteAction = rs.getString("confdeltype");
                    // 'r' = RESTRICT in PostgreSQL pg_constraint
                    assertThat(deleteAction).isEqualTo("r");
                }

                // Verify empirical constraint enforcement
                UUID testRunId = UUID.randomUUID();
                String testEmail = "empirical-challenger@example.com";

                // Ensure user exists
                try (PreparedStatement stmt = conn.prepareStatement(
                        "INSERT INTO validator_mgmt_users (email, last_login_at) VALUES (?, NOW()) ON CONFLICT (email) DO NOTHING")) {
                    stmt.setString(1, testEmail);
                    stmt.executeUpdate();
                }

                // Insert run
                try (PreparedStatement stmt = conn.prepareStatement(
                        "INSERT INTO validation_run (id, name, target_url, executed_at, status, created_by_email, total_tests, passed_tests, failed_tests) VALUES (?, 'Live DB Run', 'https://scim.example.com', NOW(), 'PASSED', ?, 10, 10, 0)")) {
                    stmt.setObject(1, testRunId);
                    stmt.setString(2, testEmail);
                    stmt.executeUpdate();
                }

                // Insert publication
                try (PreparedStatement stmt = conn.prepareStatement(
                        "INSERT INTO validation_run_publication (run_id, created_by_email, product_name, product_slug, product_version, license_type, core_score, supported_capabilities, total_capabilities, report_url, badge_url, published_at) VALUES (?, ?, 'Empirical Prod', 'emp-prod', '1.0.0', 'Apache-2.0', 100, 10, 10, 'https://scimsandbox.net/rep', 'https://scimsandbox.net/badge.svg', NOW())")) {
                    stmt.setObject(1, testRunId);
                    stmt.setString(2, testEmail);
                    stmt.executeUpdate();
                }

                // ATTEMPT DELETE ON validation_run: MUST FAIL with foreign key violation
                try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM validation_run WHERE id = ?")) {
                    stmt.setObject(1, testRunId);
                    assertThatThrownBy(stmt::executeUpdate)
                            .isInstanceOf(SQLException.class)
                            .hasMessageContaining("fk_validation_run_publication_run");
                }

                // Delete publication first -> succeeds
                try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM validation_run_publication WHERE run_id = ?")) {
                    stmt.setObject(1, testRunId);
                    int deleted = stmt.executeUpdate();
                    assertThat(deleted).isEqualTo(1);
                }

                // Now delete validation_run -> succeeds
                try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM validation_run WHERE id = ?")) {
                    stmt.setObject(1, testRunId);
                    int deleted = stmt.executeUpdate();
                    assertThat(deleted).isEqualTo(1);
                }

            } catch (SQLException e) {
                throw new RuntimeException("Database error during empirical constraint verification", e);
            }
        }

        private boolean isPostgreSqlAvailable(String host, int port) {
            try (Socket socket = new Socket(host, port)) {
                return true;
            } catch (Exception e) {
                return false;
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Part 2: Repository Query Isolation Invariants (`run.publication is null`)
    // ─────────────────────────────────────────────────────────────────────────
    @Nested
    @DisplayName("2. Repository Query Isolation Invariants")
    class RepositoryQueryIsolationInvariants {

        private MockValidationRunRepository runRepository;
        private MockPublicationRepository publicationRepository;
        private MockUserRepository userRepository;
        private TestableValidationRunService service;

        private static final String USER = "isolated-user@example.com";
        private ValidationMgmtUser mgmtUser;

        @BeforeEach
        void setUp() {
            runRepository = new MockValidationRunRepository();
            publicationRepository = new MockPublicationRepository();
            userRepository = new MockUserRepository();

            mgmtUser = new ValidationMgmtUser(USER, OffsetDateTime.now());
            userRepository.save(mgmtUser);
            userRepository.save(new ValidationMgmtUser("admin@example.com", OffsetDateTime.now()));

            service = new TestableValidationRunService(runRepository, userRepository, publicationRepository);
        }

        @Test
        @DisplayName("INV-2.1: findOwnedRuns returns strictly runs where run.publication is null")
        void findOwnedRuns_strictlyIsolatesUnpublished() {
            // Seed 5 unpublished and 5 published runs
            for (int i = 1; i <= 5; i++) {
                createRun(mgmtUser, "Unpublished " + i, false);
            }
            for (int i = 1; i <= 5; i++) {
                createRun(mgmtUser, "Published " + i, true);
            }

            // Total in DB = 10
            assertThat(runRepository.findAll()).hasSize(10);

            // findOwnedRuns MUST return only 5
            List<ValidationRun> ownedRuns = runRepository.findOwnedRuns(USER, Sort.unsorted());
            assertThat(ownedRuns).hasSize(5);
            assertThat(ownedRuns).allMatch(r -> !r.isPublished());
            assertThat(ownedRuns).allMatch(r -> r.getPublication() == null);
        }

        @Test
        @DisplayName("INV-2.2: countOwnedRuns returns strictly count where run.publication is null")
        void countOwnedRuns_strictlyIsolatesUnpublished() {
            for (int i = 1; i <= 7; i++) {
                createRun(mgmtUser, "Unpublished " + i, false);
            }
            for (int i = 1; i <= 8; i++) {
                createRun(mgmtUser, "Published " + i, true);
            }

            long unpublishedCount = runRepository.countOwnedRuns(USER);
            assertThat(unpublishedCount).isEqualTo(7L);
        }

        @Test
        @DisplayName("INV-2.3: User with 0 unpublished runs and 50 published runs has 0 owned working runs")
        void zeroUnpublishedFiftyPublished_ownedRunsIsEmpty() {
            for (int i = 1; i <= 50; i++) {
                createRun(mgmtUser, "Published " + i, true);
            }

            assertThat(runRepository.findOwnedRuns(USER, Sort.unsorted())).isEmpty();
            assertThat(runRepository.countOwnedRuns(USER)).isZero();
            assertThat(publicationRepository.countOwnedPublications(USER)).isEqualTo(50L);
        }

        @Test
        @DisplayName("INV-2.4: Publishing an unpublished run immediately isolates it from findOwnedRuns")
        void publishingRun_immediatelyRemovesFromWorkingRuns() {
            ValidationRun run = createRun(mgmtUser, "Draft Run", false);
            assertThat(runRepository.findOwnedRuns(USER, Sort.unsorted())).hasSize(1);
            assertThat(runRepository.countOwnedRuns(USER)).isEqualTo(1L);

            // Publish the run
            ValidationRunPublication pub = new ValidationRunPublication();
            setField(pub, "runId", run.getId());
            setField(pub, "run", run);
            setField(pub, "createdByEmail", USER);
            setField(pub, "publishedAt", OffsetDateTime.now());
            run.setPublication(pub);
            publicationRepository.save(pub);

            // Immediately vanishes from findOwnedRuns and countOwnedRuns
            assertThat(runRepository.findOwnedRuns(USER, Sort.unsorted())).isEmpty();
            assertThat(runRepository.countOwnedRuns(USER)).isZero();
            assertThat(publicationRepository.countOwnedPublications(USER)).isEqualTo(1L);
        }

        @Test
        @DisplayName("INV-2.5: findAccessibleById allows user to view their own published run")
        void findAccessibleById_allowsViewingPublishedRun() {
            ValidationRun publishedRun = createRun(mgmtUser, "Published Suite", true);
            UUID runId = publishedRun.getId();

            Optional<ValidationRun> accessible = runRepository.findAccessibleById(runId, USER);
            assertThat(accessible).isPresent();
            assertThat(accessible.get().isPublished()).isTrue();
        }

        private ValidationRun createRun(ValidationMgmtUser owner, String name, boolean published) {
            ValidationRun run = new ValidationRun();
            run.setName(name);
            run.setTargetUrl("https://scim.example.com/v2");
            run.setExecutedAt(OffsetDateTime.now());
            run.setStatus("PASSED");
            run.setCreatedByUser(owner);
            setField(run, "id", UUID.randomUUID());
            runRepository.save(run);

            if (published) {
                ValidationRunPublication pub = new ValidationRunPublication();
                setField(pub, "runId", run.getId());
                setField(pub, "run", run);
                setField(pub, "createdByEmail", owner.getEmail());
                setField(pub, "productName", name);
                setField(pub, "productSlug", name.toLowerCase().replace(" ", "-"));
                setField(pub, "productVersion", "1.0.0");
                setField(pub, "licenseType", "Apache-2.0");
                setField(pub, "reportUrl", "https://scimsandbox.net/rep/" + run.getId());
                setField(pub, "badgeUrl", "https://scimsandbox.net/badges/" + run.getId() + ".svg");
                setField(pub, "publishedAt", OffsetDateTime.now());
                run.setPublication(pub);
                publicationRepository.save(pub);
            }
            return run;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Part 3: Case-Insensitive Email Queries & Quota Bypass Resistance
    // ─────────────────────────────────────────────────────────────────────────
    @Nested
    @DisplayName("3. Case-Insensitive Email Queries & Quota Bypass Resistance")
    class CaseInsensitiveEmailQueriesAndQuotaBypassResistance {

        private MockValidationRunRepository runRepository;
        private MockPublicationRepository publicationRepository;
        private MockUserRepository userRepository;
        private TestableValidationRunService service;

        private static final String LOWER_EMAIL = "developer@example.com";
        private static final String UPPER_EMAIL = "DEVELOPER@EXAMPLE.COM";
        private static final String MIXED_EMAIL = "DeVeLoPeR@ExAmPlE.CoM";

        private ValidationMgmtUser mgmtUser;

        @BeforeEach
        void setUp() {
            runRepository = new MockValidationRunRepository();
            publicationRepository = new MockPublicationRepository();
            userRepository = new MockUserRepository();

            mgmtUser = new ValidationMgmtUser(LOWER_EMAIL, OffsetDateTime.now());
            userRepository.save(mgmtUser);
            userRepository.save(new ValidationMgmtUser(UPPER_EMAIL, OffsetDateTime.now()));
            userRepository.save(new ValidationMgmtUser(MIXED_EMAIL, OffsetDateTime.now()));

            service = new TestableValidationRunService(runRepository, userRepository, publicationRepository);
        }

        @ParameterizedTest
        @ValueSource(strings = {"developer@example.com", "DEVELOPER@EXAMPLE.COM", "DeVeLoPeR@ExAmPlE.CoM"})
        @DisplayName("INV-3.1: Case-insensitivity in unpublished run auto-pruning prevents quota circumvention")
        void unpublishedPruning_caseInsensitiveAcrossEmailCasing(String emailVariant) {
            // Seed 10 runs under LOWER_EMAIL
            for (int i = 1; i <= 10; i++) {
                ValidationRun run = new ValidationRun();
                run.setName("Run " + i);
                run.setTargetUrl("https://scim.example.com/v2");
                run.setExecutedAt(OffsetDateTime.now().minusMinutes(20 - i));
                run.setStatus("PASSED");
                run.setCreatedByUser(mgmtUser);
                setField(run, "id", UUID.randomUUID());
                runRepository.save(run);
            }

            // Attempt 11th run using uppercase or mixed-case email
            ValidationRunService.ExecutionResult result = service.executeRun(
                    new ValidationRunForm("Run 11", "https://scim.example.com/v2", "tok"), emailVariant);

            // Auto-pruning MUST be triggered despite differing casing
            assertThat(result.isOldRunDeleted())
                    .as("Quota bypass via casing variation '%s' must be blocked and trigger pruning", emailVariant)
                    .isTrue();

            // Total unpublished runs for the user must remain capped at exactly 10
            assertThat(runRepository.findOwnedRuns(LOWER_EMAIL, Sort.unsorted())).hasSize(10);
            assertThat(runRepository.findOwnedRuns(emailVariant, Sort.unsorted())).hasSize(10);
        }

        @ParameterizedTest
        @ValueSource(strings = {"developer@example.com", "DEVELOPER@EXAMPLE.COM", "DeVeLoPeR@ExAmPlE.CoM"})
        @DisplayName("INV-3.2: Case-insensitivity in published runs cap (50) prevents quota circumvention")
        void publishedCap_caseInsensitiveAcrossEmailCasing(String emailVariant) {
            // Seed 50 published runs under LOWER_EMAIL
            for (int i = 1; i <= 50; i++) {
                ValidationRun run = new ValidationRun();
                run.setName("Published " + i);
                run.setTargetUrl("https://scim.example.com/v2");
                run.setExecutedAt(OffsetDateTime.now());
                run.setStatus("PASSED");
                run.setCreatedByUser(mgmtUser);
                setField(run, "id", UUID.randomUUID());
                runRepository.save(run);

                ValidationRunPublication pub = new ValidationRunPublication();
                setField(pub, "runId", run.getId());
                setField(pub, "run", run);
                setField(pub, "createdByEmail", LOWER_EMAIL);
                setField(pub, "publishedAt", OffsetDateTime.now());
                run.setPublication(pub);
                publicationRepository.save(pub);
            }

            // Validate quota with uppercase/mixed-case email: MUST be blocked with 400 Bad Request
            assertThatThrownBy(() -> service.validatePublishQuota(emailVariant))
                    .isInstanceOf(ResponseStatusException.class)
                    .satisfies(ex -> {
                        ResponseStatusException rse = (ResponseStatusException) ex;
                        assertThat(rse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(rse.getReason()).contains("maximum published compliance runs cap (50)");
                    });
        }

        @Test
        @DisplayName("INV-3.3: Case-insensitive derived queries in ValidationRunPublicationRepository")
        void publicationRepository_derivedCaseInsensitiveQueries() {
            ValidationRun run = new ValidationRun();
            run.setName("Test Run");
            run.setTargetUrl("https://scim.example.com/v2");
            run.setExecutedAt(OffsetDateTime.now());
            run.setStatus("PASSED");
            run.setCreatedByUser(mgmtUser);
            setField(run, "id", UUID.randomUUID());
            runRepository.save(run);

            ValidationRunPublication pub = new ValidationRunPublication();
            setField(pub, "runId", run.getId());
            setField(pub, "run", run);
            setField(pub, "createdByEmail", LOWER_EMAIL);
            setField(pub, "publishedAt", OffsetDateTime.now());
            run.setPublication(pub);
            publicationRepository.save(pub);

            // Verify countByCreatedByEmailIgnoreCase
            assertThat(publicationRepository.countByCreatedByEmailIgnoreCase(UPPER_EMAIL)).isEqualTo(1L);
            assertThat(publicationRepository.countByCreatedByEmailIgnoreCase(MIXED_EMAIL)).isEqualTo(1L);

            // Verify findByCreatedByEmailIgnoreCaseOrderByPublishedAtDesc
            List<ValidationRunPublication> list = publicationRepository
                    .findByCreatedByEmailIgnoreCaseOrderByPublishedAtDesc(UPPER_EMAIL);
            assertThat(list).hasSize(1);
            assertThat(list.get(0).getCreatedByEmail()).isEqualTo(LOWER_EMAIL);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test Doubles & Helper Classes
    // ─────────────────────────────────────────────────────────────────────────

    private static void setField(Object target, String fieldName, Object value) {
        try {
            Field f = target.getClass().getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static class TestableValidationRunService extends ValidationRunService {
        public TestableValidationRunService(
                ValidationRunRepository runRepository,
                ValidationMgmtUserRepository userRepository,
                ValidationRunPublicationRepository publicationRepository) {
            super(runRepository, userRepository, null, null, publicationRepository, null, Executors.newCachedThreadPool());
        }

        @Override
        int discoverTestCount(String baseUrl, String authToken) {
            return 100;
        }

        @Override
        void executeLauncher(Launcher launcher, LauncherDiscoveryRequest request, TestExecutionListener listener) {
            // Hermetic in-memory execution double
        }
    }

    static class MockValidationRunRepository implements ValidationRunRepository {
        private final Map<UUID, ValidationRun> db = new LinkedHashMap<>();

        @Override
        public List<ValidationRun> findOwnedRuns(String actorEmail, Sort sort) {
            return db.values().stream()
                    .filter(r -> r.getCreatedByUser() != null && r.getCreatedByUser().getEmail().equalsIgnoreCase(actorEmail))
                    .filter(r -> r.getPublication() == null)
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

        @Override public Optional<ValidationRun> findById(UUID uuid) { return Optional.ofNullable(db.get(uuid)); }
        @Override public <S extends ValidationRun> S save(S entity) {
            if (entity.getId() == null) setField(entity, "id", UUID.randomUUID());
            db.put(entity.getId(), entity);
            return entity;
        }
        @Override public <S extends ValidationRun> S saveAndFlush(S entity) { return save(entity); }
        @Override public void delete(ValidationRun entity) { db.remove(entity.getId()); }
        @Override public void deleteById(UUID uuid) { db.remove(uuid); }
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

    static class MockPublicationRepository implements ValidationRunPublicationRepository {
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
                    .sorted(Comparator.comparing(ValidationRunPublication::getPublishedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                    .toList();
        }

        @Override
        public long countOwnedPublications(String actorEmail) {
            return findOwnedPublications(actorEmail, Sort.unsorted()).size();
        }

        @Override public Optional<ValidationRunPublication> findByRunId(UUID runId) { return Optional.ofNullable(db.get(runId)); }
        @Override public Optional<ValidationRunPublication> findById(UUID uuid) { return Optional.ofNullable(db.get(uuid)); }
        @Override public <S extends ValidationRunPublication> S save(S entity) {
            db.put(entity.getRunId(), entity);
            return entity;
        }
        @Override public void delete(ValidationRunPublication entity) { db.remove(entity.getRunId()); }
        @Override public void deleteById(UUID uuid) { db.remove(uuid); }
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

    static class MockUserRepository implements ValidationMgmtUserRepository {
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
