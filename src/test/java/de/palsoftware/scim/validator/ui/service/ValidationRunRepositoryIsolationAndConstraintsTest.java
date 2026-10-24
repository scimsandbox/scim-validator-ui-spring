package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.ui.dto.ValidationRunForm;
import de.palsoftware.scim.validator.ui.model.ValidationMgmtUser;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationRunPublication;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublicationResult;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublishRequest;
import de.palsoftware.scim.validator.ui.repo.ValidationMgmtUserRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationRunPublicationRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationRunRepository;
import jakarta.persistence.Column;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
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
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.data.repository.query.FluentQuery;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
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
import java.time.ZoneOffset;
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

        private static String readSqlMigration(String resourcePath, Path fallbackPath) throws IOException {
            try (var in = ValidationRunRepositoryIsolationAndConstraintsTest.class.getResourceAsStream(resourcePath)) {
                if (in != null) {
                    return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                }
            }
            if (Files.exists(fallbackPath)) {
                return Files.readString(fallbackPath);
            }
            throw new IOException("Migration SQL resource not found: " + resourcePath);
        }

        @Test
        @DisplayName("INV-1.1: V2 SQL migration contains ON DELETE RESTRICT composite foreign key, check constraints, and indexes")
        void v2Migration_containsOnDeleteRestrict() throws IOException {
            String sql = readSqlMigration("/sql/V2__add_validation_run_publication.sql", V2_MIGRATION_PATH);

            assertThat(sql)
                    .containsIgnoringCase("CREATE TABLE validation_run_publication")
                    .containsIgnoringCase("uk_validation_run_id_created_by_email")
                    .containsIgnoringCase("FOREIGN KEY (run_id, created_by_email) REFERENCES validation_run (id, created_by_email) ON DELETE RESTRICT")
                    .containsIgnoringCase("chk_validation_run_publication_core_score")
                    .containsIgnoringCase("chk_validation_run_publication_capabilities")
                    .containsIgnoringCase("idx_validation_run_publication_email")
                    .containsIgnoringCase("(created_by_email, published_at DESC)")
                    .containsIgnoringCase("idx_validation_run_publication_slug_version");
        }

        @Test
        @DisplayName("INV-1.4: Embedded V1+V2 SQL schema verifies composite FK, admin publication, ON DELETE RESTRICT, and CHECK constraints")
        void embeddedSqlSchema_enforcesCompositeFkAdminPublishAndOnDeleteRestrict() throws Exception {
            String v1Sql = readSqlMigration("/sql/V1__init_validator_schema.sql",
                    Path.of("../scim-validator-db/sql/V1__init_validator_schema.sql"));
            String v2Sql = readSqlMigration("/sql/V2__add_validation_run_publication.sql", V2_MIGRATION_PATH);

            String jdbcUrl = "jdbc:h2:mem:scim_v2_test_" + UUID.randomUUID().toString().replace("-", "")
                    + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH";

            try (Connection conn = DriverManager.getConnection(jdbcUrl, "sa", "")) {
                try (var stmt = conn.createStatement()) {
                    stmt.execute(v1Sql);
                    stmt.execute(v2Sql);
                }

                UUID aliceRunId = UUID.randomUUID();
                String aliceEmail = "alice@example.com";
                String adminEmail = "admin@example.com";

                try (PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO validator_mgmt_users (email, last_login_at) VALUES (?, CURRENT_TIMESTAMP)")) {
                    ps.setString(1, aliceEmail);
                    ps.executeUpdate();
                    ps.setString(1, adminEmail);
                    ps.executeUpdate();
                }

                try (PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO validation_run (id, name, target_url, executed_at, status, created_by_email, total_tests, passed_tests, failed_tests) "
                                + "VALUES (?, 'Alice Run', 'https://scim.example.com', CURRENT_TIMESTAMP, 'PASSED', ?, 10, 10, 0)")) {
                    ps.setObject(1, aliceRunId);
                    ps.setString(2, aliceEmail);
                    ps.executeUpdate();
                }

                // 1. Raw insert with mismatched email (adminEmail instead of aliceEmail) MUST fail composite FK
                assertThatThrownBy(() -> {
                    try (PreparedStatement ps = conn.prepareStatement(
                            "INSERT INTO validation_run_publication (run_id, created_by_email, product_name, product_slug, product_version, license_type, core_score, supported_capabilities, total_capabilities, report_url, badge_url, published_at) "
                                    + "VALUES (?, ?, 'Prod', 'prod', '1.0.0', 'Apache-2.0', 95, 8, 10, 'https://scimsandbox.net/r', 'https://scimsandbox.net/b', CURRENT_TIMESTAMP)")) {
                        ps.setObject(1, aliceRunId);
                        ps.setString(2, adminEmail);
                        ps.executeUpdate();
                    }
                }).isInstanceOf(SQLException.class);

                // 2. Admin publishing Alice's run via ValidationRunService.recordPublication uses run owner's email and succeeds against composite FK
                ValidationRun aliceRun = new ValidationRun();
                aliceRun.setName("Alice Run");
                aliceRun.setTargetUrl("https://scim.example.com");
                aliceRun.setExecutedAt(OffsetDateTime.now(ZoneOffset.UTC));
                aliceRun.setStatus("PASSED");
                aliceRun.setCreatedByUser(new ValidationMgmtUser(aliceEmail, OffsetDateTime.now(ZoneOffset.UTC)));
                setField(aliceRun, "id", aliceRunId);
                ValidationRunService svc = new ValidationRunService(null, null, null, null, (ValidationRunPublicationRepository) null, null);
                CompliancePublishRequest req = new CompliancePublishRequest(
                        aliceRunId, "Alice SCIM", "alice-scim", "1.0.0", "Vendor", "https://example.com",
                        "Apache-2.0", false, 98, "EMERALD", 9, 10, adminEmail, "https://scim.example.com");
                CompliancePublicationResult res = CompliancePublicationResult.success(
                        aliceRunId, "https://github.com/pr/1", "https://scimsandbox.net/r", "https://scimsandbox.net/b",
                        "sha123", OffsetDateTime.now(ZoneOffset.UTC));
                ValidationRunPublication recorded = svc.recordPublication(aliceRun, adminEmail, req, res);
                assertThat(recorded.getCreatedByEmail()).isEqualTo(aliceEmail);

                try (PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO validation_run_publication (run_id, created_by_email, product_name, product_slug, product_version, license_type, core_score, supported_capabilities, total_capabilities, report_url, badge_url, published_at) "
                                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)")) {
                    ps.setObject(1, recorded.getRunId());
                    ps.setString(2, recorded.getCreatedByEmail());
                    ps.setString(3, recorded.getProductName());
                    ps.setString(4, recorded.getProductSlug());
                    ps.setString(5, recorded.getProductVersion());
                    ps.setString(6, recorded.getLicenseType());
                    ps.setInt(7, recorded.getCoreScore());
                    ps.setInt(8, recorded.getSupportedCapabilities());
                    ps.setInt(9, recorded.getTotalCapabilities());
                    ps.setString(10, recorded.getReportUrl());
                    ps.setString(11, recorded.getBadgeUrl());
                    ps.executeUpdate();
                }

                // 3. ON DELETE RESTRICT prevents deleting the published validation_run
                assertThatThrownBy(() -> {
                    try (PreparedStatement ps = conn.prepareStatement("DELETE FROM validation_run WHERE id = ?")) {
                        ps.setObject(1, aliceRunId);
                        ps.executeUpdate();
                    }
                }).isInstanceOf(SQLException.class);

                // 4. CHECK constraint rejects core_score > 100
                UUID secondRunId = UUID.randomUUID();
                try (PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO validation_run (id, name, target_url, executed_at, status, created_by_email, total_tests, passed_tests, failed_tests) "
                                + "VALUES (?, 'Run 2', 'https://scim.example.com', CURRENT_TIMESTAMP, 'PASSED', ?, 10, 10, 0)")) {
                    ps.setObject(1, secondRunId);
                    ps.setString(2, aliceEmail);
                    ps.executeUpdate();
                }
                assertThatThrownBy(() -> {
                    try (PreparedStatement ps = conn.prepareStatement(
                            "INSERT INTO validation_run_publication (run_id, created_by_email, product_name, product_slug, product_version, license_type, core_score, supported_capabilities, total_capabilities, report_url, badge_url, published_at) "
                                    + "VALUES (?, ?, 'Prod', 'prod', '2.0.0', 'Apache-2.0', 105, 8, 10, 'https://scimsandbox.net/r', 'https://scimsandbox.net/b', CURRENT_TIMESTAMP)")) {
                        ps.setObject(1, secondRunId);
                        ps.setString(2, aliceEmail);
                        ps.executeUpdate();
                    }
                }).isInstanceOf(SQLException.class);
            }
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
        @DisplayName("INV-1.3: Real Hibernate JPA + Spring Data repositories persist ValidationRunPublication from a detached ValidationRun (@MapsId) and enforce duplicate/slug invariants")
        void realJpaRepositories_recordPublicationWithDetachedRun_succeedsAndEnforcesInvariants() throws Exception {
            String v1Sql = readSqlMigration("/sql/V1__init_validator_schema.sql",
                    Path.of("../scim-validator-db/sql/V1__init_validator_schema.sql"));
            String v2Sql = readSqlMigration("/sql/V2__add_validation_run_publication.sql", V2_MIGRATION_PATH);

            String jdbcUrl = "jdbc:h2:mem:scim_jpa_maps_id_" + UUID.randomUUID().toString().replace("-", "")
                    + ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH";

            DriverManagerDataSource dataSource = new DriverManagerDataSource(jdbcUrl, "sa", "");
            try (Connection conn = dataSource.getConnection(); var stmt = conn.createStatement()) {
                stmt.execute(v1Sql);
                stmt.execute(v2Sql);
            }

            LocalContainerEntityManagerFactoryBean emfBean = new LocalContainerEntityManagerFactoryBean();
            emfBean.setDataSource(dataSource);
            emfBean.setPackagesToScan("de.palsoftware.scim.validator.ui.model");
            HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
            emfBean.setJpaVendorAdapter(vendorAdapter);
            Map<String, Object> jpaProps = new HashMap<>();
            jpaProps.put("hibernate.hbm2ddl.auto", "validate");
            jpaProps.put("hibernate.dialect", "org.hibernate.dialect.H2Dialect");
            jpaProps.put("hibernate.physical_naming_strategy", "org.hibernate.boot.model.naming.CamelCaseToUnderscoresNamingStrategy");
            emfBean.setJpaPropertyMap(jpaProps);
            emfBean.afterPropertiesSet();

            EntityManagerFactory emf = emfBean.getObject();
            assertThat(emf).isNotNull();
            try (EntityManager em = emf.createEntityManager()) {
                JpaRepositoryFactory repoFactory = new JpaRepositoryFactory(em);
                ValidationMgmtUserRepository jpaUserRepo = repoFactory.getRepository(ValidationMgmtUserRepository.class);
                ValidationRunRepository jpaRunRepo = repoFactory.getRepository(ValidationRunRepository.class);
                ValidationRunPublicationRepository jpaPubRepo = repoFactory.getRepository(ValidationRunPublicationRepository.class);

                ValidationRunService jpaService = new ValidationRunService(
                        jpaRunRepo, jpaUserRepo, null, null, jpaPubRepo, null);

                // Transaction 1: persist users and Alice's run, then detach all entities (simulating ValidationController.getRunEntity)
                ValidationRun detachedAliceRun;
                em.getTransaction().begin();
                ValidationMgmtUser alice = jpaUserRepo.save(new ValidationMgmtUser("alice@example.com", OffsetDateTime.now(ZoneOffset.UTC)));
                ValidationMgmtUser bob = jpaUserRepo.save(new ValidationMgmtUser("bob@example.com", OffsetDateTime.now(ZoneOffset.UTC)));
                ValidationRun aliceRun = new ValidationRun();
                aliceRun.setName("Alice Detached Run");
                aliceRun.setTargetUrl("https://scim.alice.internal/v2");
                aliceRun.setExecutedAt(OffsetDateTime.now(ZoneOffset.UTC));
                aliceRun.setStatus("PASSED");
                aliceRun.setCreatedByUser(alice);
                aliceRun.setTotalTests(10);
                aliceRun.setPassedTests(10);
                aliceRun.setFailedTests(0);
                detachedAliceRun = jpaRunRepo.save(aliceRun);
                em.flush();
                em.getTransaction().commit();
                em.clear(); // detachedAliceRun is now detached!

                // Transaction 2: call recordPublication with detachedAliceRun (simulating ValidationController.publishRun)
                CompliancePublishRequest aliceReq = new CompliancePublishRequest(
                        detachedAliceRun.getId(), "Alice SCIM Server", "alice-scim", "1.0.0",
                        "Alice Corp", "https://alice.example.com", "Apache-2.0", true,
                        98, "EMERALD", 9, 10, "admin@example.com", "https://scim.alice.internal/v2");
                CompliancePublicationResult aliceRes = CompliancePublicationResult.success(
                        detachedAliceRun.getId(), "https://github.com/scimsandbox/scim-website/pull/10",
                        "https://scimsandbox.net/compliance/?run=" + detachedAliceRun.getId(),
                        "https://scimsandbox.net/compliance/badges/" + detachedAliceRun.getId() + ".svg",
                        "abcdef1234567890", OffsetDateTime.now(ZoneOffset.UTC));

                em.getTransaction().begin();
                ValidationRunPublication savedPub = jpaService.recordPublication(
                        detachedAliceRun, "admin@example.com", aliceReq, aliceRes);
                em.flush();
                em.getTransaction().commit();
                em.clear();

                assertThat(savedPub.getRunId()).isEqualTo(detachedAliceRun.getId());
                assertThat(savedPub.getCreatedByEmail()).isEqualTo("alice@example.com");
                assertThat(jpaPubRepo.existsById(detachedAliceRun.getId())).isTrue();
                ValidationRun reloadedAliceRun = jpaRunRepo.findById(detachedAliceRun.getId()).orElseThrow();
                assertThat(reloadedAliceRun.isPublished()).isTrue();

                // Transaction 3: duplicate recordPublication on the same run must throw IllegalStateException
                em.getTransaction().begin();
                assertThatThrownBy(() -> jpaService.recordPublication(
                        detachedAliceRun, "admin@example.com", aliceReq, aliceRes))
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("already been published");
                em.getTransaction().rollback();
                em.clear();

                // Transaction 4: Bob attempting to publish under Alice's productSlug ("alice-scim") must fail with 409 CONFLICT
                em.getTransaction().begin();
                ValidationMgmtUser managedBob = jpaUserRepo.findById(bob.getEmail()).orElseThrow();
                ValidationRun bobRun = new ValidationRun();
                bobRun.setName("Bob Run");
                bobRun.setTargetUrl("https://scim.bob.internal/v2");
                bobRun.setExecutedAt(OffsetDateTime.now(ZoneOffset.UTC));
                bobRun.setStatus("PASSED");
                bobRun.setCreatedByUser(managedBob);
                bobRun.setTotalTests(10);
                bobRun.setPassedTests(10);
                bobRun.setFailedTests(0);
                ValidationRun detachedBobRun = jpaRunRepo.save(bobRun);
                em.flush();
                em.getTransaction().commit();
                em.clear();

                CompliancePublishRequest bobHijackReq = new CompliancePublishRequest(
                        detachedBobRun.getId(), "Bob SCIM Server", "alice-scim", "2.0.0",
                        "Bob Corp", "https://bob.example.com", "MIT", false,
                        95, "EMERALD", 8, 10, "bob@example.com", "https://scim.bob.internal/v2");
                CompliancePublicationResult bobRes = CompliancePublicationResult.success(
                        detachedBobRun.getId(), "https://github.com/scimsandbox/scim-website/pull/11",
                        "https://scimsandbox.net/compliance/?run=" + detachedBobRun.getId(),
                        "https://scimsandbox.net/compliance/badges/" + detachedBobRun.getId() + ".svg",
                        "1234567890abcdef", OffsetDateTime.now(ZoneOffset.UTC));

                em.getTransaction().begin();
                assertThatThrownBy(() -> jpaService.recordPublication(
                        detachedBobRun, "bob@example.com", bobHijackReq, bobRes))
                        .isInstanceOf(ResponseStatusException.class)
                        .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode()).isEqualTo(HttpStatus.CONFLICT));
                em.getTransaction().rollback();
                em.clear();

                // Transaction 5: Pre-GitHub reservePublication -> releasePublicationReservation rollback -> reservePublication -> recordPublication finalization
                CompliancePublishRequest bobValidReq = new CompliancePublishRequest(
                        detachedBobRun.getId(), "Bob SCIM Server", "bob-scim", "2.0.0",
                        "Bob Corp", "https://bob.example.com", "MIT", false,
                        95, "EMERALD", 8, 10, "bob@example.com", "https://scim.bob.internal/v2");

                em.getTransaction().begin();
                ValidationRunPublication reservation = jpaService.reservePublication(detachedBobRun, "bob@example.com", bobValidReq);
                em.flush();
                em.getTransaction().commit();
                em.clear();
                assertThat(reservation.getPrUrl()).isEqualTo(ValidationRunService.PENDING_RESERVATION_PR_URL);
                assertThat(jpaPubRepo.existsById(detachedBobRun.getId())).isTrue();

                // Simulate GitHub failure releasing the reservation so Bob can retry
                em.getTransaction().begin();
                jpaService.releasePublicationReservation(detachedBobRun);
                em.flush();
                em.getTransaction().commit();
                em.clear();
                assertThat(jpaPubRepo.existsById(detachedBobRun.getId())).isFalse();

                // Retry: reservePublication then finalize with recordPublication
                em.getTransaction().begin();
                jpaService.reservePublication(detachedBobRun, "bob@example.com", bobValidReq);
                em.flush();
                em.getTransaction().commit();
                em.clear();

                em.getTransaction().begin();
                ValidationRunPublication finalizedBobPub = jpaService.recordPublication(
                        detachedBobRun, "bob@example.com", bobValidReq, bobRes);
                em.flush();
                em.getTransaction().commit();
                em.clear();
                assertThat(finalizedBobPub.getPrUrl()).isEqualTo("https://github.com/scimsandbox/scim-website/pull/11");
                assertThat(finalizedBobPub.getProductSlug()).isEqualTo("bob-scim");
            } finally {
                emf.close();
            }
        }

        @Test
        @DisplayName("INV-1.5: Test SQL migration copies in src/test/resources/sql stay in sync with ../scim-validator-db/sql")
        void testSqlResources_stayInSyncWithValidatorDbRepoWhenPresent() throws IOException {
            Path externalV1 = Path.of("../scim-validator-db/sql/V1__init_validator_schema.sql");
            Path externalV2 = V2_MIGRATION_PATH;
            if (Files.exists(externalV1)) {
                String classpathV1 = readSqlMigration("/sql/V1__init_validator_schema.sql", externalV1).replace("\r\n", "\n").trim();
                String diskV1 = Files.readString(externalV1).replace("\r\n", "\n").trim();
                assertThat(classpathV1).isEqualTo(diskV1);
            }
            if (Files.exists(externalV2)) {
                String classpathV2 = readSqlMigration("/sql/V2__add_validation_run_publication.sql", externalV2).replace("\r\n", "\n").trim();
                String diskV2 = Files.readString(externalV2).replace("\r\n", "\n").trim();
                assertThat(classpathV2).isEqualTo(diskV2);
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

        @Override
        public List<ValidationRunPublication> findByProductSlugIgnoreCaseOrderByPublishedAtDesc(String productSlug) {
            return db.values().stream()
                    .filter(p -> p.getProductSlug() != null && p.getProductSlug().equalsIgnoreCase(productSlug))
                    .sorted(Comparator.comparing(ValidationRunPublication::getPublishedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                    .toList();
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
