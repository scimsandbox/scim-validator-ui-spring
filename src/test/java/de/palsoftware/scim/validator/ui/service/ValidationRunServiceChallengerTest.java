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
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Adversarial and empirical challenge test suite for Milestone 1 retention,
 * boundary limits (10 unpublished, 50 published), and deletion guards.
 */
public class ValidationRunServiceChallengerTest {

    private InMemoryRunRepository runRepository;
    private InMemoryPublicationRepository publicationRepository;
    private InMemoryUserRepository userRepository;
    private ChallengerValidationRunService service;

    private static final String ALICE_EMAIL = "alice@example.com";
    private static final String BOB_EMAIL = "bob@example.com";
    private static final String ADMIN_EMAIL = "admin@example.com";

    private ValidationMgmtUser alice;
    private ValidationMgmtUser bob;
    private ValidationMgmtUser admin;

    @BeforeEach
    void setUp() {
        runRepository = new InMemoryRunRepository();
        publicationRepository = new InMemoryPublicationRepository();
        userRepository = new InMemoryUserRepository();

        alice = new ValidationMgmtUser(ALICE_EMAIL, OffsetDateTime.now());
        bob = new ValidationMgmtUser(BOB_EMAIL, OffsetDateTime.now());
        admin = new ValidationMgmtUser(ADMIN_EMAIL, OffsetDateTime.now());

        userRepository.save(alice);
        userRepository.save(bob);
        userRepository.save(admin);

        service = new ChallengerValidationRunService(runRepository, userRepository, publicationRepository);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 1: Boundary & Retention Invariants (0..10 -> 0 pruned; 11 -> 1 pruned)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("CH-1.1: Boundary 0..10 runs — zero pruning happens until 11th run")
    void challenge_zeroPruning_until11thRun() {
        for (int i = 1; i <= 10; i++) {
            ValidationRunService.ExecutionResult result = service.executeRun(
                    new ValidationRunForm("Alice Run " + i, "https://scim.example.com/v2", "tok"), ALICE_EMAIL);
            assertThat(result.isOldRunDeleted())
                    .as("Run %d must not trigger pruning", i)
                    .isFalse();
            assertThat(runRepository.findOwnedRuns(ALICE_EMAIL, Sort.unsorted()))
                    .hasSize(i);
        }

        // 11th run MUST trigger pruning of exactly 1 run
        ValidationRunService.ExecutionResult r11 = service.executeRun(
                new ValidationRunForm("Alice Run 11", "https://scim.example.com/v2", "tok"), ALICE_EMAIL);
        assertThat(r11.isOldRunDeleted()).isTrue();
        assertThat(runRepository.findOwnedRuns(ALICE_EMAIL, Sort.unsorted()))
                .as("Total unpublished runs must remain capped at exactly 10")
                .hasSize(10);
    }

    @Test
    @DisplayName("CH-1.2: Pruning strictly removes the oldest run by executedAt")
    void challenge_pruning_removesStrictlyOldest() {
        List<UUID> runIds = new ArrayList<>();
        OffsetDateTime baseTime = OffsetDateTime.now().minusDays(1);

        for (int i = 1; i <= 10; i++) {
            ValidationRun run = createRun(alice, "Run " + i);
            run.setExecutedAt(baseTime.plusMinutes(i * 10));
            runIds.add(run.getId());
        }

        UUID expectedPrunedId = runIds.get(0); // Oldest run (i=1)

        ValidationRunService.ExecutionResult r11 = service.executeRun(
                new ValidationRunForm("Run 11", "https://scim.example.com/v2", "tok"), ALICE_EMAIL);

        assertThat(r11.isOldRunDeleted()).isTrue();
        assertThat(runRepository.findById(expectedPrunedId))
                .as("Oldest run (Run 1) must be pruned")
                .isEmpty();

        // Verify remaining 9 runs are still present
        for (int i = 1; i < 10; i++) {
            assertThat(runRepository.findById(runIds.get(i)))
                    .as("Run %d must still exist", i + 1)
                    .isPresent();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 2: Published Runs Immunity Under Heavy Co-existence
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("CH-2.1: 10 unpublished + 10 published runs — 11th run prunes only unpublished, 0 published pruned")
    void challenge_tenUnpublishedTenPublished_prunesOnlyUnpublished() {
        // Create 10 published runs
        List<UUID> publishedIds = new ArrayList<>();
        for (int i = 1; i <= 10; i++) {
            ValidationRun pubRun = createPublishedRun(alice, "Published " + i, OffsetDateTime.now().minusHours(20 - i));
            publishedIds.add(pubRun.getId());
        }

        // Create 10 unpublished runs
        List<UUID> unpublishedIds = new ArrayList<>();
        for (int i = 1; i <= 10; i++) {
            ValidationRun unpubRun = createRun(alice, "Unpublished " + i);
            unpubRun.setExecutedAt(OffsetDateTime.now().minusMinutes(30 - i));
            unpublishedIds.add(unpubRun.getId());
        }

        assertThat(runRepository.findOwnedRuns(ALICE_EMAIL, Sort.unsorted())).hasSize(10);
        assertThat(publicationRepository.countOwnedPublications(ALICE_EMAIL)).isEqualTo(10L);

        // Execute 11th unpublished run
        ValidationRunService.ExecutionResult result = service.executeRun(
                new ValidationRunForm("Unpublished 11", "https://scim.example.com/v2", "tok"), ALICE_EMAIL);

        assertThat(result.isOldRunDeleted()).isTrue();

        // Check oldest unpublished was pruned
        assertThat(runRepository.findById(unpublishedIds.get(0))).isEmpty();

        // Check ALL 10 published runs are 100% intact
        for (UUID pubId : publishedIds) {
            assertThat(runRepository.findById(pubId))
                    .as("Published run %s must not be pruned", pubId)
                    .isPresent();
            assertThat(publicationRepository.findById(pubId))
                    .as("Publication record %s must not be pruned", pubId)
                    .isPresent();
        }
        assertThat(publicationRepository.countOwnedPublications(ALICE_EMAIL)).isEqualTo(10L);
    }

    @Test
    @DisplayName("CH-2.2: 50 published runs + 0 unpublished runs — starting 1st unpublished causes 0 pruning")
    void challenge_fiftyPublishedZeroUnpublished_noPruningOnFirstRun() {
        for (int i = 1; i <= 50; i++) {
            createPublishedRun(alice, "Pub " + i, OffsetDateTime.now().minusDays(51 - i));
        }

        assertThat(publicationRepository.countOwnedPublications(ALICE_EMAIL)).isEqualTo(50L);
        assertThat(runRepository.findOwnedRuns(ALICE_EMAIL, Sort.unsorted())).isEmpty();

        ValidationRunService.ExecutionResult result = service.executeRun(
                new ValidationRunForm("Working Run 1", "https://scim.example.com/v2", "tok"), ALICE_EMAIL);

        assertThat(result.isOldRunDeleted()).isFalse();
        assertThat(runRepository.findOwnedRuns(ALICE_EMAIL, Sort.unsorted())).hasSize(1);
        assertThat(publicationRepository.countOwnedPublications(ALICE_EMAIL)).isEqualTo(50L);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 3: Published Run Quota Rejection (50 published cap)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("CH-3.1: Publishing quota boundary — 49 allowed, 50 cap rejects 51st")
    void challenge_publishedQuota_capAt50() {
        for (int i = 1; i <= 49; i++) {
            createPublishedRun(alice, "Published " + i, OffsetDateTime.now());
        }

        // At 49 published: validatePublishQuota must succeed cleanly
        assertThatCode(() -> service.validatePublishQuota(ALICE_EMAIL))
                .doesNotThrowAnyException();

        // Create 50th published run
        createPublishedRun(alice, "Published 50", OffsetDateTime.now());

        // At 50 published: validatePublishQuota must throw 400 Bad Request
        assertThatThrownBy(() -> service.validatePublishQuota(ALICE_EMAIL))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> {
                    ResponseStatusException rse = (ResponseStatusException) ex;
                    assertThat(rse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
                    assertThat(rse.getReason()).contains("maximum published compliance runs cap (50)");
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"alice@example.com", "Alice@Example.Com", "ALICE@EXAMPLE.COM"})
    @DisplayName("CH-3.2: Published run quota is case-insensitive across email variations")
    void challenge_publishedQuota_caseInsensitive(String emailVariation) {
        for (int i = 1; i <= 50; i++) {
            createPublishedRun(alice, "Pub " + i, OffsetDateTime.now());
        }

        assertThatThrownBy(() -> service.validatePublishQuota(emailVariation))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> {
                    ResponseStatusException rse = (ResponseStatusException) ex;
                    assertThat(rse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
                });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 4: Deletion Guards (Admin vs Non-Admin, Published vs Unpublished)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("CH-4.1: Non-admin deleting their own published run is blocked with 409 Conflict")
    void challenge_nonAdmin_cannotDeletePublishedRun() {
        ValidationRun pubRun = createPublishedRun(alice, "Certified SCIM 2.0", OffsetDateTime.now());
        UUID runId = pubRun.getId();

        assertThatThrownBy(() -> service.deleteRun(runId, ALICE_EMAIL, false))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> {
                    ResponseStatusException rse = (ResponseStatusException) ex;
                    assertThat(rse.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
                    assertThat(rse.getReason()).contains("Published compliance runs cannot be deleted");
                });

        // Run and publication MUST still exist
        assertThat(runRepository.findById(runId)).isPresent();
        assertThat(publicationRepository.findById(runId)).isPresent();
    }

    @Test
    @DisplayName("CH-4.2: Admin deleting a published run is also blocked with 409 Conflict")
    void challenge_admin_canDeletePublishedRun() {
        ValidationRun pubRun = createPublishedRun(alice, "Certified SCIM 2.0", OffsetDateTime.now());
        UUID runId = pubRun.getId();

        assertThatThrownBy(() -> service.deleteRun(runId, ADMIN_EMAIL, true))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> {
                    ResponseStatusException rse = (ResponseStatusException) ex;
                    assertThat(rse.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
                    assertThat(rse.getReason()).contains("Published compliance runs cannot be deleted");
                });

        // Run and publication MUST still exist
        assertThat(runRepository.findById(runId)).isPresent();
        assertThat(publicationRepository.findById(runId)).isPresent();
    }

    @Test
    @DisplayName("CH-4.3: Non-admin deleting another user's published run throws 404 (not leaking existence)")
    void challenge_nonAdmin_deletingOtherUserPublishedRun_throws404() {
        ValidationRun pubRun = createPublishedRun(alice, "Alice's Cert", OffsetDateTime.now());
        UUID runId = pubRun.getId();

        assertThatThrownBy(() -> service.deleteRun(runId, BOB_EMAIL, false))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> {
                    ResponseStatusException rse = (ResponseStatusException) ex;
                    assertThat(rse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
                });

        // Alice's run is untouched
        assertThat(runRepository.findById(runId)).isPresent();
        assertThat(publicationRepository.findById(runId)).isPresent();
    }

    @Test
    @DisplayName("CH-4.4: Non-admin deleting their own unpublished run succeeds")
    void challenge_nonAdmin_canDeleteOwnUnpublishedRun() {
        ValidationRun unpubRun = createRun(alice, "Draft Run");
        UUID runId = unpubRun.getId();

        service.deleteRun(runId, ALICE_EMAIL, false);
        assertThat(runRepository.findById(runId)).isEmpty();
    }

    @Test
    @DisplayName("CH-4.5: Deleting non-existent run throws 404 for both user and admin")
    void challenge_deletingNonExistentRun_throws404() {
        UUID nonExistentId = UUID.randomUUID();

        assertThatThrownBy(() -> service.deleteRun(nonExistentId, ALICE_EMAIL, false))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND));

        assertThatThrownBy(() -> service.deleteRun(nonExistentId, ADMIN_EMAIL, true))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 5: Multi-Tenant Workspace Isolation
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("CH-5.1: Multi-tenant isolation — Alice reaching cap never prunes Bob's runs")
    void challenge_multiTenantIsolation() {
        // Bob has 5 runs
        List<UUID> bobRunIds = new ArrayList<>();
        for (int i = 1; i <= 5; i++) {
            bobRunIds.add(createRun(bob, "Bob Run " + i).getId());
        }

        // Alice has 10 runs
        List<UUID> aliceRunIds = new ArrayList<>();
        for (int i = 1; i <= 10; i++) {
            ValidationRun r = createRun(alice, "Alice Run " + i);
            r.setExecutedAt(OffsetDateTime.now().minusMinutes(20 - i));
            aliceRunIds.add(r.getId());
        }

        // Alice executes 11th run -> Alice's oldest pruned
        service.executeRun(new ValidationRunForm("Alice Run 11", "https://scim.example.com/v2", "tok"), ALICE_EMAIL);

        assertThat(runRepository.findById(aliceRunIds.get(0))).isEmpty();
        assertThat(runRepository.findOwnedRuns(ALICE_EMAIL, Sort.unsorted())).hasSize(10);

        // Bob's runs MUST be 100% untouched
        for (UUID bobId : bobRunIds) {
            assertThat(runRepository.findById(bobId)).isPresent();
        }
        assertThat(runRepository.findOwnedRuns(BOB_EMAIL, Sort.unsorted())).hasSize(5);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 6: Asynchronous Run Execution Boundary & Pruning Consistency
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("CH-6.1: Async execution enforces exact same 10-run unpublished cap and pruning")
    void challenge_asyncRunPruning_matchesSync() {
        List<UUID> runIds = new ArrayList<>();
        for (int i = 1; i <= 10; i++) {
            ValidationRun r = createRun(alice, "Run " + i);
            r.setExecutedAt(OffsetDateTime.now().minusMinutes(15 - i));
            runIds.add(r.getId());
        }

        ValidationRunService.ExecutionResult result = service.executeRunAsync(
                new ValidationRunForm("Async Run 11", "https://scim.example.com/v2", "tok"), ALICE_EMAIL);

        assertThat(result.isOldRunDeleted()).isTrue();
        assertThat(runRepository.findById(runIds.get(0))).isEmpty();
        assertThat(runRepository.findOwnedRuns(ALICE_EMAIL, Sort.unsorted())).hasSize(10);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 7: Backlog Surge Pruning (Surge beyond 10 runs)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("CH-7.1: Legacy backlog surge — 25 unpublished runs prunes 16 runs down to exactly 10")
    void challenge_backlogSurge_prunesMultipleDownToTen() {
        List<UUID> runIds = new ArrayList<>();
        OffsetDateTime base = OffsetDateTime.now().minusHours(30);
        for (int i = 1; i <= 25; i++) {
            ValidationRun r = createRun(alice, "Surge Run " + i);
            r.setExecutedAt(base.plusMinutes(i));
            runIds.add(r.getId());
        }

        assertThat(runRepository.findOwnedRuns(ALICE_EMAIL, Sort.unsorted())).hasSize(25);

        ValidationRunService.ExecutionResult result = service.executeRun(
                new ValidationRunForm("Surge Run 26", "https://scim.example.com/v2", "tok"), ALICE_EMAIL);

        assertThat(result.isOldRunDeleted()).isTrue();
        // 25 - 10 + 1 = 16 pruned (indices 0..15)
        for (int i = 0; i < 16; i++) {
            assertThat(runRepository.findById(runIds.get(i)))
                    .as("Run %d must have been pruned", i + 1)
                    .isEmpty();
        }
        // Indices 16..24 (9 runs) plus the new run (1 run) = 10 runs
        for (int i = 16; i < 25; i++) {
            assertThat(runRepository.findById(runIds.get(i)))
                    .as("Run %d must still exist", i + 1)
                    .isPresent();
        }
        assertThat(runRepository.findOwnedRuns(ALICE_EMAIL, Sort.unsorted())).hasSize(10);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 8: Interleaved Publish & Execution Lifecycle Invariants
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("CH-8.1: Continuous interleaved lifecycle — publishing preserves published, prunes unpublished")
    void challenge_interleavedLifecycle() {
        // Step 1: Create 10 runs
        for (int i = 1; i <= 10; i++) {
            service.executeRun(new ValidationRunForm("Step1 Run " + i, "https://scim.example.com/v2", "tok"), ALICE_EMAIL);
        }
        assertThat(runRepository.findOwnedRuns(ALICE_EMAIL, Sort.unsorted())).hasSize(10);
        assertThat(publicationRepository.countOwnedPublications(ALICE_EMAIL)).isEqualTo(0L);

        // Step 2: Publish 3 runs
        List<ValidationRun> owned = runRepository.findOwnedRuns(ALICE_EMAIL, Sort.unsorted());
        for (int i = 0; i < 3; i++) {
            ValidationRun r = owned.get(i);
            ValidationRunPublication pub = new ValidationRunPublication();
            setField(pub, "runId", r.getId());
            setField(pub, "run", r);
            setField(pub, "createdByEmail", ALICE_EMAIL);
            setField(pub, "productName", "Product " + i);
            setField(pub, "productSlug", "product-" + i);
            setField(pub, "productVersion", "1.0");
            setField(pub, "licenseType", "Apache-2.0");
            setField(pub, "reportUrl", "https://scimsandbox.net/reports/" + r.getId());
            setField(pub, "badgeUrl", "https://scimsandbox.net/badges/" + r.getId() + ".svg");
            setField(pub, "publishedAt", OffsetDateTime.now());
            r.setPublication(pub);
            publicationRepository.save(pub);
        }

        // Now: 7 unpublished, 3 published
        assertThat(runRepository.findOwnedRuns(ALICE_EMAIL, Sort.unsorted())).hasSize(7);
        assertThat(publicationRepository.countOwnedPublications(ALICE_EMAIL)).isEqualTo(3L);

        // Step 3: Run 3 more -> reaches 10 unpublished with 0 pruning
        for (int i = 1; i <= 3; i++) {
            ValidationRunService.ExecutionResult res = service.executeRun(
                    new ValidationRunForm("Step3 Run " + i, "https://scim.example.com/v2", "tok"), ALICE_EMAIL);
            assertThat(res.isOldRunDeleted()).isFalse();
        }
        assertThat(runRepository.findOwnedRuns(ALICE_EMAIL, Sort.unsorted())).hasSize(10);
        assertThat(publicationRepository.countOwnedPublications(ALICE_EMAIL)).isEqualTo(3L);

        // Step 4: Run 1 more -> prunes oldest unpublished, leaving published intact
        ValidationRunService.ExecutionResult res4 = service.executeRun(
                new ValidationRunForm("Step4 Run 1", "https://scim.example.com/v2", "tok"), ALICE_EMAIL);
        assertThat(res4.isOldRunDeleted()).isTrue();
        assertThat(runRepository.findOwnedRuns(ALICE_EMAIL, Sort.unsorted())).hasSize(10);
        assertThat(publicationRepository.countOwnedPublications(ALICE_EMAIL)).isEqualTo(3L);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 9: Null and Blank Safety on Service Quota Methods
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("CH-9.1: Service count queries handle null safely without NPE")
    void challenge_nullSafety() {
        assertThat(service.countOwnedPublications(null)).isEqualTo(0L);
        assertThat(service.countOwnedRuns(null)).isEqualTo(0L);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Challenge 10: Admin Deletion of Published Run Cleans Up Publication & Frees Quota
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("CH-10.1: Admin deletion of published run is blocked and preserves publication quota")
    void challenge_adminDelete_cascadeAndQuotaLiberation() {
        ValidationRun pubRun = createPublishedRun(alice, "Certified Cascade", OffsetDateTime.now());
        UUID runId = pubRun.getId();

        assertThat(publicationRepository.findById(runId)).isPresent();
        assertThat(service.countOwnedPublications(ALICE_EMAIL)).isEqualTo(1L);

        assertThatThrownBy(() -> service.deleteRun(runId, ADMIN_EMAIL, true))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode()).isEqualTo(HttpStatus.CONFLICT));

        assertThat(runRepository.findById(runId)).isPresent();
        assertThat(publicationRepository.findById(runId)).isPresent();
        assertThat(service.countOwnedPublications(ALICE_EMAIL)).isEqualTo(1L);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper Methods & Test Double Setup
    // ─────────────────────────────────────────────────────────────────────────

    private ValidationRun createRun(ValidationMgmtUser owner, String name) {
        ValidationRun run = new ValidationRun();
        run.setName(name);
        run.setTargetUrl("https://scim.example.com/v2");
        run.setExecutedAt(OffsetDateTime.now());
        run.setStatus("PASSED");
        run.setCreatedByUser(owner);
        setField(run, "id", UUID.randomUUID());
        return runRepository.save(run);
    }

    private ValidationRun createPublishedRun(ValidationMgmtUser owner, String name, OffsetDateTime pubTime) {
        ValidationRun run = createRun(owner, name);
        ValidationRunPublication pub = new ValidationRunPublication();
        setField(pub, "runId", run.getId());
        setField(pub, "run", run);
        setField(pub, "createdByEmail", owner.getEmail());
        setField(pub, "productName", name);
        setField(pub, "productSlug", name.toLowerCase().replace(" ", "-"));
        setField(pub, "productVersion", "1.0.0");
        setField(pub, "licenseType", "Apache-2.0");
        setField(pub, "reportUrl", "https://scimsandbox.net/reports/" + run.getId());
        setField(pub, "badgeUrl", "https://scimsandbox.net/badges/" + run.getId() + ".svg");
        setField(pub, "publishedAt", pubTime);
        run.setPublication(pub);
        publicationRepository.save(pub);
        return run;
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

    private static class ChallengerValidationRunService extends ValidationRunService {
        public ChallengerValidationRunService(
                ValidationRunRepository runRepository,
                ValidationMgmtUserRepository userRepository,
                ValidationRunPublicationRepository publicationRepository) {
            super(runRepository, userRepository, null, null, publicationRepository, null, Executors.newCachedThreadPool());
        }

        @Override
        int discoverTestCount(String baseUrl, String authToken) {
            return 253;
        }

        @Override
        void executeLauncher(Launcher launcher, LauncherDiscoveryRequest request, TestExecutionListener listener) {
            // Hermetic in-memory execution double
        }
    }

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
