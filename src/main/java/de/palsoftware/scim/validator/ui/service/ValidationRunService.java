package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.base.ScimBaseSpec;
import de.palsoftware.scim.validator.base.ScimHttpExchange;
import de.palsoftware.scim.validator.base.ScimRunContext;
import de.palsoftware.scim.validator.base.ValidatorConfiguration;
import de.palsoftware.scim.validator.ui.dto.ValidationHttpExchangeView;
import de.palsoftware.scim.validator.ui.dto.ValidationRunForm;
import de.palsoftware.scim.validator.ui.dto.ValidationRunView;
import de.palsoftware.scim.validator.ui.dto.ValidationTestResultView;
import de.palsoftware.scim.validator.ui.model.ValidationMgmtUser;
import de.palsoftware.scim.validator.ui.model.ValidationHttpExchange;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationRunPublication;
import de.palsoftware.scim.validator.ui.model.ValidationTestResult;
import de.palsoftware.scim.validator.ui.model.spec.ComplianceCatalogEntry;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublicationResult;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublishRequest;
import de.palsoftware.scim.validator.ui.repo.ValidationMgmtUserRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationHttpExchangeRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationRunPublicationRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationRunRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationTestResultRepository;
import de.palsoftware.scim.validator.ui.security.PinnedTargetHttpSupport;
import de.palsoftware.scim.validator.ui.security.TargetUrlPolicy;
import de.palsoftware.scim.validator.ui.util.BaseUrl;
import de.palsoftware.scim.validator.ui.util.Slugifier;
import jakarta.annotation.PreDestroy;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.support.descriptor.MethodSource;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

/**
 * Service managing SCIM validation run execution, persistence, and compliance publication reservations.
 *
 * <p><strong>Concurrency &amp; Deployment Assumption:</strong> Quota enforcement, product-slug ownership
 * reservation locking ({@code reservationLock}), and in-memory reconciliation tracking
 * ({@code reconciliationRequiredRunIds}, {@code pendingReconciliations}) are designed for a single
 * application instance ({@code replicas: 1} in Kubernetes). Scaling horizontally beyond a single replica
 * requires migrating these guards to database-level pessimistic locking ({@code SELECT ... FOR UPDATE})
 * or distributed locks.</p>
 */
@Service
public class ValidationRunService {

    private static final Logger log = LoggerFactory.getLogger(ValidationRunService.class);

    public static final int DEFAULT_MAX_CONCURRENT_RUNS = 4;
    public static final int DEFAULT_MAX_QUEUE_SIZE = 8;
    public static final int DEFAULT_MAX_ACTIVE_RUNS_PER_USER = 2;
    public static final long DEFAULT_STALE_RUNNING_TIMEOUT_MINUTES = 60L;
    public static final int MAX_DB_TEXT_BYTES = 2 * 1024 * 1024;
    static final int MIN_RAW_SECRET_SCRUB_LENGTH = 8;

    static final String STATUS_RUNNING = "RUNNING";
    static final String STATUS_ERROR = "ERROR";
    static final String MSG_ABRUPT_RUNTIME_ABORT = "Validation run aborted due to an unexpected runtime error";
    static final String MSG_RUN_INTERRUPTED = "Validation run interrupted";
    static final String MSG_STARTUP_ORPHAN_ABORT = "Validation run interrupted by server restart";
    static final String MSG_STALE_RUN_TIMEOUT = "Validation run timed out";
    static final String TRUNCATED_SUFFIX = "...[truncated]";
    static final String DEFAULT_PUBLIC_COMPLIANCE_BASE_URL = "https://scimsandbox.org";
    private static final int MAX_RUN_NAME_CHARS = 200;
    private static final int MAX_TARGET_URL_CHARS = 500;
    private static final int MAX_TEST_IDENTIFIER_CHARS = 500;
    private static final int MAX_DISPLAY_NAME_CHARS = 500;
    private static final int MAX_CLASS_NAME_CHARS = 300;
    private static final int MAX_TEST_NAME_CHARS = 300;
    private static final int MAX_EXCHANGE_METHOD_CHARS = 16;
    private static final int MAX_EXCHANGE_URL_CHARS = 1000;
    private static final int MAX_PRODUCT_NAME_CHARS = 120;
    private static final int MAX_PRODUCT_SLUG_CHARS = 120;
    private static final int MAX_PRODUCT_VERSION_CHARS = 60;
    private static final int MAX_VENDOR_NAME_CHARS = 120;
    private static final int MAX_LICENSE_TYPE_CHARS = 40;
    private static final int MAX_PUBLICATION_URL_CHARS = 500;

    private static final AtomicInteger RUNNER_THREAD_COUNTER = new AtomicInteger(0);
    private static final Pattern AUTH_HEADER_SCRUB_PATTERN = Pattern.compile(
            "(?im)(Authorization[\"']?+\\s*+[:=]\\s*+[\"']?+(?:Bearer|Basic)\\s++)[^\\s,;\"'\\r\\n}]++");
    private static final Pattern BEARER_TOKEN_SCRUB_PATTERN = Pattern.compile(
            "(?i)(\\bBearer\\s++)[A-Za-z0-9._~+/=-]{8,}+");
    private static final Pattern SAFE_PRODUCT_SLUG_PATTERN = Pattern.compile(
            "^[a-z0-9]++(?:-[a-z0-9]++)*+$");
    private static final Pattern SAFE_HTTP_URL_SCHEME_HOST_PATTERN = Pattern.compile(
            "^[Hh][Tt][Tt][Pp][Ss]?://[^/?#@\\s]\\S*+$",
            Pattern.UNICODE_CHARACTER_CLASS);
    private static final Pattern HTTP_URL_USERINFO_PATTERN = Pattern.compile(
            "^[Hh][Tt][Tt][Pp][Ss]?://[^/?#]*@");

    private final ValidationRunRepository runRepository;
    private final ValidationMgmtUserRepository mgmtUserRepository;
    private final ValidationTestResultRepository testResultRepository;
    private final ValidationHttpExchangeRepository exchangeRepository;
    private final ValidationRunPublicationRepository publicationRepository;
    private final ValidationProgressTracker progressTracker;
    private final ExecutorService executorService;
    private final boolean ownsExecutor;

    private Semaphore concurrentRunPermits;
    private TargetUrlPolicy targetUrlPolicy;
    private PlatformTransactionManager transactionManager;
    private SpecCatalogService specCatalogService;

    public ValidationRunService(ValidationRunRepository runRepository,
            ValidationMgmtUserRepository mgmtUserRepository,
            ValidationTestResultRepository testResultRepository,
            ValidationHttpExchangeRepository exchangeRepository) {
        this(runRepository, mgmtUserRepository, testResultRepository, exchangeRepository,
                null, new ValidationProgressTracker(), null);
    }

    public ValidationRunService(ValidationRunRepository runRepository,
            ValidationMgmtUserRepository mgmtUserRepository,
            ValidationTestResultRepository testResultRepository,
            ValidationHttpExchangeRepository exchangeRepository,
            ValidationProgressTracker progressTracker) {
        this(runRepository, mgmtUserRepository, testResultRepository, exchangeRepository,
                null, progressTracker, null);
    }

    public ValidationRunService(ValidationRunRepository runRepository,
            ValidationMgmtUserRepository mgmtUserRepository,
            ValidationTestResultRepository testResultRepository,
            ValidationHttpExchangeRepository exchangeRepository,
            ValidationProgressTracker progressTracker,
            ExecutorService executorService) {
        this(runRepository, mgmtUserRepository, testResultRepository, exchangeRepository,
                null, progressTracker, executorService);
    }

    public ValidationRunService(ValidationRunRepository runRepository,
            ValidationMgmtUserRepository mgmtUserRepository,
            ValidationTestResultRepository testResultRepository,
            ValidationHttpExchangeRepository exchangeRepository,
            ValidationRunPublicationRepository publicationRepository,
            ValidationProgressTracker progressTracker) {
        this(runRepository, mgmtUserRepository, testResultRepository, exchangeRepository,
                publicationRepository, progressTracker, null);
    }

    public ValidationRunService(ValidationRunRepository runRepository,
            ValidationMgmtUserRepository mgmtUserRepository,
            ValidationTestResultRepository testResultRepository,
            ValidationHttpExchangeRepository exchangeRepository,
            ValidationRunPublicationRepository publicationRepository,
            ValidationProgressTracker progressTracker,
            ExecutorService executorService) {
        this(runRepository, mgmtUserRepository, testResultRepository, exchangeRepository,
                publicationRepository, progressTracker, executorService,
                null, null, null, null, null);
    }

    @Autowired
    public ValidationRunService(ValidationRunRepository runRepository,
            ValidationMgmtUserRepository mgmtUserRepository,
            ValidationTestResultRepository testResultRepository,
            ValidationHttpExchangeRepository exchangeRepository,
            @Autowired(required = false) ValidationRunPublicationRepository publicationRepository,
            ValidationProgressTracker progressTracker,
            @Autowired(required = false) TargetUrlPolicy targetUrlPolicy,
            @Autowired(required = false) PlatformTransactionManager transactionManager,
            @Autowired(required = false) SpecCatalogService specCatalogService,
            @Value("${app.runs.max-concurrent:4}") Integer maxConcurrentRuns,
            @Value("${app.runs.max-queue-size:8}") Integer maxQueueSize) {
        this(runRepository, mgmtUserRepository, testResultRepository, exchangeRepository,
                publicationRepository, progressTracker, null,
                targetUrlPolicy, transactionManager, specCatalogService, maxConcurrentRuns, maxQueueSize);
    }

    private ValidationRunService(ValidationRunRepository runRepository,
            ValidationMgmtUserRepository mgmtUserRepository,
            ValidationTestResultRepository testResultRepository,
            ValidationHttpExchangeRepository exchangeRepository,
            ValidationRunPublicationRepository publicationRepository,
            ValidationProgressTracker progressTracker,
            ExecutorService executorService,
            TargetUrlPolicy targetUrlPolicy,
            PlatformTransactionManager transactionManager,
            SpecCatalogService specCatalogService,
            Integer maxConcurrentRuns,
            Integer maxQueueSize) {
        this.runRepository = runRepository;
        this.mgmtUserRepository = mgmtUserRepository;
        this.testResultRepository = testResultRepository;
        this.exchangeRepository = exchangeRepository;
        this.publicationRepository = publicationRepository;
        this.progressTracker = progressTracker != null ? progressTracker : new ValidationProgressTracker();
        int effectiveMaxConcurrent = maxConcurrentRuns != null
                ? Math.max(1, maxConcurrentRuns)
                : DEFAULT_MAX_CONCURRENT_RUNS;
        if (executorService != null) {
            this.executorService = executorService;
            this.ownsExecutor = false;
            if (maxConcurrentRuns == null && executorService instanceof ThreadPoolExecutor tpe) {
                effectiveMaxConcurrent = Math.max(1, tpe.getMaximumPoolSize());
            }
        } else {
            int queueSize = maxQueueSize != null ? maxQueueSize : DEFAULT_MAX_QUEUE_SIZE;
            this.executorService = createBoundedRunExecutor(effectiveMaxConcurrent, queueSize);
            this.ownsExecutor = true;
        }
        this.concurrentRunPermits = new Semaphore(effectiveMaxConcurrent);
        this.targetUrlPolicy = Objects.requireNonNullElse(targetUrlPolicy, TargetUrlPolicy.DEFAULT_STRICT);
        this.transactionManager = transactionManager;
        this.specCatalogService = specCatalogService;
    }

    public static ThreadPoolExecutor createBoundedRunExecutor(int maxConcurrentRuns, int maxQueueSize) {
        int poolSize = Math.max(1, maxConcurrentRuns);
        int queueCapacity = Math.max(1, maxQueueSize);
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
                poolSize,
                poolSize,
                60L,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(queueCapacity),
                runnable -> {
                    Thread thread = new Thread(runnable,
                            "scim-validation-runner-" + RUNNER_THREAD_COUNTER.incrementAndGet());
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy()
        );
        executor.allowCoreThreadTimeOut(true);
        return executor;
    }

    @PreDestroy
    public void shutdownExecutor() {
        if (ownsExecutor) {
            List<Runnable> dropped = executorService.shutdownNow();
            cancelDroppedAsyncTasks(dropped);
        }
    }

    static void cancelDroppedAsyncTasks(List<Runnable> droppedTasks) {
        if (droppedTasks == null) {
            return;
        }
        for (Runnable task : droppedTasks) {
            if (task instanceof CancelableAsyncRunTask cancelable) {
                cancelable.cancelQueuedOnShutdown();
            }
        }
    }

    @Value("${app.runs.max-per-user:10}")
    private int maxRunsPerUser = 10;

    @Value("${app.runs.max-published-per-user:50}")
    private int maxPublishedRunsPerUser = 50;

    @Value("${app.runs.max-active-per-user:2}")
    private int maxActiveRunsPerUser = DEFAULT_MAX_ACTIVE_RUNS_PER_USER;

    @Value("${app.runs.stale-running-timeout-minutes:60}")
    private long staleRunningTimeoutMinutes = DEFAULT_STALE_RUNNING_TIMEOUT_MINUTES;

    @Value("${app.compliance.public-base-url}")
    private String publicBaseUrl;

    @Value("${app.compliance.reservation-timeout-seconds:300}")
    private long reservationTimeoutSeconds = 300;

    public static final int DEFAULT_DISCOVERED_TEST_COUNT = 280;

    public record PendingReconciliation(
            String actorEmail,
            CompliancePublishRequest request,
            CompliancePublicationResult result
    ) {}

    private final Set<UUID> reconciliationRequiredRunIds = ConcurrentHashMap.newKeySet();
    private final Map<UUID, PendingReconciliation> pendingReconciliations = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> activeRunsByUser = new ConcurrentHashMap<>();
    private final Set<UUID> activeRunIds = ConcurrentHashMap.newKeySet();

    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }

    public void setSpecCatalogService(SpecCatalogService specCatalogService) {
        this.specCatalogService = specCatalogService;
    }

    public void setTargetUrlPolicy(TargetUrlPolicy targetUrlPolicy) {
        this.targetUrlPolicy = Objects.requireNonNullElse(targetUrlPolicy, TargetUrlPolicy.DEFAULT_STRICT);
    }

    public void setMaxConcurrentRuns(int maxConcurrentRuns) {
        this.concurrentRunPermits = new Semaphore(Math.max(1, maxConcurrentRuns));
    }

    public void setMaxActiveRunsPerUser(int maxActiveRunsPerUser) {
        this.maxActiveRunsPerUser = Math.max(1, maxActiveRunsPerUser);
    }

    public int getMaxActiveRunsPerUser() {
        return maxActiveRunsPerUser;
    }

    public void setStaleRunningTimeoutMinutes(long staleRunningTimeoutMinutes) {
        this.staleRunningTimeoutMinutes = Math.max(1L, staleRunningTimeoutMinutes);
    }

    public long getStaleRunningTimeoutMinutes() {
        return staleRunningTimeoutMinutes;
    }

    boolean isRunActiveInMemory(UUID runId) {
        return runId != null && activeRunIds.contains(runId);
    }

    void registerActiveRunForTesting(UUID runId) {
        if (runId != null) {
            activeRunIds.add(runId);
        }
    }

    void unregisterActiveRunForTesting(UUID runId) {
        if (runId != null) {
            activeRunIds.remove(runId);
        }
    }

    public void markReconciliationRequired(UUID runId) {
        if (runId != null) {
            reconciliationRequiredRunIds.add(runId);
        }
    }

    public void markReconciliationRequired(
            UUID runId,
            String actorEmail,
            CompliancePublishRequest request,
            CompliancePublicationResult result) {
        if (runId != null) {
            reconciliationRequiredRunIds.add(runId);
            if (request != null && result != null) {
                pendingReconciliations.put(runId, new PendingReconciliation(actorEmail, request, result));
            }
        }
    }

    public boolean isReconciliationRequired(UUID runId) {
        return runId != null && reconciliationRequiredRunIds.contains(runId);
    }

    public void clearReconciliationRequired(UUID runId) {
        if (runId != null) {
            reconciliationRequiredRunIds.remove(runId);
            pendingReconciliations.remove(runId);
        }
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public Optional<CompliancePublicationResult> tryReconcilePendingPublication(ValidationRun run) {
        return tryReconcilePendingPublicationInternal(run);
    }

    private Optional<CompliancePublicationResult> tryReconcilePendingPublicationInternal(ValidationRun run) {
        if (run == null || run.getId() == null) {
            return Optional.empty();
        }
        synchronized (reservationLock) {
            UUID runId = run.getId();
            PendingReconciliation pending = pendingReconciliations.get(runId);
            return executeInIsolatedTransaction(() -> {
                ValidationRun managed = resolveManagedRun(run);
                ValidationRunPublication existing = findExistingPublicationOrReservation(managed);
                if (run.isPublished() || managed.isPublished()
                        || (existing != null && !existing.isPendingReservation())) {
                    clearReconciliationRequired(runId);
                    if (existing != null && !existing.isPendingReservation()) {
                        run.setPublication(existing);
                    }
                    if (pending != null && pending.result() != null) {
                        return Optional.of(pending.result());
                    }
                    if (existing != null && !existing.isPendingReservation()) {
                        return Optional.of(CompliancePublicationResult.succeeded(
                                runId,
                                existing.getPrUrl(),
                                existing.getReportUrl(),
                                existing.getBadgeUrl(),
                                "reconciled",
                                existing.getPublishedAt()
                        ));
                    }
                    return Optional.empty();
                }
                if (pending == null) {
                    return Optional.empty();
                }
                recordPublicationInternal(managed, pending.actorEmail(), pending.request(), pending.result());
                if (managed != run && managed.getPublication() != null) {
                    run.setPublication(managed.getPublication());
                }
                return Optional.of(pending.result());
            });
        }
    }

    private <T> T executeInIsolatedTransaction(Supplier<T> action) {
        if (transactionManager != null) {
            TransactionTemplate txTemplate = new TransactionTemplate(transactionManager);
            txTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
            txTemplate.setReadOnly(false);
            return txTemplate.execute(status -> action.get());
        }
        return action.get();
    }

    private <T> T executeInReadWriteTransaction(Supplier<T> action) {
        if (transactionManager != null) {
            TransactionTemplate txTemplate = new TransactionTemplate(transactionManager);
            txTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRED);
            txTemplate.setReadOnly(false);
            return txTemplate.execute(status -> action.get());
        }
        return action.get();
    }

    public int getMaxRunsPerUser() {
        return maxRunsPerUser;
    }

    public int getMaxPublishedRunsPerUser() {
        return maxPublishedRunsPerUser;
    }

    public String getEffectivePublicBaseUrl() {
        return BaseUrl.require("app.compliance.public-base-url", publicBaseUrl);
    }

    public void setPublicBaseUrl(String publicBaseUrl) {
        this.publicBaseUrl = publicBaseUrl;
    }

    public long getReservationTimeoutSeconds() {
        return reservationTimeoutSeconds;
    }

    public void setReservationTimeoutSeconds(long reservationTimeoutSeconds) {
        this.reservationTimeoutSeconds = reservationTimeoutSeconds;
    }

    public Duration getReservationTimeout() {
        return Duration.ofSeconds(Math.max(1L, reservationTimeoutSeconds));
    }

    public boolean isStaleReservation(ValidationRunPublication publication) {
        if (publication != null && publication.getRunId() != null
                && reconciliationRequiredRunIds.contains(publication.getRunId())) {
            return false;
        }
        return publication != null && publication.isStalePendingReservation(getReservationTimeout());
    }

    public static class ExecutionResult {
        private final ValidationRun run;
        private final boolean oldRunDeleted;
        private final int maxRuns;

        public ExecutionResult(ValidationRun run, boolean oldRunDeleted, int maxRuns) {
            this.run = run;
            this.oldRunDeleted = oldRunDeleted;
            this.maxRuns = maxRuns;
        }

        public ValidationRun getRun() { return run; }
        public boolean isOldRunDeleted() { return oldRunDeleted; }
        public int getMaxRuns() { return maxRuns; }
    }

    private String acquireActiveRunSlot(String actorEmail) {
        String key = (actorEmail != null && !actorEmail.isBlank())
                ? actorEmail.trim().toLowerCase(Locale.ROOT)
                : "__anonymous__";
        int limit = Math.max(1, maxActiveRunsPerUser);
        AtomicBoolean acquired = new AtomicBoolean(false);
        activeRunsByUser.compute(key, (k, existing) -> {
            int current = existing == null ? 0 : existing.get();
            if (current >= limit) {
                return existing;
            }
            acquired.set(true);
            return new AtomicInteger(current + 1);
        });
        if (!acquired.get()) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                    "Too many concurrent validation runs for your account (maximum " + limit
                            + " active runs). Please wait for a running suite to finish.");
        }
        return key;
    }

    private void releaseActiveRunSlot(String slotKey) {
        if (slotKey == null) {
            return;
        }
        activeRunsByUser.computeIfPresent(slotKey, (k, counter) -> {
            int remaining = counter.decrementAndGet();
            return remaining <= 0 ? null : counter;
        });
    }

    static String scrubSecrets(String text, String authToken) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String scrubbed = text;
        if (authToken != null && !authToken.isBlank()) {
            String trimmed = authToken.trim();
            if (trimmed.length() >= MIN_RAW_SECRET_SCRUB_LENGTH) {
                scrubbed = scrubbed.replace(authToken, "[REDACTED]");
                if (!trimmed.equals(authToken)) {
                    scrubbed = scrubbed.replace(trimmed, "[REDACTED]");
                }
            }
        }
        scrubbed = AUTH_HEADER_SCRUB_PATTERN.matcher(scrubbed).replaceAll("$1[REDACTED]");
        scrubbed = BEARER_TOKEN_SCRUB_PATTERN.matcher(scrubbed).replaceAll("$1[REDACTED]");
        return scrubbed;
    }

    static String truncateUtf8Bytes(String value, int maxBytes) {
        if (value == null) {
            return null;
        }
        byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
        if (utf8.length <= maxBytes) {
            return value;
        }
        if (maxBytes <= 0) {
            return "";
        }
        int suffixLen = TRUNCATED_SUFFIX.length();
        if (maxBytes <= suffixLen) {
            return TRUNCATED_SUFFIX.substring(0, maxBytes);
        }
        int budget = maxBytes - suffixLen;
        int end = budget;
        while (end > 0 && (utf8[end] & 0xC0) == 0x80) {
            end--;
        }
        return new String(utf8, 0, end, StandardCharsets.UTF_8) + TRUNCATED_SUFFIX;
    }

    static String truncateChars(String value, int maxChars) {
        if (value == null || value.length() <= maxChars) {
            return value;
        }
        if (maxChars <= 0) {
            return "";
        }
        int end = maxChars;
        if (Character.isHighSurrogate(value.charAt(end - 1))) {
            end--;
        }
        return value.substring(0, end);
    }

    private boolean pruneOldUnpublishedRuns(String actorEmail) {
        List<ValidationRun> userRuns = runRepository.findOwnedRuns(actorEmail, Sort.by(Sort.Direction.ASC, "executedAt"));
        boolean oldRunDeleted = false;

        if (userRuns.size() >= maxRunsPerUser) {
            int toDelete = userRuns.size() - maxRunsPerUser + 1;
            for (int i = 0; i < toDelete; i++) {
                ValidationRun runToDelete = userRuns.get(i);
                if (runToDelete.isPublished()) {
                    log.warn("Skipping deletion of published run {} during auto-pruning", runToDelete.getId());
                    continue;
                }
                if (runToDelete.hasPendingReservation()) {
                    if (!isStaleReservation(runToDelete.getPublication())) {
                        log.warn("Skipping deletion of run {} with active publication reservation during auto-pruning", runToDelete.getId());
                        continue;
                    }
                    releasePublicationReservationInternal(runToDelete);
                }
                clearReconciliationRequired(runToDelete.getId());
                runRepository.delete(runToDelete);
                oldRunDeleted = true;
            }
        }
        return oldRunDeleted;
    }

    static boolean isDisallowedUrlSpaceOrControl(char c) {
        return Character.isWhitespace(c)
                || Character.isSpaceChar(c)
                || Character.isISOControl(c)
                || c == '\u0085'
                || c == '\u180E'
                || c == '\uFEFF';
    }

    static String trimUnicodeSpaces(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        int start = 0;
        int end = value.length();
        while (start < end && isDisallowedUrlSpaceOrControl(value.charAt(start))) {
            start++;
        }
        while (end > start && isDisallowedUrlSpaceOrControl(value.charAt(end - 1))) {
            end--;
        }
        return (start == 0 && end == value.length()) ? value : value.substring(start, end);
    }

    private static boolean isAsciiAlphaEqual(char c, char lower, char upper) {
        return c == lower || c == upper;
    }

    static String normalizeHttpSchemePrefix(String url) {
        if (url != null && url.length() >= 7
                && isAsciiAlphaEqual(url.charAt(0), 'h', 'H')
                && isAsciiAlphaEqual(url.charAt(1), 't', 'T')
                && isAsciiAlphaEqual(url.charAt(2), 't', 'T')
                && isAsciiAlphaEqual(url.charAt(3), 'p', 'P')) {
            if (url.length() >= 8
                    && isAsciiAlphaEqual(url.charAt(4), 's', 'S')
                    && url.startsWith("://", 5)) {
                return url.startsWith("https://") ? url : "https://" + url.substring(8);
            }
            if (url.startsWith("://", 4)) {
                return url.startsWith("http://") ? url : "http://" + url.substring(7);
            }
        }
        return url;
    }

    static String validateAndNormalizeTargetUrl(String rawBaseUrl) {
        if (rawBaseUrl == null) {
            throw new IllegalArgumentException("Invalid URL: target must not be empty");
        }
        String normalized = trimUnicodeSpaces(rawBaseUrl);
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("Invalid URL: target must not be empty");
        }
        if (normalized.length() > MAX_TARGET_URL_CHARS) {
            throw new IllegalArgumentException(
                    "Invalid URL: target URL must not exceed " + MAX_TARGET_URL_CHARS + " characters");
        }
        for (int i = 0; i < normalized.length(); i++) {
            if (isDisallowedUrlSpaceOrControl(normalized.charAt(i))) {
                throw new IllegalArgumentException(
                        "Invalid URL: target URL must not contain whitespace or control characters");
            }
        }
        return normalizeHttpSchemePrefix(normalized);
    }

    private static String normalizeRunName(String rawName) {
        if (rawName == null) {
            return "";
        }
        return truncateChars(rawName.trim(), MAX_RUN_NAME_CHARS);
    }

    private record InitializedRun(ValidationRun run, boolean oldRunDeleted) {}

    private ValidationRun buildInitialRunningEntity(
            ValidationRunForm form,
            String normalizedTargetUrl,
            String actorEmail,
            int plannedTotal) {
        ValidationRun created = new ValidationRun();
        created.setName(normalizeRunName(form.name()));
        created.setTargetUrl(normalizedTargetUrl);
        created.setExecutedAt(OffsetDateTime.now());
        created.setStatus(STATUS_RUNNING);
        ValidationMgmtUser owner = mgmtUserRepository.findById(actorEmail)
                .orElseThrow(() -> new IllegalStateException("Authenticated management user must exist"));
        created.setCreatedByUser(owner);
        created.setTotalTests(plannedTotal);
        created.setPassedTests(0);
        created.setFailedTests(0);
        return created;
    }

    private void registerTrackedSyncRunId(UUID runId, AtomicReference<UUID> trackedRunIdRef) {
        if (runId != null) {
            trackedRunIdRef.set(runId);
            activeRunIds.add(runId);
        }
    }

    private void releaseTrackedSyncRunId(AtomicReference<UUID> trackedRunIdRef) {
        UUID trackedId = trackedRunIdRef.getAndSet(null);
        if (trackedId != null) {
            activeRunIds.remove(trackedId);
        }
    }

    private void cleanupPostCommitPreSuiteFailure(ValidationRun committedRun, boolean enteredSuite) {
        if (!enteredSuite && committedRun != null && !TransactionSynchronizationManager.isActualTransactionActive()) {
            snapshotAndRecordAbruptTermination(committedRun, committedRun.getId(), null);
        }
    }

    public ExecutionResult executeRun(ValidationRunForm form, String actorEmail) {
        String normalizedTargetUrl = validateAndNormalizeTargetUrl(form.baseUrl());
        TargetUrlPolicy.ResolvedTarget resolvedTarget = targetUrlPolicy.resolve(normalizedTargetUrl);
        String activeSlotKey = acquireActiveRunSlot(actorEmail);
        try {
            if (!concurrentRunPermits.tryAcquire()) {
                throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                        "Server validation capacity reached. Please wait a moment and try again.");
            }
            AtomicReference<UUID> trackedRunIdRef = new AtomicReference<>();
            AtomicReference<ValidationRun> committedRunRef = new AtomicReference<>();
            boolean enteredSuite = false;
            try {
                int plannedTotal;
                try (var ignored = PinnedTargetHttpSupport.pin(resolvedTarget)) {
                    plannedTotal = discoverTestCount(normalizedTargetUrl, form.authToken());
                }

                InitializedRun initialized = executeInReadWriteTransaction(() -> {
                    boolean deleted = pruneOldUnpublishedRuns(actorEmail);
                    ValidationRun created = buildInitialRunningEntity(form, normalizedTargetUrl, actorEmail, plannedTotal);
                    ValidationRun saved = runRepository.save(created);
                    registerTrackedSyncRunId(saved.getId(), trackedRunIdRef);
                    return new InitializedRun(saved, deleted);
                });

                ValidationRun run = initialized.run();
                committedRunRef.set(run);
                boolean oldRunDeleted = initialized.oldRunDeleted();

                UUID runId = run.getId();
                if (runId != null) {
                    progressTracker.registerRun(runId, plannedTotal, "/runs/" + runId);
                }

                enteredSuite = true;
                ValidationRun savedRun = executeSuiteSynchronously(
                        run, runId, normalizedTargetUrl, form.authToken(), plannedTotal, resolvedTarget);
                return new ExecutionResult(savedRun, oldRunDeleted, maxRunsPerUser);
            } finally {
                cleanupPostCommitPreSuiteFailure(committedRunRef.get(), enteredSuite);
                releaseTrackedSyncRunId(trackedRunIdRef);
                concurrentRunPermits.release();
            }
        } finally {
            releaseActiveRunSlot(activeSlotKey);
        }
    }

    private ValidationRun executeSuiteSynchronously(
            ValidationRun run,
            UUID runId,
            String normalizedTargetUrl,
            String authToken,
            int plannedTotal,
            TargetUrlPolicy.ResolvedTarget resolvedTarget) {
        ValidationExecutionListener listener = null;
        boolean outcomeRecorded = false;
        ValidationRun savedRun = run;
        try (var ignored = PinnedTargetHttpSupport.pin(resolvedTarget)) {
            ValidatorConfiguration.useRunOverrides(normalizedTargetUrl, authToken);
            ScimBaseSpec.resetRunState();
            if (runId != null) {
                ScimRunContext.beginRun(runId.toString());
            }

            listener = new ValidationExecutionListener(
                    run, plannedTotal, progressTracker, testResultRepository, exchangeRepository, authToken);
            Launcher launcher = LauncherFactory.create();
            executeLauncher(launcher, buildRequest(), listener);

            String finalStatus = applyCompletedRunOutcome(run, listener);
            savedRun = executeInReadWriteTransaction(() -> runRepository.save(run));
            if (runId != null) {
                progressTracker.completeRun(runId, finalStatus, listener.total, listener.passed, listener.failed);
            }
            outcomeRecorded = true;
        } catch (Exception | AssertionError ex) {
            String safeMsg = applyFailedRunOutcome(run, listener, ex, authToken);
            log.error("Error executing validation run {}: {}", runId, safeMsg);
            savedRun = executeInReadWriteTransaction(() -> runRepository.save(run));
            if (runId != null) {
                progressTracker.failRun(runId, safeMsg);
            }
            outcomeRecorded = true;
        } finally {
            ScimRunContext.endRun();
            ScimBaseSpec.resetRunState();
            ValidatorConfiguration.clearRunOverrides();
            ValidationExecutionListener capturedListener = listener;
            listener = null;
            if (!outcomeRecorded) {
                snapshotAndRecordAbruptTermination(run, runId, capturedListener);
            }
        }
        return savedRun;
    }

    CancelableAsyncRunTask createAsyncRunTask(String activeSlotKey) {
        return new CancelableAsyncRunTask(this, activeSlotKey);
    }

    private void handoffOrScheduleAfterCommit(
            CancelableAsyncRunTask asyncTask,
            UUID runId,
            ScheduledRunPayload payload) {
        asyncTask.transferSlotOwnership();
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    asyncTask.handoffCommitted(payload);
                }

                @Override
                public void afterCompletion(int status) {
                    if (status != STATUS_COMMITTED) {
                        asyncTask.cancelOnRollback(runId);
                    }
                }
            });
        } else {
            asyncTask.handoffCommitted(payload);
        }
    }

    public ExecutionResult executeRunAsync(ValidationRunForm form, String actorEmail) {
        String normalizedTargetUrl = validateAndNormalizeTargetUrl(form.baseUrl());
        TargetUrlPolicy.ResolvedTarget resolvedTarget = targetUrlPolicy.resolve(normalizedTargetUrl);
        String activeSlotKey = acquireActiveRunSlot(actorEmail);
        CancelableAsyncRunTask asyncTask = createAsyncRunTask(activeSlotKey);
        AtomicReference<ValidationRun> committedRunRef = new AtomicReference<>();
        boolean workerOwnsSlot = false;
        try {
            try {
                executorService.execute(asyncTask);
            } catch (RejectedExecutionException rex) {
                asyncTask.abortBeforeHandoff();
                throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                        "Server validation capacity reached. Please wait a moment and try again.", rex);
            }

            int plannedTotal;
            try (var ignored = PinnedTargetHttpSupport.pin(resolvedTarget)) {
                plannedTotal = discoverTestCount(normalizedTargetUrl, form.authToken());
            }

            InitializedRun initialized = executeInReadWriteTransaction(() -> {
                boolean deleted = pruneOldUnpublishedRuns(actorEmail);
                ValidationRun created = buildInitialRunningEntity(form, normalizedTargetUrl, actorEmail, plannedTotal);
                ValidationRun saved = runRepository.saveAndFlush(created);
                asyncTask.bindRunId(saved.getId());
                return new InitializedRun(saved, deleted);
            });

            ValidationRun run = initialized.run();
            committedRunRef.set(run);
            boolean oldRunDeleted = initialized.oldRunDeleted();

            UUID runId = run.getId();
            if (runId != null) {
                ScheduledRunPayload payload = new ScheduledRunPayload(runId, form, plannedTotal, resolvedTarget);
                progressTracker.registerRun(runId, plannedTotal, "/runs/" + runId);
                handoffOrScheduleAfterCommit(asyncTask, runId, payload);
                workerOwnsSlot = true;
            } else {
                asyncTask.abortBeforeHandoff();
            }

            return new ExecutionResult(run, oldRunDeleted, maxRunsPerUser);
        } finally {
            if (!workerOwnsSlot) {
                cleanupPostCommitPreSuiteFailure(committedRunRef.get(), false);
                asyncTask.abortBeforeHandoff();
                asyncTask.releaseSlotOnCallerAbort();
            }
        }
    }

    record ScheduledRunPayload(
            UUID runId,
            ValidationRunForm form,
            int plannedTotal,
            TargetUrlPolicy.ResolvedTarget resolvedTarget
    ) {}

    static final class CancelableAsyncRunTask implements Runnable {
        private final ValidationRunService service;
        private final String activeSlotKey;
        private final CompletableFuture<ScheduledRunPayload> handoff;
        private final AtomicBoolean startedOrCancelled = new AtomicBoolean(false);
        private final AtomicBoolean slotOwned = new AtomicBoolean(false);
        private final AtomicBoolean slotReleased = new AtomicBoolean(false);
        private final AtomicReference<UUID> boundRunId = new AtomicReference<>();

        CancelableAsyncRunTask(ValidationRunService service, String activeSlotKey) {
            this(service, activeSlotKey, new CompletableFuture<>());
        }

        CancelableAsyncRunTask(
                ValidationRunService service,
                String activeSlotKey,
                CompletableFuture<ScheduledRunPayload> handoff) {
            this.service = service;
            this.activeSlotKey = activeSlotKey;
            this.handoff = Objects.requireNonNull(handoff, "Handoff future must not be null");
        }

        void bindRunId(UUID runId) {
            if (runId != null) {
                boundRunId.set(runId);
                service.activeRunIds.add(runId);
            }
        }

        private void clearBoundRunId() {
            UUID id = boundRunId.getAndSet(null);
            if (id != null) {
                service.activeRunIds.remove(id);
            }
        }

        void transferSlotOwnership() {
            slotOwned.set(true);
        }

        void releaseOwnedSlotOnce() {
            clearBoundRunId();
            if (slotOwned.get() && slotReleased.compareAndSet(false, true)) {
                service.releaseActiveRunSlot(activeSlotKey);
            }
        }

        void releaseSlotOnCallerAbort() {
            slotOwned.set(true);
            releaseOwnedSlotOnce();
        }

        void abortBeforeHandoff() {
            startedOrCancelled.set(true);
            clearBoundRunId();
            handoff.complete(null);
        }

        void handoffCommitted(ScheduledRunPayload payload) {
            handoff.complete(Objects.requireNonNull(payload, "ScheduledRunPayload must not be null"));
        }

        void cancelOnRollback(UUID uncommittedRunId) {
            service.progressTracker.removeRun(uncommittedRunId);
            clearBoundRunId();
            handoff.complete(null);
            releaseOwnedSlotOnce();
        }

        void cancelQueuedOnShutdown() {
            if (!startedOrCancelled.compareAndSet(false, true)) {
                return;
            }
            markInterruptedWhenCompleted("Validation run cancelled during shutdown");
        }

        private void markInterruptedWhenCompleted(String message) {
            handoff.whenComplete((payload, err) -> {
                try {
                    UUID targetRunId = payload != null ? payload.runId() : boundRunId.get();
                    if (targetRunId != null) {
                        service.markBackgroundRunInterruptedBestEffort(targetRunId, message);
                    }
                } finally {
                    releaseOwnedSlotOnce();
                }
            });
        }

        @Override
        public void run() {
            if (!startedOrCancelled.compareAndSet(false, true)) {
                return;
            }
            boolean cleanupHandled = false;
            try {
                ScheduledRunPayload payload;
                try {
                    payload = handoff.get();
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    markInterruptedWhenCompleted(MSG_RUN_INTERRUPTED);
                    cleanupHandled = true;
                    return;
                } catch (java.util.concurrent.ExecutionException ee) {
                    releaseOwnedSlotOnce();
                    cleanupHandled = true;
                    return;
                }
                if (payload == null) {
                    releaseOwnedSlotOnce();
                    cleanupHandled = true;
                    return;
                }
                cleanupHandled = true;
                service.executePermittedBackgroundRun(
                        payload.runId(),
                        payload.form(),
                        payload.plannedTotal(),
                        payload.resolvedTarget(),
                        this::releaseOwnedSlotOnce);
            } finally {
                if (!cleanupHandled) {
                    markInterruptedWhenCompleted(MSG_ABRUPT_RUNTIME_ABORT);
                }
            }
        }
    }

    private void executePermittedBackgroundRun(
            UUID runId,
            ValidationRunForm form,
            int plannedTotal,
            TargetUrlPolicy.ResolvedTarget resolvedTarget,
            Runnable slotReleaser) {
        boolean permitAcquired = false;
        boolean enteredOrInterrupted = false;
        try {
            concurrentRunPermits.acquire();
            permitAcquired = true;
            enteredOrInterrupted = true;
            runTestsInBackground(runId, form, plannedTotal, resolvedTarget);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            enteredOrInterrupted = true;
            markBackgroundRunInterruptedBestEffort(runId, MSG_RUN_INTERRUPTED);
        } finally {
            if (permitAcquired) {
                concurrentRunPermits.release();
            }
            if (!enteredOrInterrupted) {
                markBackgroundRunInterruptedBestEffort(runId, MSG_ABRUPT_RUNTIME_ABORT);
            }
            slotReleaser.run();
        }
    }

    private void markBackgroundRunInterruptedBestEffort(UUID runId, String failureMessage) {
        try {
            if (runRepository != null && runId != null) {
                executeInReadWriteTransaction(() -> {
                    runRepository.findById(runId).ifPresent(run -> {
                        run.setStatus(STATUS_ERROR);
                        runRepository.save(run);
                    });
                    return null;
                });
            }
        } catch (Exception | AssertionError ex) {
            log.warn("Could not mark interrupted validation run {} as ERROR: {}", runId, ex.getMessage());
        }
        if (runId != null) {
            try {
                progressTracker.failRun(runId, failureMessage);
            } catch (Exception | AssertionError ignored) {
                // Best-effort SSE failure notification without masking any unwinding Error
            }
        }
    }

    void runTestsInBackground(UUID runId, ValidationRunForm form, int plannedTotal) {
        String normalizedTargetUrl = validateAndNormalizeTargetUrl(form.baseUrl());
        runTestsInBackground(runId, form, plannedTotal, targetUrlPolicy.resolve(normalizedTargetUrl));
    }

    void runTestsInBackground(
            UUID runId,
            ValidationRunForm form,
            int plannedTotal,
            TargetUrlPolicy.ResolvedTarget resolvedTarget) {
        ValidationRun run = null;
        ValidationExecutionListener listener = null;
        boolean outcomeRecorded = false;
        try {
            Objects.requireNonNull(resolvedTarget, "ResolvedTarget must not be null");
            run = awaitPersistedRun(runId);
            if (run == null) {
                log.error("Run not found for id {}", runId);
                progressTracker.failRun(runId, "Validation run could not be initialized");
                outcomeRecorded = true;
                return;
            }

            try (var ignored = PinnedTargetHttpSupport.pin(resolvedTarget)) {
                ValidatorConfiguration.useRunOverrides(
                        normalizeHttpSchemePrefix(trimUnicodeSpaces(form.baseUrl())), form.authToken());
                ScimBaseSpec.resetRunState();
                ScimRunContext.beginRun(runId.toString());

                listener = new ValidationExecutionListener(
                        run,
                        plannedTotal,
                        progressTracker,
                        testResultRepository,
                        exchangeRepository,
                        form.authToken()
                );

                Launcher launcher = LauncherFactory.create();
                executeLauncher(launcher, buildRequest(), listener);

                String finalStatus = applyCompletedRunOutcome(run, listener);
                ValidationRun completedRun = run;
                executeInReadWriteTransaction(() -> runRepository.save(completedRun));

                progressTracker.completeRun(runId, finalStatus, listener.total, listener.passed, listener.failed);
                outcomeRecorded = true;
            }
        } catch (Exception | AssertionError ex) {
            recordBackgroundRunFailure(run, runId, listener, ex, form != null ? form.authToken() : null);
            outcomeRecorded = true;
        } finally {
            ScimRunContext.endRun();
            ScimBaseSpec.resetRunState();
            ValidatorConfiguration.clearRunOverrides();
            ValidationExecutionListener snapshotListener = listener;
            listener = null;
            if (!outcomeRecorded) {
                recordAbruptBackgroundTermination(run, runId, snapshotListener);
            }
        }
    }

    private void recordBackgroundRunFailure(
            ValidationRun run,
            UUID runId,
            ValidationExecutionListener listener,
            Throwable ex,
            String authToken) {
        if (run != null) {
            String safeMsg = applyFailedRunOutcome(run, listener, ex, authToken);
            log.error("Error executing background validation run {}: {}", runId, safeMsg);
            executeInReadWriteTransaction(() -> runRepository.save(run));
            progressTracker.failRun(runId, safeMsg);
        } else {
            String safeMsg = sanitizeFailureMessage(ex, authToken);
            log.error("Error initializing background validation run {}: {}", runId, safeMsg);
            markBackgroundRunInterruptedBestEffort(runId, safeMsg);
        }
    }

    private void recordAbruptBackgroundTermination(
            ValidationRun run,
            UUID runId,
            ValidationExecutionListener snapshotListener) {
        if (run != null) {
            snapshotAndRecordAbruptTermination(run, runId, snapshotListener);
        } else {
            markBackgroundRunInterruptedBestEffort(runId, MSG_ABRUPT_RUNTIME_ABORT);
        }
    }

    void snapshotAndRecordAbruptTermination(
            ValidationRun run,
            UUID runId,
            ValidationExecutionListener listener) {
        run.setStatus(STATUS_ERROR);
        if (listener != null) {
            run.setTotalTests(listener.total);
            run.setPassedTests(listener.passed);
            run.setFailedTests(listener.failed);
            run.setSkippedTests(listener.skipped);
            run.setAbortedTests(listener.aborted);
        } else {
            run.setTotalTests(0);
        }
        persistAbruptRunTermination(run, runId);
    }

    private void persistAbruptRunTermination(ValidationRun run, UUID runId) {
        try {
            if (runRepository != null) {
                executeInReadWriteTransaction(() -> runRepository.save(run));
            }
        } catch (Exception | AssertionError cleanupEx) {
            log.warn("Could not persist ERROR status after abrupt termination of run {}: {}",
                    runId, cleanupEx.getMessage());
        }
        if (runId != null) {
            try {
                progressTracker.failRun(runId, MSG_ABRUPT_RUNTIME_ABORT);
            } catch (Exception | AssertionError ignored) {
                // Best-effort SSE failure notification without masking the unwinding Error
            }
        }
    }

    ValidationRun awaitPersistedRun(UUID runId) {
        for (int attempt = 0; attempt < 5; attempt++) {
            ValidationRun found = runRepository.findById(runId).orElse(null);
            if (found != null) {
                return found;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
        return null;
    }

    private static String applyCompletedRunOutcome(ValidationRun run, ValidationExecutionListener listener) {
        run.setTotalTests(listener.total);
        run.setPassedTests(listener.passed);
        run.setFailedTests(listener.failed);
        run.setSkippedTests(listener.skipped);
        run.setAbortedTests(listener.aborted);
        String finalStatus;
        if (listener.failed > 0) {
            finalStatus = "FAILED";
        } else if (listener.skipped > 0 || listener.aborted > 0) {
            finalStatus = "PARTIAL";
        } else {
            finalStatus = "PASSED";
        }
        run.setStatus(finalStatus);
        return finalStatus;
    }

    private static String sanitizeFailureMessage(Throwable ex, String authToken) {
        if (ex instanceof InterruptedException) {
            Thread.currentThread().interrupt();
        }
        return scrubSecrets(ex.getMessage() != null ? ex.getMessage() : "Execution error", authToken);
    }

    private static String applyFailedRunOutcome(
            ValidationRun run,
            ValidationExecutionListener listener,
            Throwable ex,
            String authToken) {
        String safeMsg = sanitizeFailureMessage(ex, authToken);
        run.setStatus(STATUS_ERROR);
        if (listener != null) {
            run.setTotalTests(listener.total);
            run.setPassedTests(listener.passed);
            run.setFailedTests(listener.failed);
            run.setSkippedTests(listener.skipped);
            run.setAbortedTests(listener.aborted);
        } else {
            run.setTotalTests(0);
        }
        return safeMsg;
    }

    @Transactional(readOnly = true)
    public long countOwnedRuns(String actorEmail) {
        if (actorEmail == null) {
            return 0;
        }
        return runRepository.countOwnedRuns(actorEmail);
    }

    @Transactional(readOnly = true)
    public List<ValidationRunView> listRuns(String actorEmail, boolean admin) {
        List<ValidationRun> runs;
        Sort sort = Sort.by(Sort.Direction.DESC, "executedAt");
        if (admin) {
            runs = runRepository.findAll(sort);
        } else {
            runs = runRepository.findOwnedRuns(actorEmail, sort);
        }
        return runs
                .stream()
                .map(r -> ValidationRunView.from(r, getReservationTimeout()))
                .toList();
    }

    @Transactional(readOnly = true)
    public ValidationRunView getRun(UUID runId, String actorEmail, boolean admin) {
        ValidationRun run = requireRunAccess(runId, actorEmail, admin);
        return ValidationRunView.from(run, getReservationTimeout());
    }

    @Transactional(readOnly = true)
    public List<ValidationTestResultView> getTestResults(UUID runId, String actorEmail, boolean admin) {
        requireRunAccess(runId, actorEmail, admin);
        List<ValidationTestResult> testResults = testResultRepository.findByRunIdOrderByStartedAtAsc(runId);
        return testResults.stream()
                .map(testResult -> {
                    List<ValidationHttpExchangeView> exchanges = exchangeRepository
                            .findByTestResultIdOrderBySequenceNumberAsc(testResult.getId())
                            .stream()
                            .map(ValidationHttpExchangeView::from)
                            .toList();
                    return ValidationTestResultView.from(testResult, exchanges);
                })
                .toList();
    }

    @Transactional
    public void deleteRun(UUID runId, String actorEmail, boolean admin) {
        ValidationRun run = requireRunAccess(runId, actorEmail, admin);
        boolean publishedInDb = publicationRepository != null
                && publicationRepository.findById(runId).filter(p -> !p.isPendingReservation()).isPresent();
        if (run.isPublished() || publishedInDb) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Published compliance runs cannot be deleted because they are linked from the public compliance directory.");
        }
        if (isReconciliationRequired(runId)
                || (run.hasPendingReservation() && !isStaleReservation(run.getPublication()))) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Run publication is currently in progress");
        }
        if (publicationRepository != null && (run.getPublication() != null || publicationRepository.existsById(runId))) {
            if (run.getPublication() != null) {
                publicationRepository.delete(run.getPublication());
            } else {
                publicationRepository.deleteById(runId);
            }
            run.setPublication(null);
        }
        clearReconciliationRequired(runId);
        runRepository.deleteById(runId);
    }

    @Transactional(readOnly = true)
    public long countOwnedPublications(String actorEmail) {
        return countOwnedPublicationsInternal(actorEmail);
    }

    private long countOwnedPublicationsInternal(String actorEmail) {
        if (actorEmail == null || publicationRepository == null) {
            return 0;
        }
        return publicationRepository.countOwnedPublications(actorEmail);
    }

    @Transactional(readOnly = true)
    public List<ValidationRunPublication> listPublishedRuns(String actorEmail, boolean admin) {
        if (publicationRepository == null) {
            return List.of();
        }
        Sort sort = Sort.by(Sort.Direction.DESC, "publishedAt");
        List<ValidationRunPublication> raw = admin
                ? publicationRepository.findAll(sort)
                : publicationRepository.findOwnedPublications(actorEmail, sort);
        return raw.stream()
                .filter(p -> !p.isPendingReservation())
                .toList();
    }

    public static final String PENDING_RESERVATION_PR_URL = ValidationRunPublication.PENDING_RESERVATION_PR_URL;

    @EventListener(ApplicationReadyEvent.class)
    @Scheduled(fixedDelayString = "${app.compliance.reservation-cleanup-interval-ms:60000}")
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void cleanupStalePendingReservations() {
        for (Map.Entry<UUID, PendingReconciliation> entry : pendingReconciliations.entrySet()) {
            UUID runId = entry.getKey();
            try {
                if (runRepository == null) {
                    continue;
                }
                ValidationRun run = runRepository.findById(runId).orElse(null);
                if (run == null) {
                    clearReconciliationRequired(runId);
                    continue;
                }
                if (tryReconcilePendingPublicationInternal(run).isPresent()) {
                    log.info("Successfully reconciled pending compliance publication for runId={}", runId);
                }
            } catch (Exception ex) {
                log.debug("Background reconciliation attempt for runId={} did not succeed yet: {}", runId, ex.getMessage());
            }
        }
        try {
            int purged = purgeStalePendingReservationsInternal();
            if (purged > 0) {
                log.info("Purged {} stale pending compliance publication reservation(s)", purged);
            }
        } catch (Exception ex) {
            log.debug("Could not purge stale pending compliance publication reservations: {}", ex.getMessage());
        }
    }

    @EventListener(ApplicationReadyEvent.class)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public int reconcileOrphanedRunningRunsOnStartup() {
        if (runRepository == null) {
            return 0;
        }
        List<ValidationRun> runningRuns = runRepository.findByStatus(STATUS_RUNNING);
        int reconciled = reconcileRunningCandidates(runningRuns, MSG_STARTUP_ORPHAN_ABORT);
        if (reconciled > 0) {
            log.warn("Marked {} orphaned RUNNING validation run(s) as ERROR on startup", reconciled);
        }
        return reconciled;
    }

    @Scheduled(fixedDelayString = "${app.compliance.reservation-cleanup-interval-ms:60000}")
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public int reconcileStaleRunningRuns() {
        if (runRepository == null) {
            return 0;
        }
        long timeoutMinutes = Math.max(1L, staleRunningTimeoutMinutes);
        OffsetDateTime cutoff = OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(timeoutMinutes);
        List<ValidationRun> staleRuns = runRepository.findStaleRunsByStatus(STATUS_RUNNING, cutoff);
        int reconciled = reconcileRunningCandidates(staleRuns, MSG_STALE_RUN_TIMEOUT);
        if (reconciled > 0) {
            log.warn("Marked {} stale RUNNING validation run(s) older than {} minute(s) as ERROR",
                    reconciled, timeoutMinutes);
        }
        return reconciled;
    }

    private int reconcileRunningCandidates(List<ValidationRun> candidates, String failureMessage) {
        if (candidates == null || candidates.isEmpty()) {
            return 0;
        }
        int reconciled = 0;
        for (ValidationRun candidate : candidates) {
            if (reconcileSingleStaleRun(candidate, failureMessage)) {
                reconciled++;
            }
        }
        return reconciled;
    }

    private boolean reconcileSingleStaleRun(ValidationRun candidate, String failureMessage) {
        if (candidate == null) {
            return false;
        }
        UUID runId = candidate.getId();
        if (runId != null && activeRunIds.contains(runId)) {
            return false;
        }
        try {
            boolean updated = Boolean.TRUE.equals(executeInIsolatedTransaction(() -> {
                ValidationRun managed = runId != null
                        ? runRepository.findById(runId).orElse(candidate)
                        : candidate;
                if (!STATUS_RUNNING.equals(managed.getStatus())
                        || (runId != null && activeRunIds.contains(runId))) {
                    return false;
                }
                managed.setStatus(STATUS_ERROR);
                runRepository.save(managed);
                return true;
            }));
            if (updated && runId != null) {
                progressTracker.failRun(runId, failureMessage);
            }
            return updated;
        } catch (Exception ex) {
            log.warn("Failed to reconcile stale RUNNING validation run {}: {}", runId, ex.getMessage());
            return false;
        }
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public int purgeStalePendingReservations() {
        return purgeStalePendingReservationsInternal();
    }

    private int purgeStalePendingReservationsInternal() {
        if (publicationRepository == null) {
            return 0;
        }
        return executeInIsolatedTransaction(() -> {
            OffsetDateTime cutoff = OffsetDateTime.now(ZoneOffset.UTC).minus(getReservationTimeout());
            List<ValidationRunPublication> staleList = publicationRepository.findStalePendingReservations(
                    PENDING_RESERVATION_PR_URL, cutoff);
            if (staleList == null || staleList.isEmpty()) {
                return 0;
            }
            int purged = 0;
            for (ValidationRunPublication stale : staleList) {
                UUID runId = stale.getRunId();
                if (runId == null || reconciliationRequiredRunIds.contains(runId)) {
                    continue;
                }
                int deleted = publicationRepository.deleteStalePendingReservationById(
                        runId, PENDING_RESERVATION_PR_URL, cutoff);
                if (deleted > 0) {
                    purged += deleted;
                    if (runRepository != null) {
                        runRepository.findById(runId).ifPresent(r -> {
                            if (r.hasPendingReservation()) {
                                r.setPublication(null);
                                runRepository.save(r);
                            }
                        });
                    }
                }
            }
            publicationRepository.flush();
            return purged;
        });
    }

    private final Object reservationLock = new Object();

    public void validatePublishQuota(String actorEmail) {
        validatePublishQuota(actorEmail, null);
    }

    public void validatePublishQuota(String actorEmail, UUID excludeRunId) {
        long currentPublishedCount = countOwnedPublicationsInternal(actorEmail);
        long activePendingCount = countActivePendingReservations(actorEmail, excludeRunId);
        if (currentPublishedCount + activePendingCount >= maxPublishedRunsPerUser) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "User has reached maximum published compliance runs cap (" + maxPublishedRunsPerUser + ").");
        }
    }

    private long countActivePendingReservations(String actorEmail, UUID excludeRunId) {
        if (publicationRepository == null || actorEmail == null || actorEmail.isBlank()) {
            return 0;
        }
        List<ValidationRunPublication> allForUser = publicationRepository
                .findByCreatedByEmailOrderByPublishedAtDesc(actorEmail);
        if (allForUser == null) {
            return 0;
        }
        long count = 0;
        for (ValidationRunPublication p : allForUser) {
            if (excludeRunId != null && excludeRunId.equals(p.getRunId())) {
                continue;
            }
            if (p.isPendingReservation() && !isStaleReservation(p)) {
                count++;
            }
        }
        return count;
    }

    public void validateProductSlugOwnership(String productSlug, String ownerEmail) {
        validateProductSlugOwnership(productSlug, ownerEmail, null);
    }

    boolean isSlugOwnedByAnotherPublisher(String productSlug, String ownerEmail, UUID currentRunId) {
        if (publicationRepository == null || productSlug == null || productSlug.isBlank()
                || ownerEmail == null || ownerEmail.isBlank()) {
            return false;
        }
        List<ValidationRunPublication> existing = publicationRepository
                .findByProductSlugIgnoreCaseOrderByPublishedAtDesc(productSlug);
        if (existing != null) {
            for (ValidationRunPublication p : existing) {
                if (currentRunId != null && currentRunId.equals(p.getRunId())) {
                    continue;
                }
                if (p.isPendingReservation() && isStaleReservation(p)) {
                    continue;
                }
                if (p.getCreatedByEmail() != null && !p.getCreatedByEmail().equalsIgnoreCase(ownerEmail)) {
                    return true;
                }
            }
        }
        return false;
    }

    public void validateProductSlugOwnership(String productSlug, String ownerEmail, UUID currentRunId) {
        if (productSlug != null && Slugifier.isUuidFormatted(productSlug)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Product slug '" + productSlug + "' cannot use a UUID format reserved for run badge identifiers.");
        }
        if (isSlugOwnedByAnotherPublisher(productSlug, ownerEmail, currentRunId)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Product slug '" + productSlug + "' is already owned by another publisher.");
        }
    }

    @Transactional(readOnly = true)
    public ValidationRun getRunEntity(UUID runId, String actorEmail, boolean admin) {
        return requireRunAccess(runId, actorEmail, admin);
    }

    @Transactional(readOnly = true)
    public List<ValidationTestResult> getRawTestResults(UUID runId) {
        if (testResultRepository == null) {
            return List.of();
        }
        return testResultRepository.findByRunIdOrderByStartedAtAsc(runId);
    }

    @Transactional(readOnly = true)
    public List<ValidationHttpExchange> getRawExchanges(UUID runId) {
        if (exchangeRepository == null) {
            return List.of();
        }
        List<ValidationHttpExchange> exchanges = exchangeRepository.findServiceProviderConfigExchangesByRunId(runId);
        return exchanges != null ? exchanges : List.of();
    }

    @Transactional(readOnly = true)
    public Optional<ValidationRunPublication> getPublication(UUID runId) {
        if (publicationRepository == null) {
            return Optional.empty();
        }
        return publicationRepository.findById(runId)
                .filter(p -> !p.isPendingReservation());
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ValidationRunPublication reservePublication(
            ValidationRun run,
            String actorEmail,
            CompliancePublishRequest request) {
        synchronized (reservationLock) {
            return executeInIsolatedTransaction(() -> doReservePublication(run, actorEmail, request));
        }
    }

    private ValidationRunPublication doReservePublication(
            ValidationRun run,
            String actorEmail,
            CompliancePublishRequest request) {
        ValidationRun managedRun = resolveManagedRun(run);
        ValidationRunPublication existing = findExistingPublicationOrReservation(managedRun);

        if (run.isPublished() || managedRun.isPublished()
                || (existing != null && !existing.isPendingReservation())) {
            throw new IllegalStateException("Validation run has already been published: " + managedRun.getId());
        }
        if (existing != null && existing.isPendingReservation() && !isStaleReservation(existing)) {
            throw new IllegalStateException("Validation run publication is already in progress: " + managedRun.getId());
        }

        String ownerEmail = resolveOwnerEmail(managedRun, run, actorEmail);
        validateOwnerQuotaAndSlug(ownerEmail, request.productSlug(), managedRun.getId());
        String sanitizedSlug = sanitizeRequestedProductSlug(request.productSlug(), request.productName());
        if (request.productSlug() == null || !sanitizedSlug.equalsIgnoreCase(request.productSlug())) {
            validateProductSlugOwnership(sanitizedSlug, ownerEmail, managedRun.getId());
        }

        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        ValidationRunPublication reservation;
        if (existing != null) {
            OffsetDateTime stalePublishedAt = existing.getPublishedAt();
            if (publicationRepository != null) {
                OffsetDateTime cutoff = now.minus(getReservationTimeout());
                int claimed = publicationRepository.claimStalePendingReservationById(
                        managedRun.getId(), PENDING_RESERVATION_PR_URL, cutoff, now);
                if (claimed == 0) {
                    throw new IllegalStateException("Validation run publication is already in progress: " + managedRun.getId());
                }
                managedRun = resolveManagedRun(run);
                existing = findExistingPublicationOrReservation(managedRun);
            }
            log.warn("Reclaiming stale pending publication reservation for runId={} (reserved at {})",
                    managedRun.getId(), stalePublishedAt);
            reservation = existing != null ? existing : new ValidationRunPublication();
            if (existing != null) {
                reservation.markNotNew();
            }
        } else {
            reservation = new ValidationRunPublication();
        }
        populatePublicationMetadata(reservation, managedRun, ownerEmail, request);
        String baseUrl = getEffectivePublicBaseUrl();
        reservation.setReportUrl(resolveValidReportUrl(baseUrl + "/compliance/?run=" + managedRun.getId(), null, managedRun.getId()));
        reservation.setBadgeUrl(resolveValidBadgeUrl(baseUrl + "/compliance/badges/" + managedRun.getId() + ".svg", null, managedRun.getId()));
        reservation.setPrUrl(PENDING_RESERVATION_PR_URL);
        reservation.setPublishedAt(now);

        return persistPublicationAndSyncRun(reservation, managedRun, run);
    }

    @Transactional
    public void releasePublicationReservation(ValidationRun run) {
        releasePublicationReservationInternal(run);
    }

    private void releasePublicationReservationInternal(ValidationRun run) {
        if (run == null || run.getId() == null || reconciliationRequiredRunIds.contains(run.getId())) {
            return;
        }
        UUID runId = run.getId();
        if (runRepository != null) {
            runRepository.findById(runId).ifPresent(managedRun -> {
                if (managedRun.hasPendingReservation()) {
                    managedRun.setPublication(null);
                    runRepository.save(managedRun);
                }
            });
        }
        if (publicationRepository != null) {
            publicationRepository.findById(runId).ifPresent(existing -> {
                if (existing.isPendingReservation()) {
                    publicationRepository.deleteById(runId);
                }
            });
        }
        if (run.hasPendingReservation()) {
            run.setPublication(null);
        }
    }

    @Transactional
    public boolean touchPublicationReservation(UUID runId) {
        if (runId == null || publicationRepository == null) {
            return false;
        }
        return publicationRepository.findById(runId)
                .filter(ValidationRunPublication::isPendingReservation)
                .map(pub -> {
                    pub.setPublishedAt(OffsetDateTime.now(ZoneOffset.UTC));
                    publicationRepository.save(pub);
                    return true;
                })
                .orElse(false);
    }

    @Transactional
    public ValidationRunPublication recordPublication(
            ValidationRun run,
            String actorEmail,
            CompliancePublishRequest request,
            CompliancePublicationResult result) {
        return recordPublicationInternal(run, actorEmail, request, result);
    }

    private ValidationRunPublication recordPublicationInternal(
            ValidationRun run,
            String actorEmail,
            CompliancePublishRequest request,
            CompliancePublicationResult result) {
        ValidationRun managedRun = resolveManagedRun(run);
        ValidationRunPublication existing = findExistingPublicationOrReservation(managedRun);
        String ownerEmail = resolveOwnerEmail(managedRun, run, actorEmail);

        if (existing != null && existing.isPendingReservation()) {
            String reservedSlug = existing.getProductSlug() != null && !existing.getProductSlug().isBlank()
                    ? sanitizeRequestedProductSlug(existing.getProductSlug(), existing.getProductName())
                    : null;
            String fallbackReportUrl = existing.getReportUrl();
            String fallbackBadgeUrl = existing.getBadgeUrl();
            boolean originalShowSubmitter = existing.isShowSubmitter();
            populatePublicationMetadata(existing, managedRun, ownerEmail, request);
            existing.setProductSlug(resolveNonCollidingPendingSlug(
                    existing.getProductSlug(), reservedSlug, ownerEmail, managedRun.getId()));
            if (result != null && result.reconciledCatalogEntry() != null) {
                String safeSlug = resolveSafeReconciledProductSlug(
                        result.reconciledCatalogEntry().productSlug(),
                        existing.getProductSlug(),
                        ownerEmail,
                        managedRun.getId());
                applyReconciledCatalogMetadata(existing, result.reconciledCatalogEntry(), originalShowSubmitter, safeSlug);
            }
            existing.markNotNew();
            existing.setReportUrl(resolveValidReportUrl(result != null ? result.reportUrl() : null, fallbackReportUrl, managedRun.getId()));
            existing.setBadgeUrl(resolveValidBadgeUrl(result != null ? result.badgeUrl() : null, fallbackBadgeUrl, managedRun.getId()));
            existing.setPrUrl(sanitizePrUrl(result != null ? result.prUrl() : null));
            existing.setPublishedAt(result != null && result.publishedAt() != null
                    ? result.publishedAt()
                    : OffsetDateTime.now(ZoneOffset.UTC));
            ValidationRunPublication saved = persistPublicationAndSyncRun(existing, managedRun, run);
            clearReconciliationRequired(managedRun.getId());
            return saved;
        }

        if (run.isPublished() || managedRun.isPublished() || existing != null) {
            throw new IllegalStateException("Validation run has already been published: " + managedRun.getId());
        }
        String fallbackSlug = sanitizeRequestedProductSlug(request.productSlug(), request.productName());
        String effectiveSlug = (result != null && result.reconciledCatalogEntry() != null)
                ? resolveSafeReconciledProductSlug(
                        result.reconciledCatalogEntry().productSlug(), fallbackSlug, ownerEmail, managedRun.getId())
                : fallbackSlug;
        validateOwnerQuotaAndSlug(ownerEmail, effectiveSlug, managedRun.getId());

        ValidationRunPublication publication = new ValidationRunPublication();
        populatePublicationMetadata(publication, managedRun, ownerEmail, request);
        if (result != null && result.reconciledCatalogEntry() != null) {
            applyReconciledCatalogMetadata(publication, result.reconciledCatalogEntry(), request.showSubmitter(), effectiveSlug);
        }
        publication.setReportUrl(resolveValidReportUrl(result != null ? result.reportUrl() : null, null, managedRun.getId()));
        publication.setBadgeUrl(resolveValidBadgeUrl(result != null ? result.badgeUrl() : null, null, managedRun.getId()));
        publication.setPrUrl(sanitizePrUrl(result != null ? result.prUrl() : null));
        publication.setPublishedAt(result != null && result.publishedAt() != null
                ? result.publishedAt()
                : OffsetDateTime.now(ZoneOffset.UTC));

        ValidationRunPublication saved = persistPublicationAndSyncRun(publication, managedRun, run);
        clearReconciliationRequired(managedRun.getId());
        return saved;
    }

    private void applyReconciledCatalogMetadata(
            ValidationRunPublication target,
            ComplianceCatalogEntry entry,
            boolean fallbackShowSubmitter,
            String resolvedProductSlug) {
        target.setProductName(sanitizeNonBlankBounded(
                entry.productName(), MAX_PRODUCT_NAME_CHARS, target.getProductName(), "productName"));
        target.setProductSlug(resolvedProductSlug);
        target.setProductVersion(sanitizeNonBlankBounded(
                entry.productVersion(), MAX_PRODUCT_VERSION_CHARS, target.getProductVersion(), "productVersion"));
        target.setVendorName(sanitizeOptionalBounded(
                entry.vendorName(), MAX_VENDOR_NAME_CHARS, target.getVendorName(), "vendorName"));
        target.setProjectUrl(sanitizeReconciledProjectUrl(entry.projectUrl(), target.getProjectUrl()));
        target.setLicenseType(sanitizeNonBlankBounded(
                entry.licenseType(), MAX_LICENSE_TYPE_CHARS, target.getLicenseType(), "licenseType"));
        target.setShowSubmitter(fallbackShowSubmitter);

        if (entry.coreScore() >= 0 && entry.coreScore() <= 100) {
            target.setCoreScore(entry.coreScore());
        } else {
            log.warn("Ignoring out-of-range reconciled catalog coreScore={} and keeping fallback {}",
                    entry.coreScore(), target.getCoreScore());
        }

        if (entry.totalCapabilities() > 0
                && entry.supportedCapabilities() >= 0
                && entry.supportedCapabilities() <= entry.totalCapabilities()) {
            target.setSupportedCapabilities(entry.supportedCapabilities());
            target.setTotalCapabilities(entry.totalCapabilities());
        } else {
            log.warn("Ignoring invalid reconciled catalog capabilities ({}/{}) and keeping fallback ({}/{})",
                    entry.supportedCapabilities(), entry.totalCapabilities(),
                    target.getSupportedCapabilities(), target.getTotalCapabilities());
        }
    }

    private String resolveNonCollidingPendingSlug(
            String requestedSlug,
            String reservedSlug,
            String ownerEmail,
            UUID runId) {
        if (!isSlugOwnedByAnotherPublisher(requestedSlug, ownerEmail, runId)) {
            return requestedSlug;
        }
        if (reservedSlug != null
                && !reservedSlug.equalsIgnoreCase(requestedSlug)
                && !isSlugOwnedByAnotherPublisher(reservedSlug, ownerEmail, runId)) {
            log.warn("Retry productSlug '{}' is owned by another publisher; keeping reserved slug '{}'",
                    requestedSlug, reservedSlug);
            return reservedSlug;
        }
        String perRunSlug = runId != null
                ? "product-" + runId.toString().toLowerCase(Locale.ROOT)
                : "scim-product";
        log.warn("Pending reservation productSlug '{}' is owned by another publisher; falling back to '{}'",
                requestedSlug, perRunSlug);
        return perRunSlug;
    }

    private String resolveSafeReconciledProductSlug(
            String rawReconciledSlug,
            String fallbackSlug,
            String ownerEmail,
            UUID runId) {
        String candidate = sanitizeReconciledProductSlug(rawReconciledSlug, fallbackSlug);
        if (isSlugOwnedByAnotherPublisher(candidate, ownerEmail, runId)) {
            if (fallbackSlug != null && !fallbackSlug.isBlank()
                    && !candidate.equalsIgnoreCase(fallbackSlug)
                    && !isSlugOwnedByAnotherPublisher(fallbackSlug, ownerEmail, runId)) {
                log.warn("Reconciled catalog productSlug '{}' is owned by another publisher; keeping fallback slug '{}'",
                        candidate, fallbackSlug);
                return fallbackSlug;
            }
            String perRunSlug = runId != null
                    ? "product-" + runId.toString().toLowerCase(Locale.ROOT)
                    : "scim-product";
            log.warn("Reconciled/fallback productSlug '{}' is owned by another publisher; falling back to '{}'",
                    candidate, perRunSlug);
            return perRunSlug;
        }
        return candidate;
    }

    static boolean isValidPublicationHttpUrl(String candidate) {
        if (candidate == null || candidate.isEmpty() || candidate.length() > MAX_PUBLICATION_URL_CHARS) {
            return false;
        }
        for (int i = 0; i < candidate.length(); i++) {
            if (isDisallowedUrlSpaceOrControl(candidate.charAt(i))) {
                return false;
            }
        }
        return SAFE_HTTP_URL_SCHEME_HOST_PATTERN.matcher(candidate).matches()
                && !HTTP_URL_USERINFO_PATTERN.matcher(candidate).find();
    }

    static String sanitizeOptionalHttpUrl(String candidate) {
        if (candidate == null) {
            return null;
        }
        String trimmed = trimUnicodeSpaces(candidate);
        if (trimmed.isEmpty()) {
            return null;
        }
        return isValidPublicationHttpUrl(trimmed) ? trimmed : null;
    }

    static String sanitizePrUrl(String prUrl) {
        if (prUrl == null) {
            return null;
        }
        String trimmed = trimUnicodeSpaces(prUrl);
        if (trimmed.isEmpty()) {
            return null;
        }
        if (isValidPublicationHttpUrl(trimmed)) {
            return trimmed;
        }
        log.warn("Ignoring malformed or sentinel publication prUrl (length={}) to satisfy DB constraints", trimmed.length());
        return null;
    }

    static String sanitizeRequestedProductSlug(String requestedSlug, String fallbackProductName) {
        String candidate = Slugifier.slugify(requestedSlug);
        if (candidate.isEmpty()) {
            candidate = Slugifier.slugify(fallbackProductName);
        }
        if (candidate.isEmpty()) {
            candidate = "scim-product";
        }
        if (Slugifier.isUuidFormatted(candidate)) {
            candidate = "product-" + candidate;
        }
        if (candidate.length() > MAX_PRODUCT_SLUG_CHARS) {
            int end = MAX_PRODUCT_SLUG_CHARS;
            while (end > 0 && candidate.charAt(end - 1) == '-') {
                end--;
            }
            candidate = candidate.substring(0, end);
        }
        if (candidate.isEmpty()
                || !SAFE_PRODUCT_SLUG_PATTERN.matcher(candidate).matches()
                || Slugifier.isUuidFormatted(candidate)) {
            return "scim-product";
        }
        return candidate;
    }

    static String sanitizeReconciledProductSlug(String reconciledSlug, String fallbackSlug) {
        if (reconciledSlug != null) {
            String trimmed = trimUnicodeSpaces(reconciledSlug);
            if (!trimmed.isEmpty() && !Slugifier.isUuidFormatted(trimmed)) {
                String candidate = Slugifier.slugify(trimmed);
                if (candidate.length() > MAX_PRODUCT_SLUG_CHARS) {
                    int end = MAX_PRODUCT_SLUG_CHARS;
                    while (end > 0 && candidate.charAt(end - 1) == '-') {
                        end--;
                    }
                    candidate = candidate.substring(0, end);
                }
                if (!candidate.isEmpty()
                        && SAFE_PRODUCT_SLUG_PATTERN.matcher(candidate).matches()
                        && !Slugifier.isUuidFormatted(candidate)) {
                    return candidate;
                }
            }
            log.warn("Ignoring invalid reconciled catalog productSlug '{}' and keeping fallback slug '{}'",
                    reconciledSlug, fallbackSlug);
        }
        return fallbackSlug;
    }

    private static String sanitizeReconciledProjectUrl(String reconciledProjectUrl, String fallbackProjectUrl) {
        if (reconciledProjectUrl == null) {
            return null;
        }
        String trimmed = trimUnicodeSpaces(reconciledProjectUrl);
        if (trimmed.isEmpty()) {
            return null;
        }
        if (isValidPublicationHttpUrl(trimmed)) {
            return trimmed;
        }
        log.warn("Ignoring malformed reconciled catalog projectUrl (length={}) and falling back", trimmed.length());
        return sanitizeOptionalHttpUrl(fallbackProjectUrl);
    }

    private static boolean containsControlChars(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.isISOControl(s.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    private static String sanitizeNonBlankBounded(String candidate, int maxChars, String fallback, String fieldName) {
        if (candidate != null) {
            String trimmed = candidate.trim();
            if (!trimmed.isEmpty() && trimmed.length() <= maxChars && !containsControlChars(trimmed)) {
                return trimmed;
            }
            log.warn("Ignoring invalid reconciled catalog {} (length={}) and keeping fallback value",
                    fieldName, trimmed.length());
        }
        return fallback;
    }

    private static String sanitizeOptionalBounded(String candidate, int maxChars, String fallback, String fieldName) {
        if (candidate == null || candidate.isBlank()) {
            return null;
        }
        String trimmed = candidate.trim();
        if (trimmed.length() <= maxChars && !containsControlChars(trimmed)) {
            return trimmed;
        }
        log.warn("Ignoring invalid reconciled catalog {} (length={}) and keeping fallback value",
                fieldName, trimmed.length());
        return fallback != null && !fallback.isBlank() && fallback.trim().length() <= maxChars
                && !containsControlChars(fallback.trim())
                ? fallback.trim()
                : null;
    }

    private String resolveFallbackPublicBaseUrl() {
        if (publicBaseUrl != null && !trimUnicodeSpaces(publicBaseUrl).isEmpty()) {
            try {
                return getEffectivePublicBaseUrl();
            } catch (RuntimeException ignored) {
                // Fall back to default public compliance URL if unconfigured/invalid in unit tests
            }
        }
        return DEFAULT_PUBLIC_COMPLIANCE_BASE_URL;
    }

    String resolveValidReportUrl(String candidateUrl, String fallbackUrl, UUID runId) {
        String sanitized = sanitizeOptionalHttpUrl(candidateUrl);
        if (sanitized != null) {
            return sanitized;
        }
        String sanitizedFallback = sanitizeOptionalHttpUrl(fallbackUrl);
        if (sanitizedFallback != null) {
            return sanitizedFallback;
        }
        String constructed = resolveFallbackPublicBaseUrl() + "/compliance/?run=" + runId;
        if (isValidPublicationHttpUrl(constructed)) {
            return constructed;
        }
        log.warn("Configured publicBaseUrl produced invalid reportUrl (length={}); falling back to default domain",
                constructed.length());
        return DEFAULT_PUBLIC_COMPLIANCE_BASE_URL + "/compliance/?run=" + runId;
    }

    String resolveValidBadgeUrl(String candidateUrl, String fallbackUrl, UUID runId) {
        String sanitized = sanitizeOptionalHttpUrl(candidateUrl);
        if (sanitized != null) {
            return sanitized;
        }
        String sanitizedFallback = sanitizeOptionalHttpUrl(fallbackUrl);
        if (sanitizedFallback != null) {
            return sanitizedFallback;
        }
        String constructed = resolveFallbackPublicBaseUrl() + "/compliance/badges/" + runId + ".svg";
        if (isValidPublicationHttpUrl(constructed)) {
            return constructed;
        }
        log.warn("Configured publicBaseUrl produced invalid badgeUrl (length={}); falling back to default domain",
                constructed.length());
        return DEFAULT_PUBLIC_COMPLIANCE_BASE_URL + "/compliance/badges/" + runId + ".svg";
    }

    private ValidationRun resolveManagedRun(ValidationRun run) {
        return (runRepository != null && run.getId() != null)
                ? runRepository.findById(run.getId()).orElse(run)
                : run;
    }

    private ValidationRunPublication findExistingPublicationOrReservation(ValidationRun managedRun) {
        if (publicationRepository != null && managedRun.getId() != null) {
            return publicationRepository.findById(managedRun.getId()).orElse(null);
        }
        return managedRun.getPublication();
    }

    private String resolveOwnerEmail(ValidationRun managedRun, ValidationRun detachedRun, String actorEmail) {
        if (managedRun.getCreatedByEmail() != null && !managedRun.getCreatedByEmail().isBlank()) {
            return managedRun.getCreatedByEmail();
        }
        if (detachedRun.getCreatedByEmail() != null && !detachedRun.getCreatedByEmail().isBlank()) {
            return detachedRun.getCreatedByEmail();
        }
        return actorEmail;
    }

    private void validateOwnerQuotaAndSlug(String ownerEmail, String productSlug, UUID runId) {
        validatePublishQuota(ownerEmail, runId);
        validateProductSlugOwnership(productSlug, ownerEmail, runId);
    }

    private void populatePublicationMetadata(
            ValidationRunPublication target,
            ValidationRun managedRun,
            String ownerEmail,
            CompliancePublishRequest request) {
        target.setRun(managedRun);
        target.setCreatedByEmail(ownerEmail);
        target.setProductName(truncateChars(request.productName(), MAX_PRODUCT_NAME_CHARS));
        target.setProductSlug(sanitizeRequestedProductSlug(request.productSlug(), request.productName()));
        target.setProductVersion(truncateChars(request.productVersion(), MAX_PRODUCT_VERSION_CHARS));
        target.setVendorName(request.vendorName() != null && !request.vendorName().isBlank()
                ? truncateChars(request.vendorName().trim(), MAX_VENDOR_NAME_CHARS)
                : null);
        target.setProjectUrl(sanitizeOptionalHttpUrl(request.projectUrl()));
        target.setLicenseType(truncateChars(request.licenseType(), MAX_LICENSE_TYPE_CHARS));
        target.setShowSubmitter(request.showSubmitter());
        target.setCoreScore(request.coreScore());
        target.setSupportedCapabilities(request.supportedCapabilities());
        target.setTotalCapabilities(request.totalCapabilities());
    }

    private ValidationRunPublication persistPublicationAndSyncRun(
            ValidationRunPublication publication,
            ValidationRun managedRun,
            ValidationRun callerRun) {
        managedRun.setPublication(publication);
        if (publicationRepository != null) {
            publication = publicationRepository.save(publication);
            publicationRepository.flush();
        }
        if (runRepository != null) {
            runRepository.save(managedRun);
        }
        if (managedRun != callerRun) {
            callerRun.setPublication(publication);
        }
        return publication;
    }

    private ValidationRun requireRunAccess(UUID runId, String actorEmail, boolean admin) {
        if (admin) {
            return runRepository.findById(runId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Test suite not found"));
        }
        return runRepository.findAccessibleById(runId, actorEmail)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Test suite not found"));
    }

    int discoverTestCount() {
        return discoverTestCount(null, null);
    }

    int discoverTestCount(String baseUrl, String authToken) {
        int fallbackCount = specCatalogService != null && specCatalogService.getTotalTestsCount() > 0
                ? specCatalogService.getTotalTestsCount()
                : DEFAULT_DISCOVERED_TEST_COUNT;
        try {
            if (baseUrl != null && !baseUrl.isBlank()) {
                ValidatorConfiguration.useRunOverrides(baseUrl, authToken);
            }
            LauncherDiscoveryRequest request = buildRequest();
            TestPlan plan = discoverTestPlan(request);
            long count = plan.countTestIdentifiers(TestIdentifier::isTest);
            return count > 0 ? (int) count : fallbackCount;
        } catch (Exception ex) {
            String safeMsg = scrubSecrets(
                    ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName(),
                    authToken);
            log.warn("Could not discover test plan count: {}", safeMsg);
            return fallbackCount;
        } finally {
            ValidatorConfiguration.clearRunOverrides();
        }
    }

    TestPlan discoverTestPlan(LauncherDiscoveryRequest request) {
        return LauncherFactory.create().discover(request);
    }

    private static LauncherDiscoveryRequest buildRequest() throws ClassNotFoundException {
        LauncherDiscoveryRequestBuilder builder = LauncherDiscoveryRequestBuilder.request()
                .configurationParameter("junit.jupiter.execution.parallel.enabled", "false");

        for (String className : SpecCatalogService.discoverValidatorSpecClassNames()) {
            Class<?> specClass = Class.forName(className);
            builder.selectors(selectClass(specClass));
        }

        return builder.build();
    }

    void executeLauncher(Launcher launcher, LauncherDiscoveryRequest request, TestExecutionListener listener) {
        launcher.registerTestExecutionListeners(listener);
        launcher.execute(request);
    }

    static class ValidationExecutionListener implements TestExecutionListener {

        private final ValidationRun run;
        private final int plannedTotal;
        private final ValidationProgressTracker progressTracker;
        private final ValidationTestResultRepository testResultRepository;
        private final ValidationHttpExchangeRepository exchangeRepository;
        private final String authToken;
        private final Map<String, OffsetDateTime> starts = new LinkedHashMap<>();

        private int total;
        private int passed;
        private int failed;
        private int skipped;
        private int aborted;

        ValidationExecutionListener(ValidationRun run,
                int plannedTotal,
                ValidationProgressTracker progressTracker,
                ValidationTestResultRepository testResultRepository,
                ValidationHttpExchangeRepository exchangeRepository) {
            this(run, plannedTotal, progressTracker, testResultRepository, exchangeRepository, null);
        }

        ValidationExecutionListener(ValidationRun run,
                int plannedTotal,
                ValidationProgressTracker progressTracker,
                ValidationTestResultRepository testResultRepository,
                ValidationHttpExchangeRepository exchangeRepository,
                String authToken) {
            this.run = run;
            this.plannedTotal = plannedTotal;
            this.progressTracker = progressTracker;
            this.testResultRepository = testResultRepository;
            this.exchangeRepository = exchangeRepository;
            this.authToken = authToken;
        }

        int getTotal() {
            return total;
        }

        int getPassed() {
            return passed;
        }

        int getFailed() {
            return failed;
        }

        int getSkipped() {
            return skipped;
        }

        int getAborted() {
            return aborted;
        }

        @Override
        public void executionStarted(TestIdentifier testIdentifier) {
            if (!testIdentifier.isTest()) {
                return;
            }
            String uniqueId = testIdentifier.getUniqueId();
            starts.put(uniqueId, OffsetDateTime.now());
            ScimRunContext.beginTest(uniqueId);

            int currentTestIndex = total + 1;
            int effectiveTotal = Math.max(plannedTotal, currentTestIndex);
            String displayName = testIdentifier.getDisplayName();
            String specName = resolveSpecName(testIdentifier);

            if (progressTracker != null && run.getId() != null) {
                progressTracker.updateProgress(
                        run.getId(),
                        currentTestIndex,
                        effectiveTotal,
                        passed,
                        failed,
                        specName,
                        displayName
                );
            }
        }

        @Override
        public void executionFinished(TestIdentifier testIdentifier, TestExecutionResult testExecutionResult) {
            if (!testIdentifier.isTest()) {
                return;
            }

            try {
                String uniqueId = testIdentifier.getUniqueId();
                OffsetDateTime startedAt = starts.getOrDefault(uniqueId, OffsetDateTime.now());
                OffsetDateTime finishedAt = OffsetDateTime.now();

                ValidationTestResult testResult = new ValidationTestResult();
                testResult.setRun(run);
                testResult.setTestIdentifier(truncateChars(uniqueId, MAX_TEST_IDENTIFIER_CHARS));
                testResult.setDisplayName(truncateChars(testIdentifier.getDisplayName(), MAX_DISPLAY_NAME_CHARS));
                testResult.setStatus(normalizeStatus(testExecutionResult.getStatus()));
                testResult.setStartedAt(startedAt);
                testResult.setFinishedAt(finishedAt);

                Object source = testIdentifier.getSource().orElse(null);
                if (source instanceof MethodSource methodSource) {
                    testResult.setClassName(truncateChars(methodSource.getClassName(), MAX_CLASS_NAME_CHARS));
                    testResult.setTestName(truncateChars(methodSource.getMethodName(), MAX_TEST_NAME_CHARS));
                }

                Throwable throwable = testExecutionResult.getThrowable().orElse(null);
                if (throwable != null) {
                    testResult.setErrorMessage(truncateUtf8Bytes(scrubSecrets(throwable.getMessage(), authToken), MAX_DB_TEXT_BYTES));
                    testResult.setStackTrace(truncateUtf8Bytes(scrubSecrets(stackTrace(throwable), authToken), MAX_DB_TEXT_BYTES));
                }

                testResult = testResultRepository.save(testResult);

                List<ScimHttpExchange> exchanges = ScimRunContext.getForTest(uniqueId);
                List<ValidationHttpExchange> persisted = new ArrayList<>(exchanges.size());
                for (int i = 0; i < exchanges.size(); i++) {
                    ScimHttpExchange captured = exchanges.get(i);
                    ValidationHttpExchange exchange = new ValidationHttpExchange();
                    exchange.setRun(run);
                    exchange.setTestResult(testResult);
                    exchange.setSequenceNumber(i + 1);
                    exchange.setMethod(truncateChars(captured.getMethod(), MAX_EXCHANGE_METHOD_CHARS));
                    exchange.setUrl(truncateChars(captured.getUrl(), MAX_EXCHANGE_URL_CHARS));
                    exchange.setRequestHeaders(truncateUtf8Bytes(scrubSecrets(captured.getRequestHeaders(), authToken), MAX_DB_TEXT_BYTES));
                    exchange.setRequestBody(truncateUtf8Bytes(scrubSecrets(captured.getRequestBody(), authToken), MAX_DB_TEXT_BYTES));
                    exchange.setResponseStatus(captured.getResponseStatus());
                    exchange.setResponseHeaders(truncateUtf8Bytes(scrubSecrets(captured.getResponseHeaders(), authToken), MAX_DB_TEXT_BYTES));
                    exchange.setResponseBody(truncateUtf8Bytes(scrubSecrets(captured.getResponseBody(), authToken), MAX_DB_TEXT_BYTES));
                    exchange.setCreatedAt(captured.getCreatedAt() == null ? OffsetDateTime.now() : captured.getCreatedAt());
                    persisted.add(exchange);
                }
                try {
                    exchangeRepository.saveAll(persisted);
                } catch (RuntimeException ex) {
                    String safeMsg = scrubSecrets(
                            ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName(), authToken);
                    log.warn("Failed to persist HTTP exchanges for test {}: {}", uniqueId, safeMsg);
                }

                total++;
                if ("SUCCESS".equals(testResult.getStatus())) {
                    passed++;
                } else if ("ABORTED".equals(testResult.getStatus())) {
                    aborted++;
                } else {
                    failed++;
                }

                int effectiveTotal = Math.max(plannedTotal, total);
                String displayName = testIdentifier.getDisplayName();
                String specName = resolveSpecName(testIdentifier);

                if (progressTracker != null && run.getId() != null) {
                    progressTracker.updateProgress(
                            run.getId(),
                            total,
                            effectiveTotal,
                            passed,
                            failed,
                            specName,
                            displayName
                    );
                }
            } finally {
                ScimRunContext.endTest();
            }
        }

        @Override
        public void executionSkipped(TestIdentifier testIdentifier, String reason) {
            if (!testIdentifier.isTest()) {
                return;
            }

            String uniqueId = testIdentifier.getUniqueId();
            OffsetDateTime now = OffsetDateTime.now();

            ValidationTestResult testResult = new ValidationTestResult();
            testResult.setRun(run);
            testResult.setTestIdentifier(truncateChars(uniqueId, MAX_TEST_IDENTIFIER_CHARS));
            testResult.setDisplayName(truncateChars(testIdentifier.getDisplayName(), MAX_DISPLAY_NAME_CHARS));
            testResult.setStatus("SKIPPED");
            testResult.setStartedAt(now);
            testResult.setFinishedAt(now);
            testResult.setErrorMessage(truncateUtf8Bytes(scrubSecrets(reason, authToken), MAX_DB_TEXT_BYTES));

            Object source = testIdentifier.getSource().orElse(null);
            if (source instanceof MethodSource methodSource) {
                testResult.setClassName(truncateChars(methodSource.getClassName(), MAX_CLASS_NAME_CHARS));
                testResult.setTestName(truncateChars(methodSource.getMethodName(), MAX_TEST_NAME_CHARS));
            }

            testResultRepository.save(testResult);

            total++;
            skipped++;

            int effectiveTotal = Math.max(plannedTotal, total);
            String displayName = testIdentifier.getDisplayName();
            String specName = resolveSpecName(testIdentifier);

            if (progressTracker != null && run.getId() != null) {
                progressTracker.updateProgress(
                        run.getId(),
                        total,
                        effectiveTotal,
                        passed,
                        failed,
                        specName,
                        displayName
                );
            }
        }

        private static String resolveSpecName(TestIdentifier testIdentifier) {
            Object source = testIdentifier.getSource().orElse(null);
            if (source instanceof MethodSource methodSource) {
                String fullClassName = methodSource.getClassName();
                int dot = fullClassName.lastIndexOf('.');
                return dot >= 0 ? fullClassName.substring(dot + 1) : fullClassName;
            }
            return "";
        }

        private static String normalizeStatus(TestExecutionResult.Status status) {
            return switch (status) {
                case SUCCESSFUL -> "SUCCESS";
                case ABORTED -> "ABORTED";
                case FAILED -> "FAILED";
            };
        }

        private static String stackTrace(Throwable throwable) {
            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);
            throwable.printStackTrace(printWriter);
            return stringWriter.toString();
        }
    }
}
