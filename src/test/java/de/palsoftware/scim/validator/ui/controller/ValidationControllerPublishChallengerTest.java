package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.dto.CompliancePublishFormData;
import de.palsoftware.scim.validator.ui.model.ValidationMgmtUser;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationRunPublication;
import de.palsoftware.scim.validator.ui.model.spec.ColourGradient;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublicationResult;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublishRequest;
import de.palsoftware.scim.validator.ui.model.spec.ComplianceScorecardView;
import de.palsoftware.scim.validator.ui.model.spec.NormativeBreakdown;
import de.palsoftware.scim.validator.ui.repo.ValidationRunPublicationRepository;
import de.palsoftware.scim.validator.ui.service.ComplianceScoreService;
import de.palsoftware.scim.validator.ui.service.GitHubCompliancePublisherService;
import de.palsoftware.scim.validator.ui.service.MgmtUserService;
import de.palsoftware.scim.validator.ui.service.SpecCatalogService;
import de.palsoftware.scim.validator.ui.service.ValidationProgressTracker;
import de.palsoftware.scim.validator.ui.service.ValidationRunService;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.BindingResult;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Empirical Challenger stress-test harness for Milestone 4 Controller endpoint:
 * POST /runs/{runId}/publish and CompliancePublishFormData.
 *
 * Verifies:
 * 1. Adversarial Input Validation (slugs, field lengths, protocols, path traversals).
 * 2. Slug Auto-Generation under unicode, accents, symbol-only edge cases.
 * 3. Quota & State Invariants (50-run cap, double publishing, concurrency race).
 * 4. Authorization & Security Boundaries (non-owner access, unauthenticated attempts).
 * 5. Eligibility Enforcement & Score Tampering Prevention.
 * 6. External Publisher Failure Resilience (exceptions, merge failures, DB transaction isolation).
 */
@ExtendWith(MockitoExtension.class)
class ValidationControllerPublishChallengerTest {

    private static Validator validator;

    @Mock
    private ValidationRunService validationRunService;

    @Mock
    private MgmtUserService mgmtUserService;

    @Mock
    private ValidationProgressTracker validationProgressTracker;

    @Mock
    private ComplianceScoreService complianceScoreService;

    @Mock
    private SpecCatalogService specCatalogService;

    @Mock
    private GitHubCompliancePublisherService gitHubCompliancePublisherService;

    @Mock
    private ValidationRunPublicationRepository publicationRepository;

    private ValidationController controller;
    private Authentication userAuth;
    private Authentication attackerAuth;

    @BeforeAll
    static void initValidator() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            validator = factory.getValidator();
        }
    }

    @BeforeEach
    void setUp() {
        controller = new ValidationController(
                validationRunService,
                mgmtUserService,
                validationProgressTracker,
                "https://manager.example.com",
                complianceScoreService,
                specCatalogService,
                gitHubCompliancePublisherService,
                publicationRepository
        );
        userAuth = new TestingAuthenticationToken("developer@example.com", "n/a");
        attackerAuth = new TestingAuthenticationToken("attacker@example.com", "n/a");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. Adversarial Form Validation Tests (Jakarta Bean Validation)
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Adversarial Input Validation on CompliancePublishFormData")
    class AdversarialInputValidationTests {

        private CompliancePublishFormData createValidForm() {
            return new CompliancePublishFormData(
                    "Valid Product",
                    "valid-product",
                    "1.0.0",
                    "Valid Vendor",
                    "https://example.com/project",
                    "Apache-2.0",
                    true
            );
        }

        @ParameterizedTest(name = "Invalid slug rejected: [{0}]")
        @ValueSource(strings = {
                "UPPERCASE",
                "MixedCase-Product",
                "product slug with spaces",
                " leading-space",
                "trailing-space ",
                "../../etc/passwd",
                "../traversal",
                "..",
                ".",
                "foo/bar",
                "foo\\bar",
                "product_with_underscore",
                "product@symbol",
                "product#tag",
                "product$dollar",
                "product.dot",
                "product--double--hyphen",
                "-leading-hyphen",
                "trailing-hyphen-",
                "-both-ends-",
                "special!char",
                "accent-café"
        })
        void rejectAdversarialSlugs(String badSlug) {
            CompliancePublishFormData form = createValidForm();
            form.setProductSlug(badSlug);

            Set<ConstraintViolation<CompliancePublishFormData>> violations = validator.validate(form);
            assertThat(violations)
                    .anyMatch(v -> "productSlug".equals(v.getPropertyPath().toString()));
        }

        @Test
        void rejectOversizedSlug() {
            CompliancePublishFormData form = createValidForm();
            // 121 lowercase chars
            form.setProductSlug("a".repeat(121));

            Set<ConstraintViolation<CompliancePublishFormData>> violations = validator.validate(form);
            assertThat(violations)
                    .anyMatch(v -> "productSlug".equals(v.getPropertyPath().toString()));
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"   ", "\t\n"})
        void rejectBlankSlug(String blankSlug) {
            CompliancePublishFormData form = createValidForm();
            form.setProductSlug(blankSlug);

            Set<ConstraintViolation<CompliancePublishFormData>> violations = validator.validate(form);
            assertThat(violations)
                    .anyMatch(v -> "productSlug".equals(v.getPropertyPath().toString()));
        }

        @Test
        void acceptValidBoundarySlugs() {
            CompliancePublishFormData form = createValidForm();

            // Single char
            form.setProductSlug("a");
            assertThat(validator.validate(form)).isEmpty();

            // Single digit
            form.setProductSlug("7");
            assertThat(validator.validate(form)).isEmpty();

            // Exactly 120 chars valid kebab-case
            String exact120 = ("a-b-").repeat(30); // 120 chars: ends with '-' which is invalid
            String valid120 = ("ab-").repeat(39) + "abc"; // 39*3 + 3 = 120 chars
            form.setProductSlug(valid120);
            assertThat(valid120.length()).isEqualTo(120);
            assertThat(validator.validate(form)).isEmpty();
        }

        @ParameterizedTest(name = "Invalid project URL rejected: [{0}]")
        @ValueSource(strings = {
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "ftp://downloads.example.com",
                "file:///etc/passwd",
                "gopher://example.com",
                "httpx://not-supported.com",
                "not-a-url",
                "//example.com/schemeless"
        })
        void rejectAdversarialProjectUrls(String badUrl) {
            CompliancePublishFormData form = createValidForm();
            form.setProjectUrl(badUrl);

            Set<ConstraintViolation<CompliancePublishFormData>> violations = validator.validate(form);
            assertThat(violations)
                    .anyMatch(v -> "projectUrl".equals(v.getPropertyPath().toString()));
        }

        @Test
        void rejectOversizedProjectUrl() {
            CompliancePublishFormData form = createValidForm();
            form.setProjectUrl("https://example.com/" + "a".repeat(500)); // > 500 chars

            Set<ConstraintViolation<CompliancePublishFormData>> violations = validator.validate(form);
            assertThat(violations)
                    .anyMatch(v -> "projectUrl".equals(v.getPropertyPath().toString()));
        }

        @Test
        void acceptValidProjectUrls() {
            CompliancePublishFormData form = createValidForm();

            form.setProjectUrl(null);
            assertThat(validator.validate(form)).isEmpty();

            form.setProjectUrl("");
            assertThat(validator.validate(form)).isEmpty();

            form.setProjectUrl("http://insecure.example.com");
            assertThat(validator.validate(form)).isEmpty();

            form.setProjectUrl("https://secure.example.com/path?foo=bar#hash");
            assertThat(validator.validate(form)).isEmpty();
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"   ", "\t"})
        void rejectBlankProductName(String blankName) {
            CompliancePublishFormData form = createValidForm();
            form.setProductName(blankName);

            Set<ConstraintViolation<CompliancePublishFormData>> violations = validator.validate(form);
            assertThat(violations)
                    .anyMatch(v -> "productName".equals(v.getPropertyPath().toString()));
        }

        @Test
        void rejectOversizedProductName() {
            CompliancePublishFormData form = createValidForm();
            form.setProductName("P".repeat(121));

            Set<ConstraintViolation<CompliancePublishFormData>> violations = validator.validate(form);
            assertThat(violations)
                    .anyMatch(v -> "productName".equals(v.getPropertyPath().toString()));
        }

        @Test
        void rejectOversizedProductVersion() {
            CompliancePublishFormData form = createValidForm();
            form.setProductVersion("v".repeat(61));

            Set<ConstraintViolation<CompliancePublishFormData>> violations = validator.validate(form);
            assertThat(violations)
                    .anyMatch(v -> "productVersion".equals(v.getPropertyPath().toString()));
        }

        @Test
        void rejectOversizedVendorName() {
            CompliancePublishFormData form = createValidForm();
            form.setVendorName("V".repeat(121));

            Set<ConstraintViolation<CompliancePublishFormData>> violations = validator.validate(form);
            assertThat(violations)
                    .anyMatch(v -> "vendorName".equals(v.getPropertyPath().toString()));
        }

        @Test
        void rejectOversizedLicenseType() {
            CompliancePublishFormData form = createValidForm();
            form.setLicenseType("L".repeat(41));

            Set<ConstraintViolation<CompliancePublishFormData>> violations = validator.validate(form);
            assertThat(violations)
                    .anyMatch(v -> "licenseType".equals(v.getPropertyPath().toString()));
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "../etc/passwd",
                "v1/../../foo",
                "1.0..0",
                "-1.0.0",
                "v1.0/beta",
                "v1\\beta",
                "1.0; rm -rf /"
        })
        void rejectAdversarialProductVersions(String badVersion) {
            CompliancePublishFormData form = createValidForm();
            form.setProductVersion(badVersion);

            Set<ConstraintViolation<CompliancePublishFormData>> violations = validator.validate(form);
            assertThat(violations)
                    .anyMatch(v -> "productVersion".equals(v.getPropertyPath().toString()));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Slug Auto-Generation Oracle Tests
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Slug Auto-Generation Oracle Tests")
    class SlugAutoGenerationTests {

        @Test
        void complexUnicodeAndAccentsGenerateSanitizedKebabCase() {
            CompliancePublishFormData form = new CompliancePublishFormData();
            form.setProductName("  Café & Münchën !! SCIM -- Server  ");
            form.setProductSlug(null);

            String slug = form.resolveProductSlug();

            // Accent letters and symbols stripped, multi-hyphens collapsed, trimmed
            assertThat(slug).isEqualTo("caf-m-nch-n-scim-server");
            assertThat(slug).matches("^[a-z0-9]+(?:-[a-z0-9]+)*$");
        }

        @Test
        void punctuationAndLeadingTrailingHyphensAreCleanlyStripped() {
            CompliancePublishFormData form = new CompliancePublishFormData();
            form.setProductName("---Product 123...456---");
            form.setProductSlug("");

            String slug = form.resolveProductSlug();

            assertThat(slug).isEqualTo("product-123-456");
            assertThat(slug).matches("^[a-z0-9]+(?:-[a-z0-9]+)*$");
        }

        @Test
        void symbolOnlyProductNameYieldsEmptyStringWhichFailsBeanValidation() {
            CompliancePublishFormData form = new CompliancePublishFormData();
            form.setProductName("!@#$%^&*()_+");
            form.setProductSlug(null);

            String resolvedSlug = form.resolveProductSlug();
            assertThat(resolvedSlug).isEmpty();

            // When applied to the form, empty slug is rejected by @NotBlank and @Pattern
            form.setProductSlug(resolvedSlug);
            form.setProductVersion("1.0");
            form.setLicenseType("Apache-2.0");
            Set<ConstraintViolation<CompliancePublishFormData>> violations = validator.validate(form);
            assertThat(violations).anyMatch(v -> "productSlug".equals(v.getPropertyPath().toString()));
        }

        @Test
        void explicitSlugAlwaysOverridesProductNameAutoGeneration() {
            CompliancePublishFormData form = new CompliancePublishFormData();
            form.setProductName("Original Product Name");
            form.setProductSlug("custom-override-slug");

            String resolved = form.resolveProductSlug();
            assertThat(resolved).isEqualTo("custom-override-slug");
        }

        @Test
        void completelyNullFormDefaultsToScimServerFallback() {
            CompliancePublishFormData form = new CompliancePublishFormData();
            form.setProductName(null);
            form.setProductSlug(null);

            String resolved = form.resolveProductSlug();
            assertThat(resolved).isEqualTo("scim-server");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Quota & State Invariants Tests
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Quota & State Invariants")
    class QuotaAndStateInvariantTests {

        @Test
        void fiftyFirstPublishAttemptStrictlyRejectedBeforeCallingPublisher() {
            UUID runId = UUID.randomUUID();
            ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
            CompliancePublishFormData form = createValidFormData();
            BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
            RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

            when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
            org.mockito.Mockito.doThrow(new ResponseStatusException(HttpStatus.BAD_REQUEST, "User has reached maximum published compliance runs cap (50)."))
                    .when(validationRunService).validatePublishQuota("developer@example.com");

            String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

            assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
            assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
            assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString())
                    .contains("User has reached maximum published compliance runs cap (50).");

            verify(gitHubCompliancePublisherService, never()).publish(any());
            verify(validationRunService, never()).recordPublication(any(), any(), any(), any());
        }

        @Test
        void duplicatePublishingStrictlyRejected() {
            UUID runId = UUID.randomUUID();
            ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
            ValidationRunPublication pub = createSamplePublication(runId, "developer@example.com", 90);
            runEntity.setPublication(pub);

            CompliancePublishFormData form = createValidFormData();
            BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
            RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

            when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);

            String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

            assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
            assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
            assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString())
                    .contains("already been published");

            verify(gitHubCompliancePublisherService, never()).publish(any());
            verify(validationRunService, never()).recordPublication(any(), any(), any(), any());
        }

        @Test
        void doublePublishRaceCondition_simultaneousThreads_atMostOnePersists() throws Exception {
            UUID runId = UUID.randomUUID();
            ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
            ComplianceScorecardView scorecard = createSampleScorecard(90, true, null);
            CompliancePublicationResult pubResult = new CompliancePublicationResult(
                    true, runId, "https://pr", "https://rep", "https://bad", "sha", null
            );

            when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
            when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
            when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
            when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList())).thenReturn(scorecard);
            when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
            when(gitHubCompliancePublisherService.isEnabled()).thenReturn(true);
            when(gitHubCompliancePublisherService.publish(any())).thenReturn(pubResult);

            // Simulate DB primary key conflict on second publication insert
            AtomicInteger recordCount = new AtomicInteger(0);
            org.mockito.Mockito.doAnswer(invocation -> {
                int count = recordCount.incrementAndGet();
                if (count > 1) {
                    throw new RuntimeException("duplicate key value violates unique constraint \"validation_run_publication_pkey\"");
                }
                return createSamplePublication(runId, "developer@example.com", 90);
            }).when(validationRunService).recordPublication(any(), any(), any(), any());

            int concurrency = 2;
            ExecutorService executor = Executors.newFixedThreadPool(concurrency);
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(concurrency);
            RedirectAttributes[] flashAttrs = new RedirectAttributes[concurrency];

            for (int i = 0; i < concurrency; i++) {
                final int idx = i;
                flashAttrs[idx] = new RedirectAttributesModelMap();
                executor.submit(() -> {
                    try {
                        startLatch.await();
                        CompliancePublishFormData form = createValidFormData();
                        BindingResult br = new BeanPropertyBindingResult(form, "publishForm");
                        controller.publishRun(runId, form, br, userAuth, flashAttrs[idx]);
                    } catch (Exception e) {
                        // ignore
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            startLatch.countDown();
            boolean completed = doneLatch.await(5, TimeUnit.SECONDS);
            executor.shutdown();

            assertThat(completed).isTrue();
            // Exactly one succeeded with successMessage
            long successes = 0;
            long errors = 0;
            for (RedirectAttributes ra : flashAttrs) {
                if (ra.getFlashAttributes().containsKey("successMessage")) successes++;
                if (ra.getFlashAttributes().containsKey("errorMessage")) errors++;
            }
            assertThat(successes).isEqualTo(1);
            assertThat(errors).isEqualTo(1);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Authorization & Security Boundaries Tests
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Authorization & Security Boundaries")
    class AuthorizationAndSecurityBoundaryTests {

        @Test
        void unauthenticatedPublishAttemptThrowsIllegalStateException() {
            UUID runId = UUID.randomUUID();
            CompliancePublishFormData form = createValidFormData();
            BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
            RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

            Authentication emptyAuth = new TestingAuthenticationToken("", "n/a");

            org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                    controller.publishRun(runId, form, bindingResult, emptyAuth, redirectAttributes)
            ).isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Unable to resolve authenticated email");

            org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                    controller.publishRun(runId, form, bindingResult, null, redirectAttributes)
            ).isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Missing authentication");

            verify(validationRunService, never()).getRunEntity(any(), any(), anyBoolean());
            verify(gitHubCompliancePublisherService, never()).publish(any());
        }

        @Test
        void unauthorizedUserCannotPublishOthersRun() {
            UUID runId = UUID.randomUUID();
            CompliancePublishFormData form = createValidFormData();
            BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
            RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

            when(validationRunService.getRunEntity(runId, "attacker@example.com", false))
                    .thenThrow(new ResponseStatusException(HttpStatus.NOT_FOUND, "Test suite not found"));

            String redirect = controller.publishRun(runId, form, bindingResult, attackerAuth, redirectAttributes);

            assertThat(redirect).isEqualTo("redirect:/");
            assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
            assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString())
                    .contains("Test suite not found");

            verify(gitHubCompliancePublisherService, never()).publish(any());
            verify(validationRunService, never()).recordPublication(any(), any(), any(), any());
        }

        @Test
        void nonExistentRunPublishAttemptReturnsNotFound() {
            UUID runId = UUID.randomUUID();
            CompliancePublishFormData form = createValidFormData();
            BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
            RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

            when(validationRunService.getRunEntity(runId, "developer@example.com", false))
                    .thenThrow(new ResponseStatusException(HttpStatus.NOT_FOUND, "Test suite not found"));

            String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

            assertThat(redirect).isEqualTo("redirect:/");
            assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString())
                    .contains("Test suite not found");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Eligibility Bypass & Score Tampering Prevention Tests
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Eligibility Bypass & Score Tampering Prevention")
    class EligibilityAndScoreTamperingTests {

        @Test
        void runWithScore49PercentStrictlyRejected() {
            UUID runId = UUID.randomUUID();
            ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
            ComplianceScorecardView scorecard = createSampleScorecard(49, false, "Core RFC Conformance (49%) is below the minimum 50% publishing threshold");

            CompliancePublishFormData form = createValidFormData();
            BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
            RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

            when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
            when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
            when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
            when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList())).thenReturn(scorecard);
            when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(false);

            String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

            assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
            assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
            assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString())
                    .contains("below the minimum 50% publishing threshold");

            verify(gitHubCompliancePublisherService, never()).publish(any());
        }

        @ParameterizedTest(name = "Non-terminal status rejected: [{0}]")
        @ValueSource(strings = {"RUNNING", "ERROR", "IN_PROGRESS", "PENDING", "INITIALIZING"})
        void nonTerminalRunStatusStrictlyRejected(String nonTerminalStatus) {
            UUID runId = UUID.randomUUID();
            ValidationRun runEntity = createSampleRun(runId, "developer@example.com", nonTerminalStatus);
            ComplianceScorecardView scorecard = createSampleScorecard(95, false, "Validation run status (" + nonTerminalStatus + ") is not eligible for publication.");

            CompliancePublishFormData form = createValidFormData();
            BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
            RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

            when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
            when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
            when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
            when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList())).thenReturn(scorecard);
            when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(false);

            String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

            assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
            assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
            assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString())
                    .contains("Publication rejected");

            verify(gitHubCompliancePublisherService, never()).publish(any());
        }

        @Test
        void scoreTamperingAttempt_ignoresClientInjectedAttributes() {
            UUID runId = UUID.randomUUID();
            ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
            runEntity.setTargetUrl("https://scim.genuine-corp.internal");
            ComplianceScorecardView genuineScorecard = createSampleScorecard(76, true, null);

            CompliancePublicationResult pubResult = new CompliancePublicationResult(
                    true, runId, "https://pr", "https://report", "https://badge", "sha", null
            );

            // Client attempts to pass legitimate form metadata
            CompliancePublishFormData form = createValidFormData();
            BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
            RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

            when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
            when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
            when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
            when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList())).thenReturn(genuineScorecard);
            when(complianceScoreService.isEligibleForPublish(genuineScorecard, runEntity)).thenReturn(true);
            when(gitHubCompliancePublisherService.isEnabled()).thenReturn(true);
            when(gitHubCompliancePublisherService.publish(any())).thenReturn(pubResult);

            controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

            // Verify the publish request passed to GitHub publisher matches genuine server evaluation
            ArgumentCaptor<CompliancePublishRequest> captor = ArgumentCaptor.forClass(CompliancePublishRequest.class);
            verify(gitHubCompliancePublisherService).publish(captor.capture());

            CompliancePublishRequest sentRequest = captor.getValue();
            assertThat(sentRequest.coreScore()).isEqualTo(76);
            assertThat(sentRequest.colourGradient()).isEqualTo(ColourGradient.forScore(76).name());
            assertThat(sentRequest.targetUrl()).isEqualTo("https://scim.genuine-corp.internal");
            assertThat(sentRequest.actorEmail()).isEqualTo("developer@example.com");
            assertThat(sentRequest.scorecard()).isSameAs(genuineScorecard);
        }

        @Test
        void adminPublishingAnotherUsersRun_validatesQuotaForRunOwnerAndPassesScorecard() {
            UUID runId = UUID.randomUUID();
            ValidationRun aliceRun = createSampleRun(runId, "alice@example.com", "PASSED");
            ComplianceScorecardView scorecard = createSampleScorecard(96, true, null);
            CompliancePublicationResult pubResult = new CompliancePublicationResult(
                    true, runId, "https://pr", "https://report", "https://badge", "sha", null
            );

            CompliancePublishFormData form = createValidFormData();
            BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
            RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

            when(validationRunService.getRunEntity(runId, "admin@example.com", true)).thenReturn(aliceRun);
            when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
            when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
            when(complianceScoreService.computeScorecard(aliceRun, Collections.emptyList(), Collections.emptyList())).thenReturn(scorecard);
            when(complianceScoreService.isEligibleForPublish(scorecard, aliceRun)).thenReturn(true);
            when(gitHubCompliancePublisherService.isEnabled()).thenReturn(true);
            when(gitHubCompliancePublisherService.publish(any())).thenReturn(pubResult);

            Authentication adminAuth = new TestingAuthenticationToken("admin@example.com", "n/a", "ROLE_ADMIN");
            controller.publishRun(runId, form, bindingResult, adminAuth, redirectAttributes);

            verify(validationRunService).validatePublishQuota("alice@example.com");
            verify(validationRunService).recordPublication(eq(aliceRun), eq("admin@example.com"), any(CompliancePublishRequest.class), eq(pubResult));
        }

        @Test
        void detail_whenRunNameContainsTargetUrlOrIp_doesNotPreFillProductName() {
            UUID runId = UUID.randomUUID();
            ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
            runEntity.setName("Run against https://internal-scim.corp:8443/scim/v2");
            ComplianceScorecardView scorecard = createSampleScorecard(95, true, null);
            org.springframework.ui.ExtendedModelMap model = new org.springframework.ui.ExtendedModelMap();

            when(validationRunService.getRun(runId, "developer@example.com", false))
                    .thenReturn(de.palsoftware.scim.validator.ui.dto.ValidationRunView.from(runEntity));
            when(validationRunService.getTestResults(runId, "developer@example.com", false)).thenReturn(Collections.emptyList());
            when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
            when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
            when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
            when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList())).thenReturn(scorecard);
            when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);

            controller.detail(runId, model, userAuth);

            CompliancePublishFormData publishForm = (CompliancePublishFormData) model.getAttribute("publishForm");
            assertThat(publishForm).isNotNull();
            assertThat(publishForm.getProductName()).isEmpty();
            assertThat(publishForm.getProductSlug()).isEmpty();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 6. External Publisher Failure Resilience Tests
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("External Publisher Failure Resilience")
    class ExternalPublisherFailureResilienceTests {

        @Test
        void publisherThrowsRuntimeException_catchesAndNeverPersistsPublication() {
            UUID runId = UUID.randomUUID();
            ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
            ComplianceScorecardView scorecard = createSampleScorecard(92, true, null);

            CompliancePublishFormData form = createValidFormData();
            BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
            RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

            when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
            when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
            when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
            when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList())).thenReturn(scorecard);
            when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
            when(gitHubCompliancePublisherService.isEnabled()).thenReturn(true);
            when(gitHubCompliancePublisherService.publish(any())).thenThrow(new RuntimeException("GitHub 409 Conflict: branch already exists"));

            String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

            assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
            assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
            assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString())
                    .contains("GitHub publishing failed: GitHub 409 Conflict");

            verify(validationRunService, never()).recordPublication(any(), any(), any(), any());
        }

        @Test
        void publisherReturnsUnsuccessfulResult_handlesGracefully() {
            UUID runId = UUID.randomUUID();
            ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
            ComplianceScorecardView scorecard = createSampleScorecard(92, true, null);

            CompliancePublicationResult failureResult = new CompliancePublicationResult(
                    false, runId, null, null, null, null, "Squash merge rejected by protected branch rules"
            );

            CompliancePublishFormData form = createValidFormData();
            BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
            RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

            when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
            when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
            when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
            when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList())).thenReturn(scorecard);
            when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
            when(gitHubCompliancePublisherService.isEnabled()).thenReturn(true);
            when(gitHubCompliancePublisherService.publish(any())).thenReturn(failureResult);

            String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

            assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
            assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
            assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString())
                    .contains("Publication failed: Squash merge rejected");

            verify(validationRunService, never()).recordPublication(any(), any(), any(), any());
        }

        @Test
        void publisherSucceedsButDatabasePersistenceFails_notifiesUserOfPartialFailure() {
            UUID runId = UUID.randomUUID();
            ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
            ComplianceScorecardView scorecard = createSampleScorecard(92, true, null);

            CompliancePublicationResult pubResult = new CompliancePublicationResult(
                    true, runId, "https://pr", "https://report", "https://badge", "sha", null
            );

            CompliancePublishFormData form = createValidFormData();
            BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
            RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

            when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
            when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
            when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
            when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList())).thenReturn(scorecard);
            when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
            when(gitHubCompliancePublisherService.isEnabled()).thenReturn(true);
            when(gitHubCompliancePublisherService.publish(any())).thenReturn(pubResult);
            org.mockito.Mockito.doThrow(new RuntimeException("PostgreSQL connection timeout"))
                    .when(validationRunService).recordPublication(any(), any(), any(), any());

            String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

            assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
            assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
            assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString())
                    .contains("Publication merged to GitHub but failed to update local database: PostgreSQL connection timeout");
        }

        @Test
        void publisherServiceDisabled_rejectsCleanly() {
            UUID runId = UUID.randomUUID();
            ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
            ComplianceScorecardView scorecard = createSampleScorecard(92, true, null);

            CompliancePublishFormData form = createValidFormData();
            BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
            RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

            when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
            when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
            when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
            when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList())).thenReturn(scorecard);
            when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
            when(gitHubCompliancePublisherService.isEnabled()).thenReturn(false);

            String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

            assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
            assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
            assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString())
                    .contains("GitHub compliance publisher is disabled or unavailable");

            verify(gitHubCompliancePublisherService, never()).publish(any());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper Factories
    // ─────────────────────────────────────────────────────────────────────────

    private CompliancePublishFormData createValidFormData() {
        return new CompliancePublishFormData(
                "Apache Syncope", "apache-syncope", "3.0.0", "ASF", "https://syncope.apache.org", "Apache-2.0", true
        );
    }

    private ValidationRun createSampleRun(UUID runId, String userEmail, String status) {
        ValidationRun run = new ValidationRun();
        ReflectionTestUtils.setField(run, "id", runId);
        run.setName("Sample SCIM Validation");
        run.setTargetUrl("https://scim.example.com");
        run.setStatus(status);
        run.setTotalTests(52);
        run.setPassedTests("PASSED".equals(status) ? 52 : 40);
        run.setFailedTests("PASSED".equals(status) ? 0 : 12);
        run.setExecutedAt(OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(5));
        ValidationMgmtUser user = new ValidationMgmtUser(userEmail, OffsetDateTime.now(ZoneOffset.UTC));
        run.setCreatedByUser(user);
        return run;
    }

    private ValidationRunPublication createSamplePublication(UUID runId, String userEmail, int score) {
        ValidationRunPublication pub = new ValidationRunPublication();
        pub.setRunId(runId);
        pub.setCreatedByEmail(userEmail);
        pub.setProductName("Sample SCIM Product");
        pub.setProductSlug("sample-scim-product");
        pub.setProductVersion("1.0.0");
        pub.setVendorName("Sample Org");
        pub.setLicenseType("Apache-2.0");
        pub.setShowSubmitter(false);
        pub.setCoreScore(score);
        pub.setSupportedCapabilities(9);
        pub.setTotalCapabilities(10);
        pub.setReportUrl("https://scimsandbox.net/compliance/?run=" + runId);
        pub.setBadgeUrl("https://scimsandbox.net/compliance/badges/" + runId + ".svg");
        pub.setPrUrl("https://github.com/scimsandbox/scim-website/pull/1");
        pub.setPublishedAt(OffsetDateTime.now(ZoneOffset.UTC));
        return pub;
    }

    private ComplianceScorecardView createSampleScorecard(int score, boolean eligible, String reason) {
        ColourGradient gradient = ColourGradient.forScore(score);
        return new ComplianceScorecardView(
                UUID.randomUUID(), "Sample SCIM Validation", "https://scim.example.com", OffsetDateTime.now(ZoneOffset.UTC), "PASSED",
                score, gradient,
                eligible,
                reason,
                NormativeBreakdown.of("MUST", 3, 132, 130, 2, 0, 390.0, 396.0),
                NormativeBreakdown.of("SHOULD", 2, 9, 8, 1, 0, 16.0, 18.0),
                NormativeBreakdown.of("MAY", 1, 3, 3, 0, 0, 3.0, 3.0),
                Collections.emptyList(), 9, 8, 10,
                157, 144, 0, 13,
                Collections.emptyMap(), Collections.emptyList()
        );
    }
}
