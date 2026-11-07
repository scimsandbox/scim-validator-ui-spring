-- Allow composite foreign key reference from validation_run_publication to enforce
-- that validation_run_publication.created_by_email always matches validation_run.created_by_email.
ALTER TABLE validation_run
    ADD CONSTRAINT uk_validation_run_id_created_by_email UNIQUE (id, created_by_email);

-- Stores metadata for compliance runs published to the public leaderboard via GitHub PR.
-- Design notes:
-- 1. created_by_email is denormalized from validation_run for direct quota/listing index lookups
--    and is locked to validation_run.created_by_email via the composite fk_validation_run_publication_run
--    (which also transitively enforces fk_validation_run_created_by_user -> validator_mgmt_users).
-- 2. ON DELETE RESTRICT on fk_validation_run_publication_run is intentional: published runs must
--    never be auto-pruned or deleted by regular users or admins while a publication record exists
--    so product-slug ownership and public compliance directory links remain intact.
-- 3. core_score is the rounded 0-100 Core RFC Conformance percentage (not a raw test count).
-- 4. Multiple runs for the same (product_slug, product_version) are permitted (e.g. re-runs after
--    a closed PR) and ordered by recency via idx_validation_run_publication_slug_version.
CREATE TABLE validation_run_publication (
    run_id UUID PRIMARY KEY,
    created_by_email VARCHAR(500) NOT NULL,
    product_name VARCHAR(120) NOT NULL,
    product_slug VARCHAR(120) NOT NULL,
    product_version VARCHAR(60) NOT NULL,
    vendor_name VARCHAR(120),
    project_url VARCHAR(500),
    license_type VARCHAR(40) NOT NULL,
    show_submitter BOOLEAN NOT NULL DEFAULT FALSE,
    core_score INTEGER NOT NULL,
    supported_capabilities INTEGER NOT NULL,
    total_capabilities INTEGER NOT NULL,
    report_url VARCHAR(500) NOT NULL,
    badge_url VARCHAR(500) NOT NULL,
    pr_url VARCHAR(500),
    published_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT chk_validation_run_publication_core_score
        CHECK (core_score >= 0 AND core_score <= 100),
    CONSTRAINT chk_validation_run_publication_capabilities
        CHECK (supported_capabilities >= 0 AND total_capabilities > 0 AND supported_capabilities <= total_capabilities),
    CONSTRAINT fk_validation_run_publication_run
        FOREIGN KEY (run_id, created_by_email) REFERENCES validation_run (id, created_by_email) ON DELETE RESTRICT
);

CREATE INDEX idx_validation_run_publication_email
    ON validation_run_publication (created_by_email, published_at DESC);

CREATE INDEX idx_validation_run_publication_slug_version
    ON validation_run_publication (product_slug, product_version, published_at DESC);
