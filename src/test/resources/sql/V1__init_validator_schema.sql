CREATE TABLE validator_mgmt_users (
    email VARCHAR(500) PRIMARY KEY,
    last_login_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE validation_run (
    id UUID PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    target_url VARCHAR(500) NOT NULL,
    executed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) NOT NULL,
    created_by_email VARCHAR(500) NOT NULL,
    total_tests INTEGER NOT NULL,
    passed_tests INTEGER NOT NULL,
    failed_tests INTEGER NOT NULL,
    CONSTRAINT fk_validation_run_created_by_user
        FOREIGN KEY (created_by_email) REFERENCES validator_mgmt_users (email)
);

CREATE INDEX idx_validation_run_created_by_email ON validation_run (created_by_email);
CREATE INDEX idx_validation_run_executed_at ON validation_run (executed_at DESC);

CREATE TABLE validation_test_result (
    id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    test_identifier VARCHAR(500) NOT NULL,
    class_name VARCHAR(300),
    test_name VARCHAR(300),
    display_name VARCHAR(500),
    status VARCHAR(20) NOT NULL,
    error_message TEXT,
    stack_trace TEXT,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    finished_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT fk_validation_test_result_run
        FOREIGN KEY (run_id) REFERENCES validation_run (id) ON DELETE CASCADE
);

CREATE INDEX idx_validation_test_result_run_id_started_at
    ON validation_test_result (run_id, started_at ASC);

CREATE TABLE validation_http_exchange (
    id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    test_result_id UUID NOT NULL,
    sequence_number INTEGER NOT NULL,
    method VARCHAR(16),
    url VARCHAR(1000),
    request_headers TEXT,
    request_body TEXT,
    response_status INTEGER,
    response_headers TEXT,
    response_body TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT fk_validation_http_exchange_run
        FOREIGN KEY (run_id) REFERENCES validation_run (id) ON DELETE CASCADE,
    CONSTRAINT fk_validation_http_exchange_test_result
        FOREIGN KEY (test_result_id) REFERENCES validation_test_result (id) ON DELETE CASCADE
);

CREATE INDEX idx_validation_http_exchange_test_result_sequence
    ON validation_http_exchange (test_result_id, sequence_number ASC);
CREATE INDEX idx_validation_http_exchange_run_id ON validation_http_exchange (run_id);
