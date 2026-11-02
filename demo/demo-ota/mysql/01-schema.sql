CREATE TABLE IF NOT EXISTS ota_payments (
    payment_id VARCHAR(64) PRIMARY KEY,
    booking_id VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    amount DECIMAL(12, 2) NOT NULL,
    currency CHAR(3) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
