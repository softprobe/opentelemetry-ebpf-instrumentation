CREATE TABLE IF NOT EXISTS ota_orders (
    confirmation_number VARCHAR(64) PRIMARY KEY,
    passenger_last_name VARCHAR(128) NOT NULL,
    booking_json JSONB NOT NULL
);
