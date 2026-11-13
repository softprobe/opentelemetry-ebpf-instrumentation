CREATE TABLE IF NOT EXISTS catalog_items (
    id BIGINT PRIMARY KEY,
    code TEXT NOT NULL,
    title TEXT NOT NULL,
    price_cents INTEGER NOT NULL,
    in_stock BOOLEAN NOT NULL,
    attrs JSONB NOT NULL
);

INSERT INTO catalog_items (id, code, title, price_cents, in_stock, attrs)
SELECT
    i,
    format('SKU-%03s', i),
    format('Travel Package %s', i),
    10000 + (i * 450),
    true,
    jsonb_build_object('tier', CASE WHEN i % 2 = 0 THEN 'flex' ELSE 'saver' END, 'nights', 2 + (i % 5))
FROM generate_series(1, 25) AS s(i)
ON CONFLICT (id) DO NOTHING;
