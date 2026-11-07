-- Development only. The API connects as this login; `strongbox init -bootstrap-roles` makes it a
-- member of strongbox_runtime and nothing else. Migrations and admin commands use the postgres
-- superuser through STRONGBOX_MIGRATION_DATABASE_URL.
CREATE ROLE strongbox_api LOGIN PASSWORD 'strongbox-api' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
