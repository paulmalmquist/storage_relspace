SET LOCAL ROLE strongbox_owner;
CREATE INDEX ix_outbox_app_ready ON outbox (app,available_at,id)
    WHERE status IN ('pending','leased');
