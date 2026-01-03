-- Add unique constraint for request_stats upsert
-- This allows proper ON CONFLICT handling for (tunnel_id, period_start) pairs

-- Drop the old constraint reference if it exists (handles idempotency)
-- Note: If the constraint already exists, this migration is a no-op

DO $$
BEGIN
    -- Check if the constraint already exists
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint 
        WHERE conname = 'request_stats_tunnel_period_unique'
    ) THEN
        -- Add the unique constraint
        ALTER TABLE request_stats ADD CONSTRAINT request_stats_tunnel_period_unique 
            UNIQUE (tunnel_id, period_start);
        RAISE NOTICE 'Created unique constraint request_stats_tunnel_period_unique';
    ELSE
        RAISE NOTICE 'Constraint request_stats_tunnel_period_unique already exists, skipping';
    END IF;
END $$;

