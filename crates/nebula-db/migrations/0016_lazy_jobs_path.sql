-- 010 polish — extend lazy_jobs with the (tenant, project, repository)
-- a worker needs to locate the source layer in object storage.
--
-- Slice 1 left these implicit because there was no worker yet; slice 2
-- spawned a stub worker; slice 3-polish wires a real ObjectStore-backed
-- fetcher and needs the storage path. Pre-existing rows (if any from
-- the stub worker) get NULLs which the worker treats as unfetchable.

ALTER TABLE lazy_jobs
    ADD COLUMN IF NOT EXISTS tenant TEXT,
    ADD COLUMN IF NOT EXISTS project TEXT,
    ADD COLUMN IF NOT EXISTS repository TEXT;
