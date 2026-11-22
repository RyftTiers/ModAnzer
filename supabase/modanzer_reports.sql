-- ModAnzer screenshare reports, saved by supabase/functions/modanzer-report and
-- read by the RyftTiers bot's /ssresult command. Run in the RyftTiers Supabase project.
create table if not exists public.modanzer_reports (
  id           bigint generated always as identity primary key,
  ref_code     text not null unique,
  tool         text not null default 'ModAnzer',
  mode         text,
  finished     text,
  discord_id   text,
  accounts     jsonb not null default '[]'::jsonb,
  mods         jsonb,
  system       jsonb,
  injection    jsonb,
  status       text not null default 'new',   -- new -> checked
  sender_hash  text,
  received_at  timestamptz not null default now(),
  checked_by   text,                           -- Discord id of the staff member who ran /ssresult
  checked_at   timestamptz,
  player_id    text                            -- Discord id given in /ssresult user:
);

-- Only the service role (the report function and the bot) can read or write it.
alter table public.modanzer_reports enable row level security;
