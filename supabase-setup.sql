-- ============================================================================
-- EventTrack — database setup
--
-- Run this ONCE, in your Supabase project: SQL Editor → New query → paste →
-- Run. It creates the two tables the app needs and locks them down so that a
-- signed-in user can only ever read their own organisation's data.
--
-- Nothing here is optional. The security in this app is these policies. The
-- key you paste into the web page is public by design and gives access to
-- nothing on its own — every read and write is checked against the policies
-- below, on the server, where the browser cannot interfere.
-- ============================================================================


-- ----------------------------------------------------------------------------
-- 1. Who is allowed in, and as what
--
-- Roles mirror the ones already in the app. The difference is that this copy
-- lives on the server, so a user cannot promote themselves by editing what
-- their browser holds.
-- ----------------------------------------------------------------------------
create table if not exists public.members (
  user_id     uuid primary key references auth.users (id) on delete cascade,
  org_id      uuid not null,
  role        text not null check (role in ('admin', 'executive', 'volunteer', 'guest')),
  full_name   text,
  created_at  timestamptz not null default now()
);

comment on table public.members is
  'Maps an authenticated user to one organisation and one role.';


-- ----------------------------------------------------------------------------
-- 2. The data itself
--
-- The app keeps its records as a handful of large keyed values rather than
-- normalised tables, so this mirrors that shape. `version` is what stops two
-- people saving over each other: a write only lands if the version it was
-- based on is still the current one.
-- ----------------------------------------------------------------------------
create table if not exists public.app_state (
  org_id      uuid not null,
  key         text not null,
  value       text,
  version     bigint not null default 1,
  updated_at  timestamptz not null default now(),
  updated_by  uuid references auth.users (id),
  primary key (org_id, key)
);

comment on column public.app_state.version is
  'Incremented on every write. A stale write is rejected rather than applied.';


-- ----------------------------------------------------------------------------
-- 3. Row level security
--
-- With RLS enabled and no policy, nothing is readable. Each policy below then
-- grants back exactly one thing.
-- ----------------------------------------------------------------------------
alter table public.members   enable row level security;
alter table public.app_state enable row level security;

-- Helper: the organisation the current user belongs to.
-- SECURITY DEFINER so it can read `members` without recursing through the
-- policy that is being evaluated.
create or replace function public.current_org_id()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select org_id from public.members where user_id = auth.uid();
$$;

create or replace function public.current_role_name()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select role from public.members where user_id = auth.uid();
$$;

-- A user may read their own membership row, and nobody else's.
drop policy if exists members_read_own on public.members;
create policy members_read_own on public.members
  for select
  using (user_id = auth.uid());

-- Reading data: must belong to the organisation that owns the row.
drop policy if exists app_state_read on public.app_state;
create policy app_state_read on public.app_state
  for select
  using (org_id = public.current_org_id());

-- Writing data: same organisation, and not a guest.
-- Guests are read-only by definition, so the restriction is enforced here
-- rather than trusted to the interface.
drop policy if exists app_state_insert on public.app_state;
create policy app_state_insert on public.app_state
  for insert
  with check (
    org_id = public.current_org_id()
    and public.current_role_name() in ('admin', 'executive', 'volunteer')
  );

drop policy if exists app_state_update on public.app_state;
create policy app_state_update on public.app_state
  for update
  using (
    org_id = public.current_org_id()
    and public.current_role_name() in ('admin', 'executive', 'volunteer')
  )
  with check (org_id = public.current_org_id());

-- Deleting is for admins only.
drop policy if exists app_state_delete on public.app_state;
create policy app_state_delete on public.app_state
  for delete
  using (
    org_id = public.current_org_id()
    and public.current_role_name() = 'admin'
  );


-- ----------------------------------------------------------------------------
-- 4. Conflict-safe write
--
-- The client calls this instead of updating directly. It returns the new
-- version on success, or -1 when the client was working from a stale copy —
-- which the app turns into a visible warning rather than a silent overwrite.
-- ----------------------------------------------------------------------------
create or replace function public.put_state(
  p_key text,
  p_value text,
  p_expected_version bigint
)
returns bigint
language plpgsql
security invoker
set search_path = public
as $$
declare
  v_org uuid := public.current_org_id();
  v_new bigint;
begin
  if v_org is null then
    raise exception 'not a member of any organisation';
  end if;

  -- First write for this key.
  if p_expected_version is null or p_expected_version = 0 then
    insert into public.app_state (org_id, key, value, version, updated_at, updated_by)
    values (v_org, p_key, p_value, 1, now(), auth.uid())
    on conflict (org_id, key) do nothing
    returning version into v_new;

    if v_new is null then
      return -1;   -- somebody created it first
    end if;
    return v_new;
  end if;

  update public.app_state
     set value = p_value,
         version = version + 1,
         updated_at = now(),
         updated_by = auth.uid()
   where org_id = v_org
     and key = p_key
     and version = p_expected_version
  returning version into v_new;

  if v_new is null then
    return -1;     -- stale: someone else saved in the meantime
  end if;
  return v_new;
end;
$$;


-- ============================================================================
-- 5. Add your people
--
-- Create each user first: Authentication → Users → Add user (set a password
-- and tick "Auto Confirm User"). Then run the block below once per person.
--
-- Everyone in your organisation must share the SAME org_id. Generate one
-- value, then reuse that exact value for every member.
--
--    select gen_random_uuid();     -- run this once, copy the result
--
-- Replace the email, paste your org_id, and choose a role:
--   admin      — everything, including money, deletions and settings
--   executive  — day to day; no deletions, no settings
--   volunteer  — check-in desk only
--   guest      — read only
-- ============================================================================

-- insert into public.members (user_id, org_id, role, full_name)
-- select id, 'PASTE-YOUR-ORG-ID-HERE'::uuid, 'admin', 'Your Name'
--   from auth.users where email = 'you@example.com';


-- ----------------------------------------------------------------------------
-- Useful afterwards
-- ----------------------------------------------------------------------------
-- Who has access, and as what:
--   select m.role, m.full_name, u.email
--     from public.members m join auth.users u on u.id = m.user_id;
--
-- Change somebody's role:
--   update public.members set role = 'volunteer'
--    where user_id = (select id from auth.users where email = 'them@example.com');
--
-- Revoke access entirely:
--   delete from public.members
--    where user_id = (select id from auth.users where email = 'them@example.com');
