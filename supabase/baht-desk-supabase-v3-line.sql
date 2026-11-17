-- Baht Desk: LINE entry, roles and customer Buy/Sell requests
-- Roles live in app_metadata.role: client | staff | admin (only the server can set them).

create or replace function public.bd_is_staff() returns boolean
language sql stable as $$
  select coalesce((auth.jwt() -> 'app_metadata' ->> 'role') in ('staff','admin'), false)
$$;

-- the owner's staff email becomes admin, so it can give roles to LINE accounts
update auth.users
   set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb) || '{"role":"admin"}'::jsonb
 where email = 'teerapat.tewar@gmail.com';

-- customer Buy/Sell requests: a Trade customer adds and reads their own; staff see and answer all
create table if not exists public.bd_requests (
  id text primary key,
  data jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid()
);
drop trigger if exists bd_requests_touch on public.bd_requests;
create trigger bd_requests_touch before insert or update on public.bd_requests for each row execute function public.bd_touch();
create index if not exists bd_requests_updated on public.bd_requests (updated_at);
alter table public.bd_requests enable row level security;
revoke all on public.bd_requests from anon;
grant select, insert, update on public.bd_requests to authenticated;
drop policy if exists bd_requests_staff on public.bd_requests;
create policy bd_requests_staff on public.bd_requests for all to authenticated
  using (public.bd_is_staff()) with check (public.bd_is_staff());
drop policy if exists bd_requests_own_read on public.bd_requests;
create policy bd_requests_own_read on public.bd_requests for select to authenticated
  using (data ->> 'uid' = auth.uid()::text);
-- only a customer whose registration is approved as a Trade account can send a request
drop policy if exists bd_requests_own_add on public.bd_requests;
create policy bd_requests_own_add on public.bd_requests for insert to authenticated
  with check (data ->> 'uid' = auth.uid()::text and data ->> 'st' = 'new' and length(data::text) < 5000
              and exists (select 1 from public.bd_kyc_req k where k.id = 'KYC-' || auth.uid()::text
                          and k.data ->> 'st' = 'approved' and k.data ->> 'acc' = 'trade'));
-- a customer may cancel their own request while it is still new
drop policy if exists bd_requests_own_cancel on public.bd_requests;
create policy bd_requests_own_cancel on public.bd_requests for update to authenticated
  using (data ->> 'uid' = auth.uid()::text and data ->> 'st' = 'new')
  with check (data ->> 'uid' = auth.uid()::text and data ->> 'st' = 'cancelled');
