-- Baht Desk phase 2: shared order book
-- Run once in Supabase → SQL Editor → New query → Run.
-- Then Authentication → Users → Add user: one shop account (email + strong password).
-- IMPORTANT: Authentication → Sign In / Providers → turn OFF "Allow new users to sign up",
-- otherwise anyone with the page's public key could create an account and read the book.
-- Connect each shop device in Baht Desk → Desk → Shared book with that account.

create table if not exists public.bd_orders (
  id text primary key,
  data jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid()
);
create table if not exists public.bd_customers (
  id text primary key,
  data jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid()
);

-- keep updated_at moving on every change, so devices can pull "what changed since"
create or replace function public.bd_touch() returns trigger language plpgsql as $$
begin
  new.updated_at := clock_timestamp();
  new.updated_by := auth.uid();
  return new;
end $$;
drop trigger if exists bd_orders_touch on public.bd_orders;
create trigger bd_orders_touch before insert or update on public.bd_orders for each row execute function public.bd_touch();
drop trigger if exists bd_customers_touch on public.bd_customers;
create trigger bd_customers_touch before insert or update on public.bd_customers for each row execute function public.bd_touch();

create index if not exists bd_orders_updated on public.bd_orders (updated_at);
create index if not exists bd_customers_updated on public.bd_customers (updated_at);

-- Row level security: only signed-in users (the shop account) can read or write.
-- The public anon key in the page can do nothing on its own.
alter table public.bd_orders enable row level security;
alter table public.bd_customers enable row level security;
drop policy if exists bd_orders_shop on public.bd_orders;
create policy bd_orders_shop on public.bd_orders for all to authenticated using (true) with check (true);
drop policy if exists bd_customers_shop on public.bd_customers;
create policy bd_customers_shop on public.bd_customers for all to authenticated using (true) with check (true);
revoke all on public.bd_orders, public.bd_customers from anon;
grant select, insert, update on public.bd_orders, public.bd_customers to authenticated;
-- no delete grant: orders are cancelled, never deleted

-- KYC supporting documents: private storage bucket, signed-in shop account only
insert into storage.buckets (id, name, public, file_size_limit)
values ('bd-kyc', 'bd-kyc', false, 10485760)
on conflict (id) do nothing;
drop policy if exists bd_kyc_read on storage.objects;
create policy bd_kyc_read on storage.objects for select to authenticated using (bucket_id = 'bd-kyc');
drop policy if exists bd_kyc_upload on storage.objects;
create policy bd_kyc_upload on storage.objects for insert to authenticated with check (bucket_id = 'bd-kyc');
-- no update/delete policy: uploaded KYC documents are kept (removing one in Baht Desk only unlinks it)

-- ===== Client self-registration (KYC) =====
-- Clients register from Baht Desk without signing in: they can ADD a registration and its two photos,
-- but cannot read, change or delete anything. Only the signed-in shop account (admin devices) can read them.
create table if not exists public.bd_kyc_req (
  id text primary key,
  data jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid()
);
drop trigger if exists bd_kyc_req_touch on public.bd_kyc_req;
create trigger bd_kyc_req_touch before insert or update on public.bd_kyc_req for each row execute function public.bd_touch();
create index if not exists bd_kyc_req_updated on public.bd_kyc_req (updated_at);
alter table public.bd_kyc_req enable row level security;
drop policy if exists bd_kyc_req_client_add on public.bd_kyc_req;
create policy bd_kyc_req_client_add on public.bd_kyc_req for insert to anon
  with check (id like 'KYC-%' and data->>'st' = 'pending' and length(data::text) < 20000);
drop policy if exists bd_kyc_req_shop on public.bd_kyc_req;
create policy bd_kyc_req_shop on public.bd_kyc_req for all to authenticated using (true) with check (true);
grant insert on public.bd_kyc_req to anon;
grant select, insert, update on public.bd_kyc_req to authenticated;

-- clients may upload photos only into reg/<their registration>/ ; they cannot list or read them
drop policy if exists bd_kyc_client_upload on storage.objects;
create policy bd_kyc_client_upload on storage.objects for insert to anon
  with check (bucket_id = 'bd-kyc' and name like 'reg/KYC-%' and lower(name) like '%.jpg');
