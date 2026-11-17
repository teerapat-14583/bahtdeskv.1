-- Baht Desk: client accounts (username + password) - security update
-- Clients now sign up themselves, so "signed in" no longer means "staff".
-- Staff accounts carry role "staff" in app_metadata (only the project owner can set it);
-- clients can only add and read their OWN registration and upload their OWN photos.

create or replace function public.bd_is_staff() returns boolean
language sql stable as $$
  select coalesce((auth.jwt() -> 'app_metadata' ->> 'role') = 'staff', false)
$$;

-- mark the staff accounts
update auth.users
   set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb) || '{"role":"staff"}'::jsonb
 where email in ('teerapat.tewar@gmail.com', 'h.oaun.lohakit@gmail.com');

-- orders and customers: staff only
drop policy if exists bd_orders_shop on public.bd_orders;
drop policy if exists bd_orders_staff on public.bd_orders;
create policy bd_orders_staff on public.bd_orders for all to authenticated
  using (public.bd_is_staff()) with check (public.bd_is_staff());
drop policy if exists bd_customers_shop on public.bd_customers;
drop policy if exists bd_customers_staff on public.bd_customers;
create policy bd_customers_staff on public.bd_customers for all to authenticated
  using (public.bd_is_staff()) with check (public.bd_is_staff());

-- registrations: staff see and decide all; a client adds and reads only their own, and may upgrade or re-send
drop policy if exists bd_kyc_req_shop on public.bd_kyc_req;
drop policy if exists bd_kyc_req_client_add on public.bd_kyc_req;
drop policy if exists bd_kyc_req_staff on public.bd_kyc_req;
drop policy if exists bd_kyc_req_own_read on public.bd_kyc_req;
drop policy if exists bd_kyc_req_own_add on public.bd_kyc_req;
drop policy if exists bd_kyc_req_own_resend on public.bd_kyc_req;
revoke insert on public.bd_kyc_req from anon;
create policy bd_kyc_req_staff on public.bd_kyc_req for all to authenticated
  using (public.bd_is_staff()) with check (public.bd_is_staff());
create policy bd_kyc_req_own_read on public.bd_kyc_req for select to authenticated
  using (data ->> 'uid' = auth.uid()::text);
create policy bd_kyc_req_own_add on public.bd_kyc_req for insert to authenticated
  with check (id = 'KYC-' || auth.uid()::text and data ->> 'uid' = auth.uid()::text
              and data ->> 'st' in ('pending','observe') and length(data::text) < 20000);
-- a client may change their own record only to upgrade (observe -> pending) or re-send after a rejection
create policy bd_kyc_req_own_resend on public.bd_kyc_req for update to authenticated
  using (data ->> 'uid' = auth.uid()::text and data ->> 'st' in ('rejected','observe'))
  with check (data ->> 'uid' = auth.uid()::text and data ->> 'st' in ('pending','observe') and length(data::text) < 20000);

-- photos: staff read and add; a client adds only into reg/<their id>/
drop policy if exists bd_kyc_read on storage.objects;
drop policy if exists bd_kyc_upload on storage.objects;
drop policy if exists bd_kyc_client_upload on storage.objects;
drop policy if exists bd_kyc_staff_read on storage.objects;
drop policy if exists bd_kyc_staff_upload on storage.objects;
drop policy if exists bd_kyc_own_upload on storage.objects;
create policy bd_kyc_staff_read on storage.objects for select to authenticated
  using (bucket_id = 'bd-kyc' and public.bd_is_staff());
create policy bd_kyc_staff_upload on storage.objects for insert to authenticated
  with check (bucket_id = 'bd-kyc' and public.bd_is_staff());
create policy bd_kyc_own_upload on storage.objects for insert to authenticated
  with check (bucket_id = 'bd-kyc' and name like 'reg/' || auth.uid()::text || '/%' and lower(name) like '%.jpg');
