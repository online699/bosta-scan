-- =====================================================================
--  مسح الشحنات — قاعدة البيانات + المستخدمين + الصلاحيات (Supabase)
--  شغّل الملف كله مرة واحدة في: Supabase → SQL Editor → New query → Run
--  (آمن لو شغّلته مرتين)
-- =====================================================================

-- ---------- المستخدمون وصلاحياتهم ----------
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  username   text not null unique check (username ~ '^[a-z0-9._-]{3,32}$'),
  role       text not null check (role in ('admin','supervisor','scanner')),
  active     boolean not null default true,
  created_at timestamptz not null default now()
);

-- بترجّع صلاحية المستخدم الحالي (أو null لو غير موجود/موقوف)
create or replace function public.app_role()
returns text language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid() and active
$$;
revoke all on function public.app_role() from public, anon;
grant execute on function public.app_role() to authenticated;

-- ---------- البراندات (الإعدادات) ----------
create table if not exists public.brands (
  id         text primary key,
  name       text not null,
  color      text not null default '#555555',
  carrier    text not null default 'bosta' check (carrier in ('bosta','custom','none')),
  tpl        text,
  pre        text,
  bg_type    text,
  bg_color   text,
  bg_img     text,
  logo       text,
  sort       int  not null default 0,
  created_at timestamptz not null default now()
);

-- مفاتيح API لشركات الشحن: الأدمن فقط، ومش بتوصل للموظفين نهائيًا
create table if not exists public.brand_secrets (
  brand_id text primary key references public.brands(id) on delete cascade,
  api_key  text not null default ''
);

-- ---------- الشحنات المسكانة ----------
create table if not exists public.scans (
  id         text primary key,
  brand_id   text not null references public.brands(id) on delete cascade,
  tn         text not null,
  tn_key     text generated always as (lower(tn)) stored,
  "at"       timestamptz not null default now(),
  kind       text not null default 'delivery' check (kind in ('delivery','exchange','return')),
  ver        text,
  gov        text,
  cod        numeric,
  fees       numeric,
  items      numeric,
  descr      text,
  doc        text,
  st         text,
  bt         text,
  cn         text,
  cp         text,
  chk        timestamptz,
  created_by uuid references auth.users(id) on delete set null default auth.uid(),
  unique (brand_id, tn_key, kind)          -- يمنع تسجيل نفس الشحنة مرتين
);
create index if not exists scans_brand_at on public.scans (brand_id, "at");

-- ---------- محاولات التكرار ----------
create table if not exists public.dups (
  id         bigint generated always as identity primary key,
  brand_id   text not null references public.brands(id) on delete cascade,
  tn         text not null,
  kind       text not null default 'delivery',
  "at"       timestamptz not null default now(),
  rz         boolean not null default false,
  created_by uuid references auth.users(id) on delete set null default auth.uid()
);
create index if not exists dups_brand on public.dups (brand_id);

-- =====================================================================
--  الصلاحيات (Row Level Security) — بتتنفذ على السيرفر مهما حصل في المتصفح
-- =====================================================================
alter table public.profiles       enable row level security;
alter table public.brands         enable row level security;
alter table public.brand_secrets  enable row level security;
alter table public.scans          enable row level security;
alter table public.dups           enable row level security;

revoke all on all tables in schema public from anon;

-- profiles: كل واحد يشوف صفّه، والأدمن يشوف الكل. الكتابة بس عن طريق الـ Edge Function.
drop policy if exists profiles_read on public.profiles;
create policy profiles_read on public.profiles for select to authenticated
  using (id = auth.uid() or public.app_role() = 'admin');

-- brands: قراءة لأي مستخدم مفعّل، تعديل للأدمن فقط
drop policy if exists brands_read  on public.brands;
drop policy if exists brands_admin on public.brands;
create policy brands_read  on public.brands for select to authenticated
  using (public.app_role() is not null);
create policy brands_admin on public.brands for all to authenticated
  using (public.app_role() = 'admin') with check (public.app_role() = 'admin');

-- brand_secrets: الأدمن فقط (الـ Edge Function بتقراه بصلاحية السيرفر)
drop policy if exists secrets_admin on public.brand_secrets;
create policy secrets_admin on public.brand_secrets for all to authenticated
  using (public.app_role() = 'admin') with check (public.app_role() = 'admin');

-- scans: قراءة للكل | إضافة عن طريق الـ Edge Function (أو الأدمن للاستيراد) | تعديل وحذف: مشرف وأدمن
drop policy if exists scans_read   on public.scans;
drop policy if exists scans_insert on public.scans;
drop policy if exists scans_update on public.scans;
drop policy if exists scans_delete on public.scans;
create policy scans_read   on public.scans for select to authenticated
  using (public.app_role() is not null);
create policy scans_insert on public.scans for insert to authenticated
  with check (public.app_role() = 'admin');
create policy scans_update on public.scans for update to authenticated
  using (public.app_role() in ('admin','supervisor')) with check (public.app_role() in ('admin','supervisor'));
create policy scans_delete on public.scans for delete to authenticated
  using (public.app_role() in ('admin','supervisor'));

-- dups
drop policy if exists dups_read   on public.dups;
drop policy if exists dups_insert on public.dups;
drop policy if exists dups_update on public.dups;
create policy dups_read   on public.dups for select to authenticated
  using (public.app_role() is not null);
create policy dups_insert on public.dups for insert to authenticated
  with check (public.app_role() = 'admin');
create policy dups_update on public.dups for update to authenticated
  using (public.app_role() = 'admin') with check (public.app_role() = 'admin');

-- ---------- التحديث اللحظي بين الأجهزة ----------
do $$ begin alter publication supabase_realtime add table public.scans;  exception when duplicate_object then null; end $$;
do $$ begin alter publication supabase_realtime add table public.dups;   exception when duplicate_object then null; end $$;
do $$ begin alter publication supabase_realtime add table public.brands; exception when duplicate_object then null; end $$;

-- =====================================================================
--  إنشاء أول أدمن (بعد ما تعمل المستخدم من لوحة Supabase)
--  1) Authentication → Users → Add user → Create new user
--       Email:    admin@scanapp.app      (اسم المستخدم + @scanapp.app)
--       Password: كلمة مرور قوية
--       علّم على Auto Confirm User
--  2) شغّل السطر ده (غيّر 'admin' لو عايز اسم مستخدم تاني، ولازم يطابق الإيميل):
--
--  insert into public.profiles (id, username, role)
--  select id, 'admin', 'admin' from auth.users where email = 'admin@scanapp.app';
-- =====================================================================
