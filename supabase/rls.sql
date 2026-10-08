-- ══════════════════════════════════════════════════════════════════════
-- Reglas de acceso (RLS) — Sistema de tickets Salud Divina
-- Ejecutar en Supabase → SQL Editor, POR PASOS y en este orden.
--
-- Quién accede a qué:
--   Portal de empleados (rol anon, sin sesión):
--     · crear tickets (solo en estado Pendiente)
--     · registrar sus correos en email_log
--     · subir imágenes a ticket-imagenes/tickets/...
--     · consultar UN ticket por código y saber si un código existe,
--       solo a través de las funciones consultar_ticket / codigo_ticket_existe
--   Panel admin (usuarios en la tabla admins):
--     · leer y actualizar tickets, leer y registrar correos
--   Nadie más puede leer, modificar ni borrar datos.
-- ══════════════════════════════════════════════════════════════════════


-- ──────────────────────────────────────────────────────────────────────
-- PASO 0 (diagnóstico, no cambia nada): políticas que existen hoy
-- ──────────────────────────────────────────────────────────────────────
select schemaname, tablename, policyname, cmd, roles, qual, with_check
from pg_policies
where (schemaname = 'public'  and tablename in ('tickets', 'email_log'))
   or (schemaname = 'storage' and tablename = 'objects')
order by schemaname, tablename, policyname;


-- ──────────────────────────────────────────────────────────────────────
-- PASO 1: funciones y tabla de administradores
-- No cambia permisos todavía: se puede ejecutar en cualquier momento.
-- ──────────────────────────────────────────────────────────────────────
begin;

-- Administradores del panel. Sin políticas: solo se consulta vía es_admin().
create table if not exists public.admins (
  user_id uuid primary key references auth.users (id) on delete cascade
);
alter table public.admins enable row level security;

create or replace function public.es_admin()
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (select 1 from public.admins where user_id = auth.uid());
$$;

-- Consulta de un ticket por código para el portal (solo los campos que muestra)
create or replace function public.consultar_ticket(p_codigo text)
returns json
language sql stable security definer
set search_path = public
as $$
  select json_build_object(
    'codigo',      codigo,
    'nombre',      nombre,
    'area',        area,
    'tipo',        tipo,
    'created_at',  created_at,
    'prioridad',   prioridad,
    'descripcion', descripcion,
    'estado',      estado
  )
  from public.tickets
  where codigo = upper(trim(p_codigo))
  limit 1;
$$;

-- Para que el portal genere códigos que no existan
create or replace function public.codigo_ticket_existe(p_codigo text)
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (select 1 from public.tickets where codigo = p_codigo);
$$;

grant execute on function public.consultar_ticket(text)     to anon, authenticated;
grant execute on function public.codigo_ticket_existe(text) to anon, authenticated;
grant execute on function public.es_admin()                 to authenticated;

commit;

-- ⚠ REEMPLAZA los correos por los de las cuentas que entran al panel admin
insert into public.admins (user_id)
select id from auth.users
where email in ('CORREO_ADMIN_1@ejemplo.com', 'CORREO_ADMIN_2@ejemplo.com')
on conflict do nothing;

-- Verifica que aparezcan TODOS los administradores antes de seguir al paso 2
select u.email from public.admins a join auth.users u on u.id = a.user_id;


-- ──────────────────────────────────────────────────────────────────────
-- PASO 2: activar RLS y políticas
-- Ejecutar DESPUÉS de publicar la versión del portal que usa las funciones
-- (si se ejecuta antes, la consulta de tickets del portal deja de funcionar).
-- ──────────────────────────────────────────────────────────────────────
begin;

-- Quitar políticas anteriores de estas tablas (se reemplazan por las de abajo)
do $$
declare p record;
begin
  for p in
    select policyname, tablename from pg_policies
    where schemaname = 'public' and tablename in ('tickets', 'email_log')
  loop
    execute format('drop policy %I on public.%I', p.policyname, p.tablename);
  end loop;

  -- Políticas de storage que mencionan el bucket ticket-imagenes
  for p in
    select policyname from pg_policies
    where schemaname = 'storage' and tablename = 'objects'
      and (coalesce(qual, '') ilike '%ticket-imagenes%' or coalesce(with_check, '') ilike '%ticket-imagenes%')
  loop
    execute format('drop policy %I on storage.objects', p.policyname);
  end loop;
end $$;

-- ── tickets ──────────────────────────────────────────
alter table public.tickets enable row level security;

-- Portal: crear tickets nuevos, sin poder fijar estado ni observaciones
-- (incluye authenticated por si un admin abre el portal con su sesión iniciada)
create policy "portal_crea_tickets" on public.tickets
  for insert to anon, authenticated
  with check (
    estado = 'Pendiente'
    and coalesce(observaciones, '') = ''
    and prioridad in ('Alta', 'Normal')
  );

create policy "admin_lee_tickets" on public.tickets
  for select to authenticated
  using (public.es_admin());

create policy "admin_actualiza_tickets" on public.tickets
  for update to authenticated
  using (public.es_admin())
  with check (public.es_admin());

-- ── email_log ────────────────────────────────────────
alter table public.email_log enable row level security;

-- Portal: solo los tipos de correo que envía al crear un ticket
create policy "portal_registra_correos" on public.email_log
  for insert to anon, authenticated
  with check (tipo_correo in ('ticket_nuevo', 'ticket_nuevo_cc', 'constancia_solicitante'));

create policy "admin_lee_correos" on public.email_log
  for select to authenticated
  using (public.es_admin());

create policy "admin_registra_correos" on public.email_log
  for insert to authenticated
  with check (public.es_admin());

-- ── storage: ticket-imagenes ─────────────────────────
-- El bucket es público para que funcionen las URLs de las imágenes, pero
-- sin política de select nadie puede listar los archivos.
-- Límites iguales a los del portal: 5 MB, JPG/PNG/WEBP.
update storage.buckets
set public = true,
    file_size_limit = 5242880,
    allowed_mime_types = array['image/jpeg', 'image/png', 'image/webp']
where id = 'ticket-imagenes';

-- Portal: subir imágenes solo dentro de tickets/ (sin sobrescribir ni borrar)
create policy "portal_sube_imagenes" on storage.objects
  for insert to anon, authenticated
  with check (
    bucket_id = 'ticket-imagenes'
    and (storage.foldername(name))[1] = 'tickets'
  );

commit;


-- ──────────────────────────────────────────────────────────────────────
-- PASO 3 (opcional, si no lo hiciste antes): códigos de ticket únicos
-- ──────────────────────────────────────────────────────────────────────
-- 3a. Si devuelve filas, hay códigos repetidos: corrígelos antes de 3b
select codigo, count(*) from public.tickets group by codigo having count(*) > 1;

-- 3b.
alter table public.tickets add constraint tickets_codigo_unique unique (codigo);


-- ──────────────────────────────────────────────────────────────────────
-- PASO 4 (verificación): debe mostrar rowsecurity = true en ambas tablas
-- y las políticas nuevas
-- ──────────────────────────────────────────────────────────────────────
select tablename, rowsecurity from pg_tables
where schemaname = 'public' and tablename in ('tickets', 'email_log', 'admins');

select schemaname, tablename, policyname, cmd, roles
from pg_policies
where (schemaname = 'public'  and tablename in ('tickets', 'email_log'))
   or (schemaname = 'storage' and tablename = 'objects')
order by schemaname, tablename, policyname;
