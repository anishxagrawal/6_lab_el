-- Migration to add ai_suggested_fix column to findings table
alter table if exists public.findings 
    add column if not exists ai_suggested_fix text;

-- Add comment for documentation
comment on column public.findings.ai_suggested_fix is 'AI suggested remediation fix/snippet for the vulnerability/finding';
