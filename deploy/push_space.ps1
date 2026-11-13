# Push one Heimdall service to its Hugging Face Space.
#
#   .\deploy\push_space.ps1 -Service backend    -Space RaGaS111/multi-llm-backend
#   .\deploy\push_space.ps1 -Service middleware -Space RaGaS111/heimdall-middleware
#
# The Space repo is cloned to a temp folder, made to match the service folder, and pushed.
# Secrets, local runtime files, tests and research write-ups are left out. Git asks for your
# Hugging Face username and a write token (huggingface.co/settings/tokens) the first time.
param(
    [Parameter(Mandatory = $true)][ValidateSet('middleware', 'backend')][string]$Service,
    [Parameter(Mandatory = $true)][string]$Space
)
$ErrorActionPreference = 'Stop'

$root = Split-Path $PSScriptRoot -Parent
$src = Join-Path $root $(if ($Service -eq 'middleware') { 'heimdall-middleware' } else { 'multi-llm-backend' })
$work = Join-Path ([IO.Path]::GetTempPath()) ('hf-space-' + ($Space -replace '/', '-'))

if (Test-Path $work) { Remove-Item $work -Recurse -Force }
git clone "https://huggingface.co/spaces/$Space" $work
if ($LASTEXITCODE -ne 0) { throw "Could not clone spaces/$Space. Check the name and your token." }

# /MIR makes the Space match the folder. Excluded names are neither copied nor deleted, so the
# Space's own .git stays. Folder names follow heimdall-middleware/.dockerignore.
$excludeDirs = '.git', '__pycache__', '.pytest_cache', 'node_modules', 'tests', 'figures', 'paper',
               'analysis', 'artifact*', 'phase*', 'raw', 'normalized', 'exports'
$excludeFiles = '.gitattributes', '.env', '.env.local', '*.pyc', '*.db', 'review_queue.json*', 'admin_audit.jsonl*',
                'honeypot_logs.jsonl', 'reviewer_labels.jsonl', 'extdev_misses.json'
robocopy $src $work /MIR /NFL /NDL /NJH /NJS /NP /XD $excludeDirs /XF $excludeFiles | Out-Null
if ($LASTEXITCODE -ge 8) { throw "Copy failed (robocopy exit $LASTEXITCODE)." }

# *.db is left out: Hugging Face refuses plain-git binary files, the immune database is rebuilt at
# start, and the experiment registry is git-ignored. The Space's Research page therefore lists no experiments.
# Last check before anything leaves the machine: no provider key may be in the tree.
$leak = Get-ChildItem $work -Recurse -File | Where-Object { $_.FullName -notmatch '\\\.git\\' } |
        Select-String -Pattern 'gsk_[A-Za-z0-9]{20,}', 'AIza[0-9A-Za-z_\-]{30,}' -List
if ($leak) { $leak | ForEach-Object { Write-Host "Key-like text in $($_.Path)" }; throw 'Refusing to push.' }

Push-Location $work
try {
    git add -A
    git diff --cached --quiet
    if ($LASTEXITCODE -eq 0) { Write-Host 'Space is already up to date.'; return }
    git commit -q -m "Deploy $Service"
    git push
    if ($LASTEXITCODE -ne 0) { throw 'Push failed.' }
    Write-Host "Pushed. The Space rebuilds now: https://huggingface.co/spaces/$Space"
}
finally { Pop-Location }
