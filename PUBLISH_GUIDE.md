# fors33-verifier: Git + PyPI Publish Guide

Step-by-step to push to GitHub and publish to PyPI. Terminal approach.

---

## Security scrub (completed)

Before publish, the following were verified per governance:

| Item | Status |
|------|--------|
| No API keys, tokens, credentials | Pass |
| No IPs, hostnames, internal IDs | Pass |
| No proprietary logic or formulas | Pass |
| Generic examples only (https://..., /path/to/...) | Pass |
| CTA to fors33.com/products (public URL) | Pass |

Package contents are public-ready.

---

## Package layout

The fors33-verifier package lives in `products/dpk/open_source/fors33-verifier/`. Required files:

- `verify_dpk.py` — main module
- `README.md` — install and usage
- `LICENSE` — MIT
- `pyproject.toml` — package metadata
- `PUBLISH.md` — maintainer notes (optional in standalone repo)

---

## Option A: Monorepo (FORS33 contains open_source)

Use this if FORS33 is already a Git repo and you push the whole project.

### Step 1: Git (if using version control)

```powershell
cd c:\Users\jahar\Documents\FORS33
git add products/dpk/open_source/fors33-verifier/
git status
git commit -m "Add fors33-verifier package for PyPI"
git remote add origin https://github.com/YOUR_ORG/FORS33.git
git push -u origin main
```

### Step 2: PyPI

```powershell
cd c:\Users\jahar\Documents\FORS33\products\dpk\open_source\fors33-verifier
python -m pip install build twine
python -m build
twine upload dist/*
```

When prompted:

- **Username:** `__token__`
- **Password:** your PyPI API token (create at pypi.org → Account → API tokens)

---

## Option B: Standalone fors33-verifier repo

Use this if you want a separate GitHub repo only for the verifier package.

### Step 1: Prepare standalone folder

```powershell
mkdir c:\Users\jahar\Documents\fors33-verifier
cd c:\Users\jahar\Documents\fors33-verifier
copy c:\Users\jahar\Documents\FORS33\products\dpk\open_source\fors33-verifier\verify_dpk.py .
copy c:\Users\jahar\Documents\FORS33\products\dpk\open_source\fors33-verifier\README.md .
copy c:\Users\jahar\Documents\FORS33\products\dpk\open_source\fors33-verifier\LICENSE .
copy c:\Users\jahar\Documents\FORS33\products\dpk\open_source\fors33-verifier\pyproject.toml .
copy c:\Users\jahar\Documents\FORS33\products\dpk\open_source\fors33-verifier\PUBLISH.md .
```

### Step 2: Git init and push

```powershell
cd c:\Users\jahar\Documents\fors33-verifier
git init
git add verify_dpk.py README.md LICENSE pyproject.toml PUBLISH.md
git commit -m "Initial fors33-verifier package"
git branch -M main
git remote add origin https://github.com/YOUR_ORG/fors33-verifier.git
git push -u origin main
```

### Step 3: PyPI

```powershell
cd c:\Users\jahar\Documents\fors33-verifier
python -m pip install build twine
python -m build
twine upload dist/*
```

Use `__token__` and your PyPI API token when prompted.

---

## PyPI first-time setup

1. Go to [pypi.org](https://pypi.org) and create an account (or log in).
2. **Account → API tokens → Add API token**
3. Name it (e.g. `fors33-verifier-upload`)
4. Scope: **Entire account** or **Project: fors33-verifier**
5. Copy the token (it's shown once).

---

## Order: Git first, then PyPI

1. Push to GitHub (so the code is versioned).
2. Run build and `twine upload` (publish to PyPI).

---

## Verify after publish

```powershell
pip install fors33-verifier
fors33-verifier --help
```

---

## Version bumps

1. Update `version` in `pyproject.toml`
2. Rebuild: `python -m build`
3. Upload: `twine upload dist/*` (PyPI accepts new versions only, not re-uploads of the same version)
