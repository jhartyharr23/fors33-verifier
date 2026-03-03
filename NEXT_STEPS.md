# fors33-verifier: PyPI & GitHub — Next Steps

Package is built and ready. Complete these in order.

---

## 1. GitHub (do first)

FORS33 is not yet a Git repo. Choose one:

### Option A: Monorepo (recommended)

```powershell
cd c:\Users\jahar\Documents\FORS33
git init
git add .
git commit -m "Initial commit: FORS33 monorepo with fors33-verifier"
git branch -M main
git remote add origin https://github.com/YOUR_ORG/FORS33.git
git push -u origin main
```

Replace `YOUR_ORG` with your GitHub username or org. Create the repo on GitHub first (empty, no README).

### Option B: Standalone fors33-verifier repo

```powershell
mkdir c:\Users\jahar\Documents\fors33-verifier
cd c:\Users\jahar\Documents\fors33-verifier
copy c:\Users\jahar\Documents\FORS33\products\dpk\open_source\fors33-verifier\verify_dpk.py .
copy c:\Users\jahar\Documents\FORS33\products\dpk\open_source\fors33-verifier\README.md .
copy c:\Users\jahar\Documents\FORS33\products\dpk\open_source\fors33-verifier\LICENSE .
copy c:\Users\jahar\Documents\FORS33\products\dpk\open_source\fors33-verifier\pyproject.toml .
copy c:\Users\jahar\Documents\FORS33\products\dpk\open_source\fors33-verifier\PUBLISH.md .
git init
git add .
git commit -m "Initial fors33-verifier package"
git branch -M main
git remote add origin https://github.com/YOUR_ORG/fors33-verifier.git
git push -u origin main
```

---

## 2. PyPI first-time upload

Build is already done. From this directory:

```powershell
cd c:\Users\jahar\Documents\FORS33\products\dpk\open_source\fors33-verifier
python -m twine upload dist/*
```

When prompted:
- **Username:** `__token__`
- **Password:** your PyPI API token (pypi.org → Account → API tokens → Add token, scope: Project fors33-verifier)

If you need to rebuild first: `python -m build` then `python -m twine upload dist/*`

---

## 3. Trusted Publishing (optional, for future releases)

After the project exists on PyPI, enable Trusted Publishing so GitHub Actions can publish without tokens:

1. pypi.org → Account → Publishing → Add a new pending publisher
2. PyPI Project Name: `fors33-verifier`
3. Owner: your GitHub org/username
4. Repository: `FORS33` (or `fors33-verifier` if standalone)
5. Workflow name: `publish-fors33-verifier.yml`
6. Environment: (leave blank)

Future releases: create a GitHub release or run workflow manually → PyPI publish happens automatically.

---

## 4. Verify

```powershell
pip install fors33-verifier
fors33-verifier --help
```
