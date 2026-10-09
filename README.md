# ATBU SUG Intelligent Security Monitoring System for E-Voting (ISMSF)

An unsupervised Machine Learning security monitoring platform for electronic voting telemetry, customized for the Abubakar Tafawa Balewa University (ATBU) Student Union Government (SUG) General Election.

---

## 🏛️ Election Details & Time Window
- **Institution**: Abubakar Tafawa Balewa University (ATBU), Bauchi
- **Scheduled Window**: Friday, 9th October 2026, 6:00 PM – 10:00 PM (18:00 – 22:00 WAT / 17:00 – 21:00 UTC)
- **Voter Authentication**: ATBU Registration Number (`YY/XXXXXU/L` or `YY/XXXXXD/L`, e.g. `21/48920U/1`) + Secret 4-digit PIN.
- **Constraints**: 1-student-1-vote (`has_voted` lock), real-time audit trail, pre-election test mode override.

---

## 🚀 Live Routes
- **Voter Portal**: `/voter` — Student registration, PIN creation, countdown timer, and presidential/executive ballot.
- **Admin SOC Dashboard**: `/dashboard` — Security Operations Center with real-time rolling 5-minute telemetry, ML risk scoring, activity trend sparkline, alert triage, and zero starting alerts.
- **Red-Team Console**: `/redteam` — Dedicated sub-page for injecting live anomalies (Brute-Force Attack, Velocity Voting Surge, Credential Stuffing, After-Hours Probing).

---

## ☁️ Deploying to Render in 3 Steps

### Step 1: Create a GitHub Repository
1. Go to [github.com/new](https://github.com/new).
2. Repository name: `ismsf-evoting` (can be public or private).
3. Do **not** initialize with README, .gitignore, or license (they already exist in this project).
4. Click **Create repository**.

### Step 2: Push Your Local Code
In your PowerShell or terminal inside this directory, run:
```powershell
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/ismsf-evoting.git
git push -u origin main
```

### Step 3: Connect to Render.com
1. Go to [dashboard.render.com](https://dashboard.render.com).
2. Click **New +** -> **Web Service** (or **Blueprint**).
3. Connect your GitHub account and select `ismsf-evoting`.
4. Render will automatically detect `render.yaml` or you can verify:
   - **Runtime**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn ingestion.main:app --host 0.0.0.0 --port $PORT`
5. Click **Deploy Web Service**.

Once deployed (usually 2–3 minutes), Render provides a permanent public HTTPS URL (e.g. `https://atbu-ismsf-evoting.onrender.com`). You can safely power off or hibernate your laptop!
