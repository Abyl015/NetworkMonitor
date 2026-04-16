# AGENTS.md

## Project identity (do not change)

This repository is a diploma project in cybersecurity.

**Official project direction:**
Intelligent information security monitoring system based on network traffic analysis.

The project is specifically about:
- network traffic monitoring for security purposes
- anomaly detection
- IOC detection
- infected host identification
- incident correlation
- security assessment

### Hard rule
Do **not** change the diploma topic, project identity, or project positioning.

Do **not** reframe the project into:
- a generic packet sniffer
- a pure networking monitor
- a generic analytics dashboard
- a different diploma topic

The project must remain a **cybersecurity-oriented monitoring and threat detection system**.

---

## Core architectural intent

The current intended architecture is:

`Traffic Capture / PCAP -> Feature Extraction -> Rules + ML + IOC -> Verdict -> Incident -> Security Assessment -> GUI / Reports`

This architecture should be preserved unless the user explicitly requests a redesign.

---

## Model / ML restrictions

Current ML direction is based on anomaly detection.

### Hard rule
Do **not** replace or remove **Isolation Forest** on your own.

If you believe Isolation Forest should be changed:
- do not implement the change automatically
- first clearly explain why
- wait for explicit user approval

You may improve:
- feature extraction
- training flow
- model persistence
- calibration
- explainability
- integration with IOC/rules

But do **not** replace the main anomaly model without a direct request.

---

## Required post-change validation

### Hard rule
After any change affecting:
- `engine.py`
- `scoring.py`
- `database.py`
- `rules`
- `ML`
- `IOC`
- `incident logic`
- `PCAP logic`

you must do both:

1. Run syntax validation:
- `python -m py_compile ...`

2. Run a **real PCAP test** if possible

The PCAP validation is mandatory for core logic changes.
Do not skip it unless it is impossible in the environment.

The goal is to verify that changes did not break:
- PCAP analysis
- IOC matching
- verdict generation
- incident generation
- security assessment

---

## UI / UX task policy

UI/UX work is allowed and encouraged.

The project has design mockups prepared externally using Google Stitch.

### The agent may:
- implement GUI structure
- connect screens to current logic
- improve layout
- improve usability
- wire data into UI blocks
- create or update GUI code for the approved screens

### The agent must not:
- arbitrarily redesign the whole visual identity
- ignore provided mockups
- replace the diploma security meaning with generic business dashboard design

---

## Required UI screens

The UI work should focus on these 3 main screens / views:

1. **Main screen**
   - primary monitoring dashboard
   - system status
   - security assessment
   - logs / alerts / incidents
   - top suspicious hosts / threat summary

2. **PCAP screen**
   - file selection
   - offline analysis mode
   - processing state
   - results summary
   - detected incidents / IOC / suspicious hosts

3. **Settings / Profile screen**
   - profile selection
   - thresholds
   - ML parameters
   - sampling
   - reset / retrain related controls
   - detection configuration

### Important rule
If mockup images or exported design files exist in the repository or are provided by the user, follow them as the primary UI reference.

Do not invent a completely different UI structure when these 3 screens are already defined.

---

## Design intent for UI

The UI must look like a **cybersecurity desktop dashboard**, not a generic admin panel.

Priority of information:
1. current threat state
2. incidents
3. IOC hits
4. suspicious / malicious hosts
5. security assessment
6. logs
7. settings

Use the UI to support:
- demo during diploma defense
- clear explanation of the system
- visibility of security-relevant events

---

## Project priorities

When making changes, prioritize:
1. correctness of threat detection
2. stability of PCAP mode
3. explainability
4. incident logic
5. security assessment quality
6. GUI integration
7. styling and polish

---

## Code style

### Python
- keep code readable
- prefer helper methods over giant functions
- use descriptive names
- prefer `Path(...)` over hardcoded OS paths
- avoid fragile hacks
- avoid silent failures unless justified
- keep code explainable for diploma defense

### Logging
Logs should remain human-readable and useful for:
- debugging
- screenshots
- diploma defense explanation

Avoid excessive noise when possible.

---

## Mockup files

If present, use these files as the primary UI reference:
- `assets/mockups/main.png`
- `assets/mockups/pcap.png`
- `assets/mockups/settings_profile.png`

Do not ignore these mockups when implementing or updating GUI.

## Detection logic rules

Preserve and respect the distinction between:
- `anomaly`
- `suspicious`
- `malicious`

Preserve and respect:
- IOC IP logic
- IOC DNS logic
- infected host candidate
- incident correlation
- security assessment

Do not weaken IOC findings into generic anomalies.
Do not turn all infected-host traffic into malicious automatically.
Do not remove explainability.

---

## GUI engineering rules

When editing GUI:
- preserve existing QSS/theme compatibility
- prefer structural improvements over random visual changes
- make sure monitoring and PCAP actions still work
- keep security-relevant widgets visible
- do not hide or bury incidents / IOC / assessment

If adding new GUI blocks, keep them aligned with the three required screens:
- Main
- PCAP
- Settings/Profile

---

## Files that require extra care

### Core logic
Be extra careful with:
- `engine.py`
- `scoring.py`
- `database.py`

### GUI
Be extra careful with:
- `main.py`
- `worker.py`
- `plot_widget.py`
- `settings_dialog.py`

Do not break signal/worker flow for:
- live monitoring
- PCAP analysis
- settings/profile application

---

## Mandatory summary after changes

When finishing a task, clearly summarize:
- what changed
- why it changed
- which files changed
- whether syntax validation passed
- whether a PCAP run was performed
- what the PCAP result showed

If PCAP was not run, explicitly say that it was not run and why.

---

## Things that are not allowed without approval

- changing the diploma topic
- changing the conceptual identity of the project
- replacing Isolation Forest
- major architecture redesign
- adding heavy dependencies casually
- replacing security-focused UI with generic analytics UI
- skipping PCAP validation for core logic changes
