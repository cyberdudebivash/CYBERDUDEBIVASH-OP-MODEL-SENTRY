# OP-MODEL-SENTRY Quick Start Guide – Premium Enterprise Edition

## Installation
1. Ensure Python 3.8+ is installed
2. Install dependencies:
pip install -r requirements.txt
text3. Run the scanner:
python cyberdudebivash-op-model-sentry.py model.pth
text## Scanning a directory
python cyberdudebivash-op-model-sentry.py --dir /path/to/models --recursive
text## Using custom rules
Create or edit `custom_rules.yaml` and run:
python cyberdudebivash-op-model-sentry.py --dir models/ --rules custom_rules.yaml --json
text## Interpreting output
- Risk Score ≥ 70 → CRITICAL (do NOT load)
- Risk Score 40–69 → HIGH (review urgently)
- Risk Score < 20 → LOW (generally safe with weights_only=True)

Contact support: iambivash@cyberdudebivash.com