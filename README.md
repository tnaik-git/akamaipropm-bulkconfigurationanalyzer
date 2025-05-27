# Akamai Property Manager Bulk Configuration Analyzer

## Overview

This script (`main.py`) is designed to analyze Akamai Property Manager configurations across multiple accounts. It detects configuration issues, missing behaviors, mismatches in certificates, improper slot settings, and generates per-account and merged summary reports in CSV or Excel format.

This script is a enhancement of https://git.source.akamai.com/projects/PSJAPAN/repos/api-rosawa-bulk_config_test/browse
and takes multiple configs as input

## Features

- Analyze all active properties for selected Akamai accounts.
- Detect missing critical/recommended behaviors per product.
- Highlight configuration mismatches and caveats (e.g., origin hostname using IP, CNAME TTL issues).
- Validate certificate deployments and SNI settings.
- Optionally include traffic data and live certificate fetches.
- Export individual reports per account and optionally merge them.

## File Structure

| File          | Description |
|---------------|-------------|
| `main.py`     | Main execution script for analyzing Akamai property configurations. |
| `mylib.py`    | Library of reusable functions to interact with Akamai APIs and parse configuration data. |
| `accounts.csv`| Input CSV specifying the list of accounts to process (user provided). |

## Prerequisites

- Python 3.13.1
- `.edgerc` file configured with Akamai API credentials ([setup guide](https://collaborate.akamai.com/confluence/display/~rosawa/Get+Started+with+Akamai+API))

### Required Python Dependencies

Install using `uv` (or `pip`):

```bash
uv pip install -r requirements.txt
```

**requirements.txt**
```
cryptography==44.0.2
dnspython==2.7.0
edgegrid-python==2.0.0
ipython==9.0.2
numpy==2.2.4
openpyxl==3.1.5
pandas==2.2.3
python-dateutil==2.9.0.post0
python-pptx==1.0.2
requests==2.32.3
tqdm==4.67.1
```

## Usage Instructions

1. **Prepare Account List**

   Create a CSV file (e.g., `accounts.csv`) with a column:
   ```
   account
   AccountOne
   AccountTwo
   ```

2. **Run the Script**

   Launch the analysis:

   ```bash
   uv run main.py
   ```

3. **Follow Prompts**

   - Provide the path to your `accounts.csv`.
   - Choose whether to analyze all properties or specific ones.
   - Enable/disable traffic stats or server certificate fetching.
   - After analysis, the output is saved to `/output/{account}.csv`.

4. **Merge Reports (Optional)**

   After all accounts are processed, you’ll be prompted to merge selected reports:
   - Provide another CSV file listing account names to include in the merge.
   - Output is saved as `merge_details/merge_details.csv`.

## Output

- Individual account CSVs: `output/{account}.csv`
- Optional merged file: `merge_details/merge_details.csv`
- JSON property rule snapshots per property: `property/{account}/{property_name}_v{version}.json`

## Notes

- Critical and recommended behaviors are product-specific and customizable in the script.
- Behaviors are validated against Akamai's available behavior list.
- The script highlights potential issues in configuration using conditional formatting (when Excel is used).
