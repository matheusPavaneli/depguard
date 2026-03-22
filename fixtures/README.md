# Evaluation fixtures

- **`eval-dataset.csv`**: labeled rows (`benign` vs `should_alert`) for `npm run eval-metrics`. Columns: `name`, `version`, `expected`, `note`.
- Vulnerable rows reference advisories indexed on [OSV](https://osv.dev/) (e.g. `minimist@1.2.5`, `lodash@4.17.19`).
