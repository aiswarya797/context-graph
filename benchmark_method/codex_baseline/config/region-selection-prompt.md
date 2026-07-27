You are selecting source regions for a software issue-localization benchmark.

Inspect the current repository and the issue below using read-only inspection
only. Do not run tests, builds, installers, package managers, or target
application code. Do not modify files. Choose the ordered one to five regions
that are the strongest evidence for understanding and fixing the issue.

Return exactly one JSON object matching the supplied output schema. Preserve
repository-relative paths and use one-based inclusive line ranges. Order the
regions from strongest to weakest evidence. Give each region a short reason.

Issue:
{{problem_statement}}

