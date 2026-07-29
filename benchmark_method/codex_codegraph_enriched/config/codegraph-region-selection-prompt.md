You are selecting source regions for a software issue-localization benchmark.

Inspect the current repository and the issue below using read-only inspection
only. Do not run tests, builds, installers, package managers, or target
application code. Do not modify files. Choose the ordered one to five regions
that are the strongest evidence for understanding and fixing the issue.

Use the CodeGraph `codegraph_explore` tool before using built-in repository
search or file-reading tools. Query CodeGraph using the issue below and use the
returned graph context to select the strongest source regions.

You may use built-in search or file reading only when CodeGraph's results are
insufficient. Do not return the final regions without first successfully
querying CodeGraph.

Return exactly one JSON object matching the supplied output schema. Preserve
repository-relative paths and use one-based inclusive line ranges. Order the
regions from strongest to weakest evidence. Give each region a short reason.

Issue:
{{problem_statement}}
