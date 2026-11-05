---
title: 'Azura WebGuard Inspector: a local-first workspace for inspecting untrusted web application source code with deterministic engines, human-reviewed AI, and reusable security knowledge'
tags:
  - C#
  - .NET
  - software security
  - static analysis
  - malware detection
  - web shells
  - large language models
  - knowledge management
authors:
  - name: Agnan Zakariya
    orcid: 0000-0000-0000-0000  # TODO: replace with your ORCID iD
    affiliation: 1
affiliations:
  - name: TODO — institution or "Independent Researcher", City, Indonesia
    index: 1
date: 5 November 2026
bibliography: paper.bib
---

# Summary

Web applications are frequently assembled from third-party code: frameworks, plugins, themes and complete products
bought from marketplaces or downloaded from unofficial mirrors. Such code can contain vulnerabilities, leaked
credentials, vulnerable dependencies and deliberately planted backdoors such as web shells
[@Starov2016; @Ohm2020]. Azura WebGuard Inspector is an open-source Windows desktop application that lets a person
inspect such a source tree locally and reproducibly. It inventories and hashes every file, runs deterministic detection
engines — Semgrep [@Semgrep], Gitleaks [@Gitleaks], OSV-Scanner [@OSVScanner], YARA-X [@YARAX] and ClamAV [@ClamAV] —
enriches results with optional threat intelligence (OSV.dev, CISA Known Exploited Vulnerabilities [@CISAKEV],
MalwareBazaar [@MalwareBazaar]), and presents normalised findings with redacted evidence. A local language model
can explain a finding, and either a local model or Claude Code can propose a fix; every proposal is shown as a diff and
written only after a person applies it, with a backup and undo. All scans, findings, analyses, fixes and human verdicts
are recorded as linked Markdown notes in an Obsidian vault [@Obsidian], which the tool then consults *before* running
engines or models again. A Model Context Protocol (MCP) [@MCP] server exposes the same read-only, folder-scoped tools to
external AI agents.

# Statement of need

Security researchers, incident responders and developers who study or audit third-party web code face three recurring
problems. First, no single tool covers the relevant classes of issues: taint-style vulnerabilities, secrets, vulnerable
dependencies and obfuscated malware each require different engines with different output formats. Second, large
language models are increasingly used to triage and repair vulnerabilities [@Pearce2023], but sending proprietary or
malicious code to a remote service is often unacceptable, and model output must not be treated as ground truth. Third,
analysts repeatedly re-examine the same files — the same plugin appears in many projects and the same project is scanned
many times — yet their verdicts are usually lost in reports or tickets.

Azura addresses these needs with three design principles. (1) *Local-first and least privilege*: source code is only
read, never uploaded; network lookups are opt-in and send only package coordinates or file hashes; secrets are redacted
before anything reaches a model, a note or a report. (2) *Engines decide, AI proposes, humans validate*: findings come
from deterministic engines; AI analyses are stored as unverified hypotheses; code is changed only after a person reviews
a diff. (3) *Knowledge is reused*: verdicts are keyed by a stable finding fingerprint and by file content (SHA-256), so
a file identical to one already confirmed as malicious is flagged without running an engine, a false-positive verdict
carries over to identical files in other projects, previously applied fixes are offered again for the same rule, and
unchanged files are not re-analysed. In our measurements on a 51-file project, a repeated scan without changes took
3.9 s instead of 26.7 s with all local engines enabled.

The target audience is researchers who need a reproducible, auditable pipeline for studying untrusted web code (for
example, measuring backdoors in redistributed "nulled" PHP plugins and themes), and practitioners who must inspect such
code without exposing it.

# State of the field

Individual engines such as Semgrep, Gitleaks, OSV-Scanner, YARA-X and ClamAV are mature and widely used, and
aggregation platforms such as DefectDojo [@DefectDojo] collect their reports on a server for vulnerability management.
Research on web shells [@Starov2016] and software supply-chain attacks [@Ohm2020] has characterised the threat, and
datasets such as CVEfixes [@Bhandari2021] support work on automated repair. Azura does not replace these tools; it
combines them in a desktop workspace that runs entirely on the analyst's machine, adds a human-in-the-loop repair
workflow with redaction and reversible application, and closes the loop with a personal knowledge base that is
consulted before engines and models. We are not aware of an open-source tool that combines these elements for local
inspection of untrusted web application code.

# Software design

The solution is written in C# for .NET 10 and has no NuGet dependencies. A `Core` library defines contracts (findings,
engines, fixers, knowledge memory); `Detection`, `Intelligence`, `AI`, `Persistence` and `Scanner` implement them and
depend only on `Core`; a WPF desktop client and a stdio MCP server are the two composition roots. Engines are invoked
by absolute path with time-outs and output caps, and engines that support it run incrementally: a configuration stamp
(engine version, rule files, signature database) decides whether cached per-file results are still valid, and only
changed files are scanned. Fix proposals are exact text edits that must match the file uniquely and are applied
all-or-nothing. The vulnerable version of a fixed file is preserved as a commented-out copy outside the scan scope. A
custom test runner executes 100 automated tests covering parsing, redaction, patching, incremental scanning, knowledge
reuse and view-model behaviour.

# AI usage disclosure

<!-- TODO: check the current JOSS policy on generative AI and adapt this section. Keep it accurate. -->
Substantial parts of the source code, tests and documentation were written with the assistance of an AI coding
assistant (Anthropic Claude via Claude Code) under the direction of the author, who specified the requirements,
reviewed the changes, ran the tests and validated the behaviour on real projects.

# Acknowledgements

<!-- TODO: funding, institutions or people to thank; remove the section if there are none. -->

# References
