# Obsidian Integration Prompts

This file contains example prompts for connecting Obsidian notes to the SAST AI Detection project.
Use these when you want to summarize, link, or develop project artifacts from Obsidian.

## Good Prompt Examples

### 1. Project summary mapping
```text
I am working on a Laravel + Rubix ML SAST triage application in the repo at g:/personal_project/sast-ai-detection-app.
Create a concise Obsidian note that maps the current project scope, key files, and existing CI workflow.
Include the scan upload page, ML training commands, and Inertia/React frontend notes.
```

Why it is good:
- Clearly states repo path and project stack
- Asks for a concise note structure
- Mentions exact project features and workflows

### 2. Issue or task capture
```text
I need to track a new task for this SAST app: add better test coverage for upload and scan ingestion.
Create an Obsidian markdown note with a task list, links to `tests/Feature/ScanUploadTest.php`, `app/Http/Controllers/ScanController.php`, and `resources/js/pages/Scans/Upload.jsx`.
```

Why it is good:
- Provides the exact task and target files
- Formats output as actionable Obsidian note content
- Makes it easy to preserve context in a vault

### 3. Good/bad prompt documentation
```text
Write an Obsidian note titled "SAST AI Detection prompt guidance".
Include examples of good prompts and bad prompts for interacting with this Laravel + Rubix ML project.
Mention why each prompt is good or bad.
```

Why it is good:
- Requests a structured note with explicit title
- Focuses on prompt quality and context for future sessions
- Aligns with the project and makes the output reusable

## Bad Prompt Examples

### 1. Too vague without context
```text
Help me with this project.
```

Why it is bad:
- No repository, technology, or objective is specified
- Impossible to know whether this is backend, frontend, or docs work
- Likely causes hallucination or misaligned advice

### 2. Assumes features that may not exist
```text
Add a new `scope` folder and move all features there, then generate CI tests for it.
```

Why it is bad:
- Assumes project structure changes without verifying current repo state
- Asks for code changes without confirming whether the files exist
- Can cause unnecessary or incorrect refactors

### 3. Asks for generic help without project details
```text
Write a prompt for my note app.
```

Why it is bad:
- No reference to Obsidian, repo, or what the note should contain
- Too general to produce useful project-specific notes
- Does not help the AI avoid hallucination

## How to use these prompts with Obsidian

- Copy the good prompt example into a new Obsidian note when you need to capture project-specific context.
- Use the bad prompt examples as a checklist to avoid weak or ambiguous requests.
- Keep the note titled clearly, such as `SAST AI Detection - Obsidian Prompt Guidance`.

## Recommended vault link strategy

If your Obsidian vault is on the same machine, include the actual repo path or a stable alias in the note, for example:
- `Repo: g:/personal_project/sast-ai-detection-app`
- `Source files: resources/js/pages/Scans/Upload.jsx`
- `CI workflow: .github/workflows/tests.yml`

This makes your note easy to search and prevents later confusion.
