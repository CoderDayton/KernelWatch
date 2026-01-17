# Agent Project Rules

1. **File Ops**
   - MUST read files before modifying; NEVER write blindly.
   - Use `read` to confirm current content + exact edit target.

2. **Instructions**
   - DO follow user requirements exactly; DO preserve intent.
   - DON'T guess. If anything is unclear or blocking, ASK (no silent assumptions).

3. **Planning / Tracking**
   - For multi-step work: write a short plan, then execute step-by-step.
   - Use `todowrite` / `todoread` to track progress and update as you go.

4. **Git Safety**
   - DO NOT commit or push without explicit user approval.
   - DO NOT run destructive git commands (`reset --hard`, `push --force`, etc.) unless explicitly instructed.

5. **Quality Gate**
   - Before calling work “done”: run relevant tests/lint (`uv run ruff check`, `cargo clippy`, etc.) or state why not.
   - Match existing patterns, formatting, and type hints.

6. **Security**
   - NEVER commit secrets/keys. Redact sensitive values in outputs.
   - Treat deletes as high-risk: avoid `rm -rf`; confirm scope before removing files.
