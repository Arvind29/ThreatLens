
# AGENTS.md — ThreatLens

## Project Purpose
ThreatLens is a cybersecurity threat intelligence application.

## Development Rules
1. Understand existing code before modifying it.
2. Do not rewrite working functionality unnecessarily.
3. Keep changes limited to the requested scope.
4. Follow existing coding conventions.
5. Explain significant architectural changes.

## Security Rules
1. Never hardcode API keys or credentials.
2. Never expose secrets in logs.
3. Validate all external inputs.
4. Use secure API communication.
5. Do not introduce vulnerable dependencies.

## Testing
1. Run relevant tests after modifications.
2. Report test failures honestly.
3. Do not claim success without test evidence.

## GitHub Workflow
1. Work on a separate branch.
2. Prepare a plan before implementation.
3. Open a Pull Request for changes.
4. Explain changes, risks and rollback steps.
5. Never directly modify the main branch.

## Agent Restrictions
- Do not delete existing functionality without approval.
- Do not modify GitHub workflows or deployment settings without approval.
- Do not access or expose production secrets.
