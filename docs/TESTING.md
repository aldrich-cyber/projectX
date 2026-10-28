# Testing Methodology

## 1. Purpose

This document describes how testing evidence and verification status are recorded for the STELTH project.

## 2. Test Status Definitions

| Status | Meaning |
|---|---|
| Planned | Requirement documented; implementation not confirmed |
| Implemented | Implementation reported or present in the source |
| Tested | Test executed and its result recorded |
| Verified | Evidence supports a specific claim under documented conditions |
| Blocked | Testing could not be completed |
| Not verified | Available evidence is insufficient |

## 3. Test Records

Each test record should include:

- Test identifier
- Test purpose
- Git commit hash
- Operating system and version
- Python version
- Test method
- Result
- Evidence location
- Known limitations

## 4. Reporting Standards

1. Never invent test results or test counts.
2. Distinguish test requirements from executed tests.
3. Record failures and unresolved issues.
4. Document the environment used for testing.
5. Do not claim universal compatibility based on one environment.
6. Remove credentials and personal information from published reports.

## 5. Current Evidence Limitations

The available M3 specification defines requirements and acceptance criteria but does not provide execution results proving that every criterion passed.

Overall test coverage and cross-version compatibility remain unconfirmed unless supported by additional evidence.

## 6. Reproducibility

Document the environment and procedures needed to reproduce authorized software-quality tests. Public reports should avoid exposing sensitive information or operational instructions that could enable misuse.

## 7. Conclusion

Reliable documentation distinguishes implementation, test execution, and verified results. The project status should be updated only when supporting evidence is available.
