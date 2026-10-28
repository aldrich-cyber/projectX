# PROJECT X

**A Python-based Windows malware research and development project.**

> **Status:** In development  
> **Platform:** Microsoft Windows  
> **Language:** Python 3.12, as reported in development notes

## Overview

STELTH is a Windows-focused software project exploring background process behavior, Windows API interactions, lifecycle management, and monitoring-related functionality.

This repository documents the project's development history, technical specifications, debugging observations, testing status, and known limitations. It distinguishes specified behavior from reported implementation and verified results.

## Technical Scope

The development record covers:

- Python-based process execution and heartbeat behavior.
- Windows system interfaces accessed through `ctypes`.
- Application lifecycle and startup-related behavior.
- Monitoring-related component specifications.
- Error handling, regression testing, and Windows compatibility.

The presence of a specification or implementation record does not establish that a feature has been independently verified.

## Technology

- Python
- Microsoft Windows
- Python standard library
- `ctypes`
- Git and GitHub

## Documentation

- [Technical Development Report](docs/DEVELOPMENT_REPORT.md)
- [Testing Methodology](docs/TESTING.md)
- [M3 Specification](docs/M3_SPECIFICATION.md)
- [Security and Responsible Research](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Verification Standards

Project documentation uses four distinct statuses:

- **Planned:** described as a future requirement.
- **Implemented:** implementation is reported or present in the code.
- **Tested:** a test has been executed and its result recorded.
- **Verified:** supporting evidence confirms the specific behavior under the documented conditions.

## Responsible Research

This project concerns malware development. Research must remain within explicitly authorized, controlled environments. Do not use the project to collect private information, access systems without permission, or compromise other users.

Public documentation should not contain credentials, private datasets, or live collected information.

## Project Status

**In development.** Refer to the technical report for the evidence and limitations associated with individual components.
