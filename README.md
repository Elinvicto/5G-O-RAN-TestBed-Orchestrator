# Orchestrator

This repository contains a Python-based orchestration and attack-emulation framework, likely targeting 5G / ORAN-style network environments. It includes discovery, inventory mapping, service probing, attack execution, reporting, and a lightweight dashboard.

> **Note:** The `5gorc/` directory is a bundled Python virtual environment and is not part of the application logic.

---

## Project Structure

### Core Orchestration

- **`orchestrator.py`**  
  Main entry point for the orchestrator. Coordinates discovery, mapping, probing, and execution workflows.

- **`common.py`**  
  Shared utilities, helpers, and common logic used across multiple modules.

- **`mapping.py`**  
  Handles logical and/or physical component mapping, likely translating discovered resources into an internal model.

- **`component_map.json`**  
  Static mapping definition describing known components, roles, or relationships.

---

### Discovery & Inventory

- **`discover.py`**  
  Performs environment or network discovery to identify reachable components and services.

- **`inventory.json`**  
  Generated or static inventory describing discovered nodes, services, or assets.

- **`netns_info.py`**  
  Gathers Linux network namespace information, useful for containerized or virtualized environments.

---

### Probing & Analysis

- **`probe_services.py`**  
  Actively probes discovered services to determine availability, behavior, or exposed interfaces.

- **`report.py`**  
  Generates reports from discovery, probing, or attack results.

---

### Attack Emulation

- **`attacks.py`**  
  Defines available attack primitives or scenarios.

- **`attack_runner.py`**  
  Executes one or more attacks against selected targets.

- **`attack_emulator.py`**  
  Higher-level orchestration for simulating attacks, possibly coordinating multiple attack runners.

---

### Dashboard & UI

- **`dashboard_app.py`**  
  Web-based dashboard application for visualizing system state, results, or reports.

- **`templates/`**  
  HTML or UI templates used by the dashboard application.

---

### Supporting Assets

- **`oneshot.sh`**  
  Convenience shell script for running a full orchestration or test flow in one command.

- **`oran_orchestrator_work/`**  
  Working directory for runtime artifacts, logs, intermediate files, or generated outputs.

---

### Ignored / Generated

- **`__pycache__/`**  
  Python bytecode cache (generated).

- **`5gorc/`**  
  Python virtual environment containing dependencies (generated, not source code).

---

## Typical Workflow

1. Run discovery to identify components and services
2. Map discovered components into a structured model
3. Probe services for behavior and exposure
4. Execute attack emulation scenarios
5. Generate reports and view results via the dashboard

---

## Requirements

- Python 3.12 (recommended, based on virtual environment)
- Linux environment (network namespaces are used)
- Root or elevated privileges may be required for certain operations

---

## Notes

This project appears designed for research, testing, or security assessment purposes. Use responsibly and only in authorized environments.
