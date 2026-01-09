# 5G-O-RAN TestBed Orchestrator

## Description
The Orchestrator directory contains the control logic used to coordinate and execute adversarial campaigns across the UE, RAN, and Core components of a 5G O-RAN testbed. It provides a unified mechanism to launch, synchronize, and terminate attack phases while continuously collecting system and network telemetry required for resilience evaluation.

The orchestrator is designed to support repeatable, parameterized experiments, enabling controlled stress conditions and consistent comparison across baseline and defended configurations.

## Features
- **Campaign-driven execution**: 
  Defines multi-phase attack scenarios (e.g., UE attach flooding, RRC signaling storms, user-plane traffic bursts) using configuration files for reproducibility.

- **Cross-plane coordination**:
  Orchestrates adversarial activity spanning the UE, RAN, and Core planes, allowing evaluation of cascading and cross-layer effects.

- **Baseline and control toggles**:
  Supports running identical campaigns with security controls enabled or disabled (e.g., TLS, resource quotas, rate limits) to quantify resilience deltas.

- **Telemetry collection and timestamping**:
  Collects CPU, memory, signaling success rates, and throughput metrics with synchronized timestamps for recovery time and degradation analysis.

- **Experiment repeatability**:
  Enables repeated runs with configurable randomization (e.g., start offsets, intensity levels) to support statistical analysis.

- **Modular and extensible design**:
  Allows new attack modules, metrics collectors, or control hooks (e.g., RIC/A1/O1 triggers) to be added with minimal changes.

## Technical Architecture
The architecture of the **5G-O-RAN TestBed Orchestrator** can be broken down into the following core components:

### Technical Architecture Diagram (Orchestrated Adversarial Evaluation Framework)
```mermaid
graph TD
    A[Central Orchestrator Node]
    A --> B[Attack Control Layer]
    A --> C[Configuration & Campaign Engine]
    A --> D[Telemetry & Metrics Collection Layer]
    A --> E[Control Toggle Interface]
    A --> F[Data Persistence Layer]
    A --> G[RIC / Management Touchpoint (Optional)]
    G --> H[Threshold-based Alarms]
    G --> I[Closed-loop Signaling]
    A --> J[Analysis & Reporting Interface]

    B --> B1[UE-plane Attacks: Attach Flooding, RRC Storms, Traffic Bursts]
    B --> B2[RAN-plane Attacks: Scheduler Stress, Signaling Overload]
    B --> B3[Core-plane Attacks: AMF/UPF Overload, Session Anomalies]

    C --> C1[Attack Type, Intensity, Duration, Concurrency]
    C --> C2[Randomization Parameters]
    C --> C3[Baseline vs Defense Modes]

    D --> D1[CPU/Memory Usage]
    D --> D2[Signaling Success/Failure Rates]
    D --> D3[Throughput, Latency Metrics]

    E --> E1[Transport Security: TLS]
    E --> E2[Container-level CPU/Memory Quotas]
    E --> E3[Rate-limiting, Admission Control]

    F --> F1[Experiment Logs: CSV/Parquet]
    F --> F2[Metadata: Campaign ID, Run Number, Config Hash]

    J --> J1[Compute Metrics: E_sec, T_res, Recovery Lag]
    J --> J2[Generate Figures, Tables]
```

## Usage Steps
The following steps outline how to use the 5G-O-RAN TestBed Orchestrator in your environment:

1. **Clone the Repository**
   ```bash
   git clone https://github.com/Elinvicto/5G-O-RAN-TestBed-Orchestrator.git
   cd 5G-O-RAN-TestBed-Orchestrator
   ```

2. **Install Dependencies**
   - Use the provided `requirements.txt` file for Python dependencies:
     ```bash
     pip install -r requirements.txt
     ```

3. **Run the Main Orchestrator**
   - Start the orchestration script:
     ```bash
     python orchestrator.py
     ```

4. **Access the Web Interface**
   - Navigate to the provided URL (e.g., `http://127.0.0.1:5000`) to interact with the visual interface.

5. **Test a Component**
   - Upload configurations and test scripts via the web interface or command-line.

## How to Deploy in Your Own Environment

### Pre-requisites
Ensure the following software and tools are installed on your system:
- Python 3.8+ 
- Docker (optional, for containerized deployment)
- GCC/G++ compiler for C, C++, Cython components

### Deployment Steps
1. **Prepare Configuration**
   - Edit the `config.yaml` file to align with your testbed setup.

2. **Set up Dependencies**
   - Install all required Python libraries and compile Cython modules:
     ```bash
     python setup.py build_ext --inplace
     ```

3. **Run the Dockers (Optional)**
   - If using the Dockerized version, build and run the container:
     ```bash
     docker build -t 5g-oran-orchestrator .
     docker run -d -p 5000:5000 5g-oran-orchestrator
     ```

4. **Launch the Orchestrator**
   - Initiate the orchestrator by running the main entry-point script:
     ```bash
     python orchestrator.py
     ```

5. **Customize Components**
   - Modify the components under `modules/` directory for adding proprietary features.

## Conclusion
The **5G-O-RAN TestBed Orchestrator** provides a robust and scalable solution for testing and managing Open RAN environments. By combining Python's simplicity with efficient low-level modules, the project facilitates next-generation 5G research and development. Its modularity and extensibility ensure it can cater to a wide variety of deployment scenarios, making it a go-to choice for researchers and developers in the 5G domain.

We welcome contributions! Feel free to fork, test, and submit pull requests to make O-RAN orchestration even better.
