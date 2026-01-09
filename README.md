# 5G-O-RAN TestBed Orchestrator

## Description
The **5G-O-RAN TestBed Orchestrator** is a comprehensive orchestration framework designed for the testing, deployment, and management of 5G Open RAN (O-RAN) setups. It serves as a bridge between software-defined tools, testbed environments, and network components, ensuring seamless integration and automation in 5G O-RAN development. This project is optimized for high performance and modularity, making it accessible to researchers, developers, and 5G testers alike.

## Features
- **5G Open RAN Compatibility**: Ensures compatibility with O-RAN specifications and standards.
- **Automation**: Simplified deployment and management of O-RAN components.
- **Multi-Language Support**:
  - Primarily implemented in Python (98.4%), leveraging its simplicity and versatility.
  - Incorporates low-level components in C, Cython, C++, and Fortran for enhanced computational efficiency.
  - Includes JavaScript integration for front-end interaction.
- **Extensibility**: Modular design allowing easy extension of functionalities and integration with external tools.
- **Performance Optimizations**: Equipped with efficient computational features for real-time scenarios.

## Technical Architecture
The architecture of the **5G-O-RAN TestBed Orchestrator** can be broken down into the following core components:

1. **Orchestrator Core**: Written in Python, driving main functionalities like communication, automation, and coordination.
2. **Low-level Performance Modules**: Developed in C, Cython, C++, and Fortran to facilitate high-performance operations and mathematical processing.
3. **Web-based Monitoring Interface**: JavaScript components allowing real-time monitoring and dashboarding for orchestration workflows.
4. **Modularized Interfaces**: API-driven interaction points for external tools and libraries.
5. **Containerized Environment**: Supports Docker for deployment in diverse environments with reproducibility and scalability.

### Technical Architecture Diagram
```mermaid
graph TD
    A[Orchestrator Core<br>(Python)] --> B[API Endpoints<br>(Modular Interfaces)]
    A --> C[Low-level Performance Modules<br>(C, Cython, C++, Fortran)]
    A --> D[Configuration Engine<br>(YAML/JSON)]
    B --> E[External Tools/Plugins]
    B --> F[Web-based Monitoring Interface<br>(JavaScript)]
    A --> G[Containerized Environment<br>(Docker)]

    subgraph Orchestrator Core
        A
        D
    end

    subgraph Interfaces
        B
        E
        F
    end
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
