# Running the Project

Follow these steps to run the complete project using `uv`.

## Prerequisites

1.  **Ensure `uv` is in your PATH**:
    Running the following command ensures `uv` is accessible directly:
    ```bash
    export PATH="$HOME/.local/bin:$PATH"
    ```
    *(Note: You might need to restart your terminal or run `source ~/.bashrc` for this to persist).*

2.  **Environment Setup**:
    Make sure your `.env` file is configured with your API key:
    ```bash
    # .env
    OPENAI_API_KEY=your-openai-api-key-here
    # OR for MegaLLM:
    MEGALLM_API_KEY=your-megallm-api-key-here
    ```

## Installation

Install the project dependencies including the simulator extras:

```bash
uv sync --extra simulator
```

## Running Simulations

The project uses a central runner script to execute different multi-agent scenarios.

### 1. List Available Scenarios
To see all available simulations:

```bash
uv run python -m arbiter.simulator.runner --list
```

### 2. Run Specific Scenarios
Run individual CrewAI simulations using the `--crew` flag:

*   **Agent Onboarding**:
    ```bash
    uv run python -m arbiter.simulator.runner --crew onboarding
    ```

*   **Access Control**:
    ```bash
    uv run python -m arbiter.simulator.runner --crew access
    ```

*   **Security Incident**:
    ```bash
    uv run python -m arbiter.simulator.runner --crew incident
    ```

*   **Full End-to-End Simulation**:
    ```bash
    uv run python -m arbiter.simulator.runner --crew simulation
    ```
    

### 3. Run Deterministic Scenarios
You can also run the non-LLM, deterministic scenarios:

```bash
uv run python -m arbiter.simulator.runner --all
```
