"""
Arbiter Simulator Package

Multi-agent simulation demonstrating the Arbiter protocol.

Usage:
    # Run a specific scenario
    from arbiter.simulator import run_scenario
    result = run_scenario("onboarding")
    result.print_report()
    
    # Run all scenarios
    from arbiter.simulator import run_all_scenarios
    results = run_all_scenarios()
    
    # CLI
    python -m arbiter.simulator.runner --scenario onboarding
"""

from arbiter.simulator.tools import (
    ToolResult,
    SimulationContext,
    get_context,
    reset_context,
    create_agent_identity,
    issue_credential,
    create_presentation,
    verify_presentation,
    revoke_credential,
    request_access,
    get_agent_info,
    list_agents,
    get_event_log,
)

from arbiter.simulator.agents import (
    AgentRole,
    SimulatedAgent,
    IdentityAuthorityAgent,
    ResearcherAgent,
    GuardianAgent,
    CoordinatorAgent,
    DataProviderAgent,
    create_identity_authority,
    create_researcher,
    create_guardian,
    create_coordinator,
    create_data_provider,
)

from arbiter.simulator.scenarios import (
    Scenario,
    ScenarioResult,
    AgentOnboardingScenario,
    ResearchMissionScenario,
    CredentialRevocationScenario,
    CollaborativeTaskScenario,
    SCENARIOS,
    list_scenarios,
    run_scenario,
    run_all_scenarios,
)

try:
    from arbiter.simulator.crew import (
        CREWAI_AVAILABLE,
        check_api_key,
        get_arbiter_tools,
        create_security_admin_agent,
        create_access_controller_agent,
        create_researcher_agent,
        create_onboarding_crew,
        create_access_control_crew,
        create_security_incident_crew,
        run_onboarding_demo,
        run_access_control_demo,
        run_security_incident_demo,
    )
except ImportError:
    CREWAI_AVAILABLE = False

__all__ = [
    # Tools
    "ToolResult",
    "SimulationContext",
    "get_context",
    "reset_context",
    "create_agent_identity",
    "issue_credential",
    "create_presentation",
    "verify_presentation",
    "revoke_credential",
    "request_access",
    "get_agent_info",
    "list_agents",
    "get_event_log",
    # Agents
    "AgentRole",
    "SimulatedAgent",
    "IdentityAuthorityAgent",
    "ResearcherAgent",
    "GuardianAgent",
    "CoordinatorAgent",
    "DataProviderAgent",
    "create_identity_authority",
    "create_researcher",
    "create_guardian",
    "create_coordinator",
    "create_data_provider",
    # Scenarios
    "Scenario",
    "ScenarioResult",
    "AgentOnboardingScenario",
    "ResearchMissionScenario",
    "CredentialRevocationScenario",
    "CollaborativeTaskScenario",
    "SCENARIOS",
    "list_scenarios",
    "run_scenario",
    "run_all_scenarios",
    # CrewAI
    "CREWAI_AVAILABLE",
]
