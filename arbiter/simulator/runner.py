"""
Arbiter Simulator - CLI Runner

Run simulations from the command line.

Usage:
    python -m arbiter.simulator.runner --scenario onboarding
    python -m arbiter.simulator.runner --all
    python -m arbiter.simulator.runner --list
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from arbiter.simulator.scenarios import (
    list_scenarios,
    run_scenario,
    run_all_scenarios,
    ScenarioResult,
)

try:
    from arbiter.simulator.crew import (
        CREWAI_AVAILABLE,
        check_api_key,
        run_onboarding_demo,
        run_access_control_demo,
        run_security_incident_demo,
        run_full_simulation_demo,
    )
except ImportError:
    CREWAI_AVAILABLE = False
    check_api_key = lambda: False


def print_banner() -> None:
    """Print the Arbiter banner."""
    print("""
    +===================================================+
    |                                                   |
    |      A R B I T E R                                |
    |                                                   |
    |      Multi-Agent Identity & Integrity Simulator   |
    +===================================================+
    """)


def run_single_scenario(name: str, output_json: bool = False) -> bool:
    """Run a single scenario.
    
    Args:
        name: Scenario name
        output_json: If True, output JSON instead of report
        
    Returns:
        True if scenario succeeded
    """
    try:
        result = run_scenario(name)
        
        if output_json:
            print(result.to_json())
        else:
            result.print_report()
        
        return result.success
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return False


def run_all(output_json: bool = False) -> bool:
    """Run all scenarios.
    
    Args:
        output_json: If True, output JSON instead of report
        
    Returns:
        True if all scenarios succeeded
    """
    results = run_all_scenarios()
    
    if output_json:
        output = {name: r.to_dict() for name, r in results.items()}
        print(json.dumps(output, indent=2))
    else:
        print("\n" + "="*60)
        print("RUNNING ALL SCENARIOS")
        print("="*60)
        
        for result in results.values():
            result.print_report()
        
        # Summary
        passed = sum(1 for r in results.values() if r.success)
        total = len(results)
        
        print("\n" + "="*60)
        print(f"SUMMARY: {passed}/{total} scenarios passed")
        print("="*60 + "\n")
    
    return all(r.success for r in results.values())


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Arbiter Multi-Agent Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Deterministic scenarios (no API key needed)
  python -m arbiter.simulator.runner --list
  python -m arbiter.simulator.runner --scenario onboarding
  python -m arbiter.simulator.runner --all
  
  # LLM-powered crews (requires OPENAI_API_KEY in .env)
  python -m arbiter.simulator.runner --crew onboarding
  python -m arbiter.simulator.runner --crew access
  python -m arbiter.simulator.runner --crew incident
  
  # Full end-to-end simulation
  python -m arbiter.simulator.runner --crew simulation
        """,
    )
    
    parser.add_argument(
        "--scenario", "-s",
        type=str,
        help="Name of deterministic scenario to run",
    )
    
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Run all deterministic scenarios",
    )
    
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List available scenarios",
    )
    
    parser.add_argument(
        "--crew", "-c",
        type=str,
        choices=["onboarding", "access", "incident", "simulation"],
        help="Run LLM-powered CrewAI demo (requires API key)",
    )
    
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output results as JSON",
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress banner",
    )
    
    args = parser.parse_args()
    
    if not args.quiet and not args.json:
        print_banner()
    
    if args.list:
        scenarios = list_scenarios()
        if args.json:
            data = {
                "scenarios": scenarios,
                "crews": ["onboarding", "access", "incident", "simulation"],
                "crewai_available": CREWAI_AVAILABLE,
                "api_key_set": check_api_key() if CREWAI_AVAILABLE else False,
            }
            print(json.dumps(data))
        else:
            print("Available deterministic scenarios:")
            for name in scenarios:
                print(f"  - {name}")
            print("\nAvailable LLM-powered crews:")
            print("  - onboarding : Onboard a new agent with credentials")
            print("  - access     : Test access control decisions")
            print("  - incident   : Handle security incident (revocation)")
            print("  - simulation : Run complete end-to-end lifecycle demo")
            if CREWAI_AVAILABLE:
                if check_api_key():
                    print("\n[OK] CrewAI installed, API key configured")
                else:
                    print("\n[!] CrewAI installed but API Key (OPENAI_API_KEY or MEGALLM_API_KEY) not set in .env")
            else:
                print("\n[!] CrewAI not installed. Run: uv pip install 'arbiter[simulator]'")
        return 0
    
    if args.all:
        success = run_all(args.json)
        return 0 if success else 1
    
    if args.scenario:
        success = run_single_scenario(args.scenario, args.json)
        return 0 if success else 1
    
    if args.crew:
        if not CREWAI_AVAILABLE:
            print("Error: CrewAI not installed. Run: uv pip install 'arbiter[simulator]'", 
                  file=sys.stderr)
            return 1
        
        if not check_api_key():
            print("Error: API Key (OPENAI_API_KEY or MEGALLM_API_KEY) not set in .env file", file=sys.stderr)
            return 1
        
        print(f"\n🤖 Running LLM-powered '{args.crew}' crew...\n")
        print("="*60)
        
        try:
            if args.crew == "onboarding":
                result = run_onboarding_demo()
            elif args.crew == "access":
                result = run_access_control_demo()
            elif args.crew == "incident":
                result = run_security_incident_demo()
            elif args.crew == "simulation":
                result = run_full_simulation_demo()
            else:
                print(f"Unknown crew: {args.crew}", file=sys.stderr)
                return 1
            
            print("\n" + "="*60)
            print("CREW RESULT:")
            print("="*60)
            print(result)
            return 0
        except Exception as e:
            print(f"Error running crew: {e}", file=sys.stderr)
            return 1
    
    # No action specified
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
