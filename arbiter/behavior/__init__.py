"""
Arbiter - Behavior Layer

This module provides a comprehensive behavior monitoring system for AI agents.
It acts as a daemon process that continuously monitors agent behavior and
automatically triggers credential revocation when misbehavior is detected.

Components:
- EventBus: Normalizes and distributes telemetry events
- ProfileStore: Maintains per-agent behavioral baselines
- OnHostDetectors: Fast, deterministic anomaly detectors
- CentralDetector: ML-based semantic drift detection
- Watchdog: Semantic classification using embeddings
- PolicyEngine: Decision engine for enforcement actions
- BehaviorDaemon: Background process orchestrating all components

Integration with Arbiter:
- Direct connection to RevocationManager for instant credential revocation
- Works alongside Identity and Integrity layers
- Provides real-time behavioral threat detection

Example:
    from arbiter.behavior import BehaviorDaemon
    from arbiter.identity import RevocationManager
    
    # Create revocation manager
    revocation = RevocationManager.initialize_system()
    
    # Start behavior monitoring daemon
    daemon = BehaviorDaemon(revocation_manager=revocation)
    daemon.start()
    
    # Submit agent events for monitoring
    daemon.submit_event(event)
    
    # Stop monitoring
    daemon.stop()
"""

__version__ = "0.1.0"

from arbiter.behavior.event_bus import EventBus, TOOL_RISK_MAP
from arbiter.behavior.profile_store import ProfileStore
from arbiter.behavior.detectors import OnHostDetectors
from arbiter.behavior.central_detector import CentralDetector
from arbiter.behavior.watchdog import Watchdog
from arbiter.behavior.policy import PolicyEngine, PolicyDecision
from arbiter.behavior.telemetry import make_event, SENSITIVE_KEYWORDS
from arbiter.behavior.daemon import BehaviorDaemon, BehaviorEvent

__all__ = [
    # Core Components
    "EventBus",
    "ProfileStore",
    "OnHostDetectors",
    "CentralDetector",
    "Watchdog",
    "PolicyEngine",
    "PolicyDecision",
    # Telemetry
    "make_event",
    "SENSITIVE_KEYWORDS",
    "TOOL_RISK_MAP",
    # Daemon
    "BehaviorDaemon",
    "BehaviorEvent",
]
