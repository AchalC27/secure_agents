"""
Arbiter - Behavior Daemon

Background process that continuously monitors agent behavior.
Automatically triggers credential revocation when misbehavior is detected.

The daemon provides:
- Real-time event processing pipeline
- Integration with RevocationManager
- Async event queue processing
- Comprehensive audit logging
- Configurable thresholds and policies

This is the main entry point for behavior monitoring integration.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from queue import Queue, Empty
from typing import Any, Callable, Dict, List, Optional

from arbiter.behavior.event_bus import EventBus
from arbiter.behavior.profile_store import ProfileStore
from arbiter.behavior.detectors import OnHostDetectors
from arbiter.behavior.central_detector import CentralDetector
from arbiter.behavior.watchdog import Watchdog
from arbiter.behavior.policy import PolicyEngine
from arbiter.behavior.telemetry import make_event

# Setup logging
logger = logging.getLogger("arbiter.behavior")


@dataclass
class BehaviorEvent:
    """
    Wrapper for behavior monitoring events.
    
    Combines raw event data with processing metadata.
    """
    raw_event: Dict[str, Any]
    agent_did: Optional[str] = None
    credential_id: Optional[str] = None
    handler_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    processed: bool = False
    
    def as_telemetry(self) -> Dict[str, Any]:
        """Convert to telemetry event format."""
        event = self.raw_event.copy()
        event["agent_did"] = self.agent_did
        event["credential_id"] = self.credential_id
        event["handler_id"] = self.handler_id
        return event


@dataclass
class RevocationRecord:
    """
    Record of a credential revocation triggered by behavior monitoring.
    """
    agent_id: str
    agent_did: Optional[str]
    credential_id: Optional[str]
    handler_id: Optional[str]
    reason: str
    risk_score: float
    attack_type: str
    actions_taken: List[str]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize for logging/storage."""
        return {
            "agent_id": self.agent_id,
            "agent_did": self.agent_did,
            "credential_id": self.credential_id,
            "handler_id": self.handler_id,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "attack_type": self.attack_type,
            "actions_taken": self.actions_taken,
            "timestamp": self.timestamp.isoformat(),
        }


class BehaviorDaemon:
    """
    Background behavior monitoring daemon.
    
    Orchestrates the entire behavior monitoring pipeline:
    1. Receives events from agents
    2. Normalizes and enriches events
    3. Runs fast-path detectors
    4. Runs central semantic analysis
    5. Invokes watchdog for high-risk events
    6. Applies policy decisions
    7. Triggers credential revocation when necessary
    
    Designed to run as a daemon process alongside agent operations.
    
    Example:
        from arbiter.behavior import BehaviorDaemon
        from arbiter.identity import RevocationManager
        
        # Create with revocation integration
        revocation = RevocationManager.initialize_system()
        daemon = BehaviorDaemon(revocation_manager=revocation)
        
        # Start daemon (runs in background thread)
        daemon.start()
        
        # Submit events for monitoring
        daemon.submit_event({...})
        
        # Query status
        print(daemon.stats())
        
        # Stop when done
        daemon.stop()
    """

    def __init__(
        self,
        revocation_manager: Optional[Any] = None,
        revocation_callback: Optional[Callable[[str, str], None]] = None,
        watchdog_threshold: float = 0.8,
        process_interval: float = 0.1,
        enable_async: bool = True,
    ) -> None:
        """
        Initialize the behavior daemon.
        
        Args:
            revocation_manager: Optional RevocationManager for credential revocation
            revocation_callback: Optional callback(handler_id, reason) for revocation
            watchdog_threshold: Risk score threshold for invoking watchdog
            process_interval: Interval between processing cycles (seconds)
            enable_async: Whether to run processing in background thread
        """
        # Core components
        self.event_bus = EventBus()
        self.profile_store = ProfileStore()
        self.onhost_detectors = OnHostDetectors(self.profile_store)
        # Share embedder instance to avoid loading models multiple times
        embedder = self.event_bus.embedding_service
        self.central_detector = CentralDetector(self.profile_store, embedder=embedder)
        self.watchdog = Watchdog(embedder=embedder)
        self.policy_engine = PolicyEngine()
        
        # Revocation integration
        self.revocation_manager = revocation_manager
        self.revocation_callback = revocation_callback
        
        # Configuration
        self.watchdog_threshold = watchdog_threshold
        self.process_interval = process_interval
        self.enable_async = enable_async
        
        # Event queue for async processing
        self._event_queue: Queue[BehaviorEvent] = Queue()
        
        # State
        self._running = False
        self._thread: Optional[threading.Thread] = None
        
        # Metrics
        self._total_events = 0
        self._alerts_triggered = 0
        self._revocations_triggered = 0
        
        # Audit log
        self._audit_log: List[Dict[str, Any]] = []
        self._revocation_records: List[RevocationRecord] = []
        
        # Agent to credential mapping
        self._agent_credentials: Dict[str, Dict[str, str]] = {}

    def register_agent_credential(
        self,
        agent_id: str,
        agent_did: str,
        credential_id: str,
        handler_id: str,
    ) -> None:
        """
        Register an agent's credential for revocation tracking.
        
        Args:
            agent_id: Agent identifier
            agent_did: Agent's DID
            credential_id: Credential ID
            handler_id: Revocation handler ID
        """
        self._agent_credentials[agent_id] = {
            "agent_did": agent_did,
            "credential_id": credential_id,
            "handler_id": handler_id,
        }

    def submit_event(
        self,
        event: Dict[str, Any],
        agent_did: Optional[str] = None,
        credential_id: Optional[str] = None,
        handler_id: Optional[str] = None,
    ) -> None:
        """
        Submit an event for behavior monitoring.
        
        Events can be submitted directly or through the telemetry helper.
        
        Args:
            event: Raw telemetry event
            agent_did: Optional agent DID for revocation
            credential_id: Optional credential ID
            handler_id: Optional revocation handler ID
        """
        # Check if we have registered credentials for this agent
        agent_id = event.get("agent_id")
        if agent_id and agent_id in self._agent_credentials:
            creds = self._agent_credentials[agent_id]
            agent_did = agent_did or creds.get("agent_did")
            credential_id = credential_id or creds.get("credential_id")
            handler_id = handler_id or creds.get("handler_id")
        
        behavior_event = BehaviorEvent(
            raw_event=event,
            agent_did=agent_did,
            credential_id=credential_id,
            handler_id=handler_id,
        )
        
        if self.enable_async and self._running:
            self._event_queue.put(behavior_event)
        else:
            self._process_event(behavior_event)

    def submit_telemetry(
        self,
        agent_id: str,
        agent_role: str,
        session_id: str,
        user_id: str,
        event_type: str,
        tool_name: str,
        payload: str,
        token_count: int,
        **kwargs: Any,
    ) -> None:
        """
        Submit telemetry using the make_event helper.
        
        Convenience method that constructs the event.
        
        Args:
            agent_id: Agent identifier
            agent_role: Agent role
            session_id: Session ID
            user_id: User ID
            event_type: Event type
            tool_name: Tool being used
            payload: Event payload/content
            token_count: Token count
            **kwargs: Additional event fields
        """
        event = make_event(
            agent_id=agent_id,
            agent_role=agent_role,
            session_id=session_id,
            user_id=user_id,
            event_type=event_type,
            tool_name=tool_name,
            payload=payload,
            token_count=token_count,
            **kwargs,
        )
        self.submit_event(event)

    def _process_event(self, behavior_event: BehaviorEvent) -> Dict[str, Any]:
        """
        Process a single event through the monitoring pipeline.
        
        Args:
            behavior_event: Event to process
            
        Returns:
            Processing result with decision and metadata
        """
        event = behavior_event.raw_event
        agent_id = event.get("agent_id", "unknown")
        
        try:
            # Step 1: Normalize event
            normalized = self.event_bus.normalize(event)
            
            # Step 2: Update profile
            self.profile_store.update(agent_id, normalized)
            
            # Step 3: Run fast-path detectors
            alerts = self.onhost_detectors.detect(normalized)
            
            # Step 4: Run central detector
            risk_score = self.central_detector.score(normalized)
            
            # Step 5: Invoke watchdog for high-risk events
            watchdog_result = None
            if risk_score >= self.watchdog_threshold:
                watchdog_result = self.watchdog.classify(normalized)
            
            # Step 6: Apply policy
            decision = self.policy_engine.decide(
                normalized, alerts, risk_score, watchdog_result
            )
            
            # Update metrics
            self._total_events += 1
            if alerts:
                self._alerts_triggered += len(alerts)
                self.profile_store.increment_alerts(agent_id)
            
            # Step 7: Handle revocation if needed
            if decision.get("should_revoke"):
                self._handle_revocation(
                    behavior_event,
                    risk_score,
                    watchdog_result,
                    decision,
                )
            
            # Create result
            result = {
                "agent_id": agent_id,
                "risk_score": risk_score,
                "alerts": alerts,
                "watchdog": watchdog_result,
                "decision": decision,
                "timestamp": time.time(),
            }
            
            # Log high-risk events
            if risk_score >= 0.6 or decision.get("actions"):
                self._audit_log.append(result)
            
            behavior_event.processed = True
            return result
            
        except Exception as e:
            logger.error(f"Error processing event for {agent_id}: {e}")
            return {
                "agent_id": agent_id,
                "error": str(e),
                "timestamp": time.time(),
            }

    def _handle_revocation(
        self,
        behavior_event: BehaviorEvent,
        risk_score: float,
        watchdog_result: Optional[Dict[str, Any]],
        decision: Dict[str, Any],
    ) -> None:
        """
        Handle credential revocation for misbehaving agents.
        
        Args:
            behavior_event: The triggering event
            risk_score: Risk score at time of revocation
            watchdog_result: Watchdog classification
            decision: Policy decision
        """
        agent_id = behavior_event.raw_event.get("agent_id", "unknown")
        handler_id = behavior_event.handler_id
        attack_type = watchdog_result.get("label", "UNKNOWN") if watchdog_result else "UNKNOWN"
        
        # Build revocation reason
        reasons = decision.get("reasons", [])
        reason = "; ".join(reasons) if reasons else f"Behavior anomaly: {attack_type}"
        
        # Create revocation record
        record = RevocationRecord(
            agent_id=agent_id,
            agent_did=behavior_event.agent_did,
            credential_id=behavior_event.credential_id,
            handler_id=handler_id,
            reason=reason,
            risk_score=risk_score,
            attack_type=attack_type,
            actions_taken=decision.get("actions", []),
        )
        self._revocation_records.append(record)
        
        logger.warning(
            f"REVOCATION TRIGGERED for agent {agent_id}: "
            f"risk_score={risk_score:.2f}, attack_type={attack_type}"
        )
        
        # Perform actual revocation
        revoked = False
        
        if handler_id and self.revocation_manager:
            try:
                self.revocation_manager.revoke_credential(handler_id)
                revoked = True
                logger.info(f"Credential revoked via RevocationManager: {handler_id}")
            except Exception as e:
                logger.error(f"RevocationManager revocation failed: {e}")
        
        if handler_id and self.revocation_callback:
            try:
                self.revocation_callback(handler_id, reason)
                revoked = True
                logger.info(f"Credential revoked via callback: {handler_id}")
            except Exception as e:
                logger.error(f"Revocation callback failed: {e}")
        
        if revoked:
            self._revocations_triggered += 1
            self.profile_store.increment_revocation_warnings(agent_id)
        elif handler_id:
            logger.warning(
                f"Revocation recommended but no handler available for {agent_id}. "
                f"Handler ID: {handler_id}"
            )

    def _processing_loop(self) -> None:
        """Background processing loop."""
        logger.info("Behavior daemon processing loop started")
        
        while self._running:
            try:
                # Get next event with timeout
                try:
                    behavior_event = self._event_queue.get(
                        timeout=self.process_interval
                    )
                    self._process_event(behavior_event)
                except Empty:
                    pass
                    
            except Exception as e:
                logger.error(f"Error in processing loop: {e}")
                time.sleep(self.process_interval)
        
        logger.info("Behavior daemon processing loop stopped")

    def start(self) -> None:
        """Start the behavior daemon."""
        if self._running:
            logger.warning("Daemon already running")
            return
        
        self._running = True
        
        if self.enable_async:
            self._thread = threading.Thread(
                target=self._processing_loop,
                daemon=True,
                name="BehaviorDaemon",
            )
            self._thread.start()
            logger.info("Behavior daemon started in async mode")
        else:
            logger.info("Behavior daemon started in sync mode")

    def stop(self, timeout: float = 5.0) -> None:
        """
        Stop the behavior daemon.
        
        Args:
            timeout: Seconds to wait for processing thread
        """
        self._running = False
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning("Daemon thread did not stop cleanly")
        
        logger.info("Behavior daemon stopped")

    def is_running(self) -> bool:
        """Check if daemon is running."""
        return self._running

    def get_risk_score(self, agent_id: str) -> float:
        """Get current risk score for an agent."""
        return self.central_detector.get_risk_history(agent_id)

    def get_profile(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get behavioral profile for an agent."""
        return self.profile_store.get_profile(agent_id)

    def get_revocation_records(self) -> List[Dict[str, Any]]:
        """Get all revocation records."""
        return [r.to_dict() for r in self._revocation_records]

    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit log entries."""
        return self._audit_log[-limit:]

    def stats(self) -> Dict[str, Any]:
        """
        Get daemon statistics.
        
        Returns:
            Statistics dictionary
        """
        return {
            "running": self._running,
            "async_mode": self.enable_async,
            "total_events_processed": self._total_events,
            "alerts_triggered": self._alerts_triggered,
            "revocations_triggered": self._revocations_triggered,
            "pending_events": self._event_queue.qsize(),
            "registered_agents": len(self._agent_credentials),
            "profiled_agents": len(self.profile_store.profiles),
            "audit_log_size": len(self._audit_log),
            "event_bus_stats": self.event_bus.stats(),
        }

    def reset(self) -> None:
        """Reset all daemon state."""
        self._total_events = 0
        self._alerts_triggered = 0
        self._revocations_triggered = 0
        self._audit_log.clear()
        self._revocation_records.clear()
        self._agent_credentials.clear()
        
        self.event_bus.reset()
        self.profile_store.clear()
        self.central_detector.reset_all()
        
        # Clear queue
        while not self._event_queue.empty():
            try:
                self._event_queue.get_nowait()
            except Empty:
                break
        
        logger.info("Behavior daemon state reset")
