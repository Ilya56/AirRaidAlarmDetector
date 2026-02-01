"""
Configurable Air Raid Alarm Detection Engine

This module provides a universal, YAML-driven detection engine for processing
messages and generating alert events based on configurable rules, keywords,
locations, and fusion modes.
"""

import re
import time
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum


class FusionMode(Enum):
    """Defines how detections from multiple channels are combined."""
    ANY = "any"
    ALL = "all"
    MAJORITY = "majority"


class AlertPriority(Enum):
    """Alert priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Channel:
    """Represents a monitored channel."""
    name: str
    id: str
    telegram_id: int
    enabled: bool = True
    priority: int = 1


@dataclass
class Keyword:
    """Represents a detection keyword with variants."""
    term: str
    variants: List[str] = field(default_factory=list)
    enabled: bool = True

    def all_terms(self) -> List[str]:
        """Get all terms including the main term and variants."""
        return [self.term] + self.variants


@dataclass
class Location:
    """Represents a monitored location."""
    name: str
    aliases: List[str] = field(default_factory=list)
    enabled: bool = True

    def all_names(self) -> List[str]:
        """Get all location names including aliases."""
        return [self.name] + self.aliases


@dataclass
class Rule:
    """Represents a detection rule."""
    name: str
    description: str
    conditions: Dict[str, Any]
    actions: Dict[str, Any]


@dataclass
class DetectionEvent:
    """Represents a detected threat event."""
    timestamp: datetime
    channel_id: str
    channel_name: str
    message: str
    matched_keywords: List[str]
    matched_locations: List[str]
    priority: AlertPriority
    rule_name: Optional[str] = None


@dataclass
class DetectionState:
    """Tracks state of recent detections for TTL and cooldown."""
    timestamp: datetime
    channel_id: str
    keywords: List[str]
    locations: List[str]


class ConfigurableEngine:
    """
    Universal detection engine that processes messages based on YAML configuration.
    
    The engine supports:
    - Multiple channel monitoring
    - Keyword and location-based detection
    - Fusion modes (any, all, majority)
    - TTL for detection memory
    - Cooldown periods between alarms
    - Custom detection rules
    """

    def __init__(self, config_path: str):
        """
        Initialize the detection engine with a configuration file.
        
        Args:
            config_path: Path to the YAML configuration file
        """
        self.config_path = config_path
        self._initialize()

    def _initialize(self):
        """Load configuration and initialize engine state."""
        self.config = self._load_config()
        
        # Parse configuration
        self.fusion_mode = FusionMode(self.config.get('fusion_mode', 'any'))
        self.ttl_seconds = self.config.get('ttl_seconds', 300)
        self.cooldown_seconds = self.config.get('cooldown_seconds', 60)
        
        # Parse channels
        self.channels: Dict[str, Channel] = {}
        for ch in self.config.get('channels', []):
            channel = Channel(
                name=ch['name'],
                id=ch['id'],
                telegram_id=ch.get('telegram_id', 0),
                enabled=ch.get('enabled', True),
                priority=ch.get('priority', 1)
            )
            self.channels[channel.id] = channel
        
        # Parse keywords
        self.keywords: List[Keyword] = []
        for kw in self.config.get('keywords', []):
            keyword = Keyword(
                term=kw['term'],
                variants=kw.get('variants', []),
                enabled=kw.get('enabled', True)
            )
            if keyword.enabled:
                self.keywords.append(keyword)
        
        # Parse locations
        self.locations: List[Location] = []
        for loc in self.config.get('locations', []):
            location = Location(
                name=loc['name'],
                aliases=loc.get('aliases', []),
                enabled=loc.get('enabled', True)
            )
            if location.enabled:
                self.locations.append(location)
        
        # Parse rules
        self.rules: List[Rule] = []
        for rule_data in self.config.get('rules', []):
            rule = Rule(
                name=rule_data['name'],
                description=rule_data.get('description', ''),
                conditions=rule_data.get('conditions', {}),
                actions=rule_data.get('actions', {})
            )
            self.rules.append(rule)
        
        # Detection state tracking
        self.detection_history: List[DetectionState] = []
        self.last_alarm_time: Dict[str, datetime] = {}
        
        # Event listeners
        self.event_listeners: List[Callable[[DetectionEvent], None]] = []

    def _load_config(self) -> Dict:
        """Load and parse the YAML configuration file."""
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def reload_config(self):
        """Reload configuration from file (useful for hot-reloading)."""
        self._initialize()

    def add_event_listener(self, listener: Callable[[DetectionEvent], None]):
        """
        Register a callback to be notified of detection events.
        
        Args:
            listener: Function that takes a DetectionEvent and processes it
        """
        self.event_listeners.append(listener)

    def _cleanup_old_detections(self):
        """Remove detection states older than TTL."""
        cutoff_time = datetime.now() - timedelta(seconds=self.ttl_seconds)
        self.detection_history = [
            state for state in self.detection_history
            if state.timestamp > cutoff_time
        ]

    def _is_in_cooldown(self, channel_id: str, keywords: List[str], 
                        locations: List[str]) -> bool:
        """
        Check if an alarm for this combination is still in cooldown period.
        
        Args:
            channel_id: Channel identifier
            keywords: List of matched keywords
            locations: List of matched locations
            
        Returns:
            True if in cooldown, False otherwise
        """
        key = f"{channel_id}:{':'.join(sorted(keywords))}:{':'.join(sorted(locations))}"
        last_alarm = self.last_alarm_time.get(key)
        
        if last_alarm is None:
            return False
        
        time_since_last = (datetime.now() - last_alarm).total_seconds()
        return time_since_last < self.cooldown_seconds

    def _record_alarm(self, channel_id: str, keywords: List[str], 
                      locations: List[str]):
        """Record that an alarm was triggered for cooldown tracking."""
        key = f"{channel_id}:{':'.join(sorted(keywords))}:{':'.join(sorted(locations))}"
        self.last_alarm_time[key] = datetime.now()

    def _match_keywords(self, message: str) -> List[str]:
        """
        Find all keywords that match in the message.
        
        Args:
            message: The message text to search
            
        Returns:
            List of matched keyword terms
        """
        message_lower = message.lower()
        matched = []
        
        for keyword in self.keywords:
            for term in keyword.all_terms():
                # Use word boundary matching for better precision
                pattern = r'\b' + re.escape(term.lower()) + r'\b'
                if re.search(pattern, message_lower):
                    matched.append(keyword.term)
                    break  # Only count each keyword once
        
        return matched

    def _match_locations(self, message: str) -> List[str]:
        """
        Find all locations that match in the message.
        
        Args:
            message: The message text to search
            
        Returns:
            List of matched location names
        """
        if not self.locations:
            # If no locations configured, return empty list (matches all)
            return []
        
        message_lower = message.lower()
        matched = []
        
        for location in self.locations:
            for name in location.all_names():
                pattern = r'\b' + re.escape(name.lower()) + r'\b'
                if re.search(pattern, message_lower):
                    matched.append(location.name)
                    break  # Only count each location once
        
        return matched

    def _evaluate_rule(self, rule: Rule, keywords: List[str], 
                       locations: List[str], message: str) -> bool:
        """
        Evaluate if a rule's conditions are met.
        
        Args:
            rule: The rule to evaluate
            keywords: Matched keywords
            locations: Matched locations
            message: Original message
            
        Returns:
            True if all conditions are met
        """
        conditions = rule.conditions
        
        # Check keyword requirement
        if conditions.get('keyword_required', True) and not keywords:
            return False
        
        # Check location requirement
        if conditions.get('location_required', False):
            if self.locations and not locations:
                return False
        
        # Check minimum message length
        min_length = conditions.get('min_message_length', 0)
        if len(message) < min_length:
            return False
        
        return True

    def _determine_priority(self, keywords: List[str], locations: List[str], 
                           message: str) -> Tuple[AlertPriority, Optional[str]]:
        """
        Determine alert priority based on matched rules.
        
        Returns:
            Tuple of (priority, rule_name)
        """
        # Evaluate rules in order (first match wins)
        for rule in self.rules:
            if self._evaluate_rule(rule, keywords, locations, message):
                priority_str = rule.actions.get('priority', 'medium')
                try:
                    priority = AlertPriority(priority_str)
                except ValueError:
                    priority = AlertPriority.MEDIUM
                return priority, rule.name
        
        # Default priority if no rules match
        return AlertPriority.MEDIUM, None

    def ingest_message(self, channel_id: str, message: str, 
                      message_id: Optional[int] = None) -> Optional[DetectionEvent]:
        """
        Process an incoming message and detect threats.
        
        Args:
            channel_id: Identifier of the channel (must match config)
            message: The message text to analyze
            message_id: Optional message ID for tracking
            
        Returns:
            DetectionEvent if a threat is detected, None otherwise
        """
        # Clean up old detection history
        self._cleanup_old_detections()
        
        # Validate channel
        channel = self.channels.get(channel_id)
        if not channel or not channel.enabled:
            return None
        
        # Match keywords and locations
        matched_keywords = self._match_keywords(message)
        matched_locations = self._match_locations(message)
        
        # If no keywords matched, no detection
        if not matched_keywords:
            return None
        
        # If locations are configured and none matched, no detection
        # (unless location_required is False in rules)
        has_location_match = bool(matched_locations) or not self.locations
        
        # Check if we should suppress due to cooldown
        if self._is_in_cooldown(channel_id, matched_keywords, matched_locations):
            return None
        
        # Determine priority and matching rule
        priority, rule_name = self._determine_priority(
            matched_keywords, matched_locations, message
        )
        
        # Record detection state
        detection_state = DetectionState(
            timestamp=datetime.now(),
            channel_id=channel_id,
            keywords=matched_keywords,
            locations=matched_locations
        )
        self.detection_history.append(detection_state)
        
        # Record alarm for cooldown tracking
        self._record_alarm(channel_id, matched_keywords, matched_locations)
        
        # Create detection event
        event = DetectionEvent(
            timestamp=datetime.now(),
            channel_id=channel_id,
            channel_name=channel.name,
            message=message,
            matched_keywords=matched_keywords,
            matched_locations=matched_locations,
            priority=priority,
            rule_name=rule_name
        )
        
        # Notify listeners
        for listener in self.event_listeners:
            try:
                listener(event)
            except Exception as e:
                print(f"Error in event listener: {e}")
        
        return event

    def get_active_channels(self) -> List[Channel]:
        """Get list of enabled channels."""
        return [ch for ch in self.channels.values() if ch.enabled]

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get engine statistics.
        
        Returns:
            Dictionary with detection statistics
        """
        return {
            'total_channels': len(self.channels),
            'active_channels': len(self.get_active_channels()),
            'total_keywords': len(self.keywords),
            'total_locations': len(self.locations),
            'total_rules': len(self.rules),
            'detection_history_size': len(self.detection_history),
            'cooldown_entries': len(self.last_alarm_time),
            'fusion_mode': self.fusion_mode.value,
            'ttl_seconds': self.ttl_seconds,
            'cooldown_seconds': self.cooldown_seconds
        }
