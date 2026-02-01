#!/usr/bin/env python3
"""
Example: Using the Detection Engine Programmatically

This example demonstrates how to use the ConfigurableEngine
without the full service integration.
"""

from app.configurable_engine import ConfigurableEngine, DetectionEvent

def on_detection(event: DetectionEvent):
    """Callback function for detection events."""
    print(f"\n🚨 ALERT DETECTED!")
    print(f"   Time: {event.timestamp}")
    print(f"   Channel: {event.channel_name}")
    print(f"   Priority: {event.priority.value}")
    print(f"   Keywords: {', '.join(event.matched_keywords)}")
    print(f"   Locations: {', '.join(event.matched_locations)}")
    print(f"   Message: {event.message[:100]}...")


def main():
    """Main example function."""
    # Initialize the detection engine
    print("Initializing detection engine...")
    engine = ConfigurableEngine('data/threat_config.yml')
    
    # Register event listener
    engine.add_event_listener(on_detection)
    
    # Display engine configuration
    stats = engine.get_statistics()
    print(f"\nEngine Configuration:")
    print(f"  Active Channels: {stats['active_channels']}")
    print(f"  Keywords: {stats['total_keywords']}")
    print(f"  Locations: {stats['total_locations']}")
    print(f"  Fusion Mode: {stats['fusion_mode']}")
    print(f"  Cooldown: {stats['cooldown_seconds']}s")
    
    # Simulate incoming messages
    print("\n" + "=" * 60)
    print("Simulating incoming messages...")
    print("=" * 60)
    
    messages = [
        ("official_alerts", "Air raid alert! Seek shelter in Kyiv region."),
        ("community_watch", "Missile launch detected heading towards Lviv."),
        ("official_alerts", "Just a weather update - sunny day."),
        ("community_watch", "UAV activity reported over Kharkiv."),
    ]
    
    for channel_id, message in messages:
        print(f"\n📨 Processing: \"{message[:50]}...\"")
        event = engine.ingest_message(channel_id, message)
        
        if not event:
            print("   ℹ️  No detection (message ignored)")
    
    # Display final statistics
    print("\n" + "=" * 60)
    final_stats = engine.get_statistics()
    print(f"\nFinal Statistics:")
    print(f"  Detection History: {final_stats['detection_history_size']} events")
    print(f"  Cooldown Entries: {final_stats['cooldown_entries']} active")


if __name__ == '__main__':
    main()
