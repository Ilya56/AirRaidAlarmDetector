# Air Raid Alarm Detector

A configurable, YAML-driven air raid alarm detection system that monitors Telegram channels for threat keywords and publishes real-time alerts via MQTT.

## Features

- **YAML-Driven Configuration**: Easily configure channels, keywords, locations, and detection rules without code changes
- **Universal Detection Engine**: Reusable Python module for message analysis and alert generation
- **Telegram Integration**: Monitor multiple Telegram channels simultaneously using Telethon
- **MQTT Publishing**: Publish structured alert events to MQTT for downstream processing
- **Smart Detection**: 
  - Keyword matching with variants and aliases
  - Location-based filtering
  - Configurable fusion modes (any/all/majority)
  - TTL (time-to-live) for detection memory
  - Cooldown periods to prevent alert spam
  - Rule-based priority assignment
- **Hot Reload**: Support for configuration reloading without service restart

## Project Structure

```
AirRaidAlarmDetector/
├── app/
│   ├── __init__.py
│   └── configurable_engine.py    # Universal detection engine module
├── data/
│   └── threat_config.yml          # Configuration file (example included)
├── service.py                      # Main service with Telethon + MQTT
├── example.py                      # Standalone usage example
├── requirements.txt                # Python dependencies
└── README.md                       # This file
```

## Quick Start

### 1. Prerequisites

- Python 3.8 or higher
- Telegram account and API credentials
- MQTT broker (e.g., Mosquitto)

### 2. Installation

Clone the repository and install dependencies:

```bash
git clone <repository-url>
cd AirRaidAlarmDetector
pip install -r requirements.txt
```

### 3. Telegram API Setup

1. Go to [https://my.telegram.org](https://my.telegram.org)
2. Log in with your phone number
3. Navigate to "API development tools"
4. Create a new application to get your `API_ID` and `API_HASH`

### 4. Configuration

Edit `data/threat_config.yml` to configure your detection parameters:

- **channels**: List of Telegram channels to monitor (get channel IDs using Telegram)
- **keywords**: Threat-related terms and their variants
- **locations**: Geographic areas to monitor (optional)
- **fusion_mode**: How to combine detections (`any`, `all`, or `majority`)
- **ttl_seconds**: How long to remember a detection (default: 300)
- **cooldown_seconds**: Minimum time between repeat alarms (default: 60)
- **rules**: Custom detection logic with priority levels

### 5. Environment Variables

Create a `.env` file or set environment variables:

```bash
# Required: Telegram credentials
export TELEGRAM_API_ID="your_api_id"
export TELEGRAM_API_HASH="your_api_hash"
export TELEGRAM_PHONE="+1234567890"

# Optional: MQTT configuration (defaults shown)
export MQTT_BROKER="localhost"
export MQTT_PORT="1883"
export MQTT_TOPIC="alerts/air_raid"
export MQTT_USERNAME=""  # Optional
export MQTT_PASSWORD=""  # Optional

# Optional: Configuration file path
export CONFIG_PATH="data/threat_config.yml"
```

### 6. Run the Service

```bash
python service.py
```

On first run, you'll need to authenticate with Telegram by entering the code sent to your phone.

## Configuration Guide

### Channels

Each channel must have a valid Telegram channel ID. To find a channel ID:

```python
# Quick script to get channel IDs
from telethon import TelegramClient
import asyncio

api_id = YOUR_API_ID
api_hash = 'YOUR_API_HASH'

async def get_channel_id(channel_username):
    client = TelegramClient('session', api_id, api_hash)
    await client.start()
    entity = await client.get_entity(channel_username)
    print(f"Channel ID: {entity.id}")
    await client.disconnect()

asyncio.run(get_channel_id('@channel_username'))
```

### Keywords

Keywords support main terms and variants for flexible matching:

```yaml
keywords:
  - term: "air raid"
    variants:
      - "air alert"
      - "aerial threat"
    enabled: true
```

All matching is case-insensitive and uses word boundaries for accuracy.

### Locations

Locations are optional. If defined, messages must mention a location to trigger:

```yaml
locations:
  - name: "Kyiv"
    aliases:
      - "Kiev"
      - "Kyiv Oblast"
    enabled: true
```

Leave the `locations` list empty to detect all messages with keywords.

### Fusion Modes

- **any**: Trigger if ANY monitored channel detects a threat (most sensitive)
- **all**: Trigger only if ALL channels detect the threat (most conservative)
- **majority**: Trigger if more than 50% of channels detect the threat

### Rules

Define custom detection logic with conditions and actions:

```yaml
rules:
  - name: "critical_alert"
    description: "High priority alerts"
    conditions:
      keyword_required: true
      location_required: false
      min_message_length: 10
    actions:
      priority: "critical"
```

## Detection Engine API

The `ConfigurableEngine` can be used programmatically:

```python
from app.configurable_engine import ConfigurableEngine

# Initialize engine
engine = ConfigurableEngine('data/threat_config.yml')

# Register event listener
def on_alert(event):
    print(f"Alert: {event.matched_keywords} in {event.channel_name}")

engine.add_event_listener(on_alert)

# Ingest messages
event = engine.ingest_message(
    channel_id='official_alerts',
    message='Air raid alert in Kyiv! Seek shelter immediately.'
)

if event:
    print(f"Detection: {event.priority.value} priority")

# Get statistics
stats = engine.get_statistics()
print(stats)
```

See `example.py` for a complete working example of using the engine programmatically.

## MQTT Alert Format

Alerts are published as JSON to the configured MQTT topic:

```json
{
  "timestamp": "2024-01-15T14:30:00.123456",
  "channel_id": "official_alerts",
  "channel_name": "Official Alert Channel",
  "message": "Air raid alert in Kyiv region...",
  "matched_keywords": ["air raid", "shelter"],
  "matched_locations": ["Kyiv"],
  "priority": "critical",
  "rule_name": "critical_alert"
}
```

## Subscribing to Alerts

Use any MQTT client to subscribe:

```bash
# Using mosquitto_sub
mosquitto_sub -h localhost -t "alerts/air_raid" -v

# Using Python
import paho.mqtt.client as mqtt

def on_message(client, userdata, msg):
    print(f"Alert: {msg.payload.decode()}")

client = mqtt.Client()
client.on_message = on_message
client.connect("localhost", 1883, 60)
client.subscribe("alerts/air_raid")
client.loop_forever()
```

## Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
pytest
```

### Hot Reload Configuration

The service supports configuration reloading:

```python
# In your code or via signal handler
engine.reload_config()
```

## Security Considerations

- **Never commit API credentials** to version control
- Use environment variables or secure secret management
- Restrict MQTT broker access with authentication
- Monitor for false positives and tune configuration
- Consider using TLS/SSL for MQTT connections in production

## Troubleshooting

### "Failed to connect to MQTT broker"

- Verify MQTT broker is running: `systemctl status mosquitto`
- Check broker address and port are correct
- Ensure firewall allows connections

### "Telegram authentication failed"

- Verify API_ID and API_HASH are correct
- Use the phone number in international format (+1234567890)
- Check that you have access to the phone for 2FA codes

### "No detections occurring"

- Verify channel IDs are correct (negative numbers for channels)
- Check that channels are marked as `enabled: true`
- Ensure keywords match the expected message content
- Review logs for configuration errors

## License

This project is provided as-is for educational and safety purposes.

## Contributing

Contributions are welcome! Please ensure:

- All code, comments, and documentation are in English
- Changes maintain backward compatibility with the configuration format
- New features include appropriate documentation
- Code follows existing style conventions

## Support

For issues or questions, please open an issue on the repository.
