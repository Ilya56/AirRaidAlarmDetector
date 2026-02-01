#!/usr/bin/env python3
"""
Air Raid Alarm Detection Service

Minimal working service that integrates Telethon for Telegram monitoring
and MQTT for publishing alert notifications.

Environment Variables Required:
    TELEGRAM_API_ID: Telegram API ID (get from my.telegram.org)
    TELEGRAM_API_HASH: Telegram API hash (get from my.telegram.org)
    TELEGRAM_PHONE: Phone number for Telegram authentication
    MQTT_BROKER: MQTT broker address (default: localhost)
    MQTT_PORT: MQTT broker port (default: 1883)
    MQTT_TOPIC: MQTT topic for publishing alerts (default: alerts/air_raid)
    MQTT_USERNAME: MQTT username (optional)
    MQTT_PASSWORD: MQTT password (optional)
    CONFIG_PATH: Path to threat_config.yml (default: data/threat_config.yml)
"""

import os
import sys
import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path

try:
    from telethon import TelegramClient, events
    from telethon.tl.types import Channel
except ImportError:
    print("ERROR: telethon not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("ERROR: paho-mqtt not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

from app.configurable_engine import ConfigurableEngine, DetectionEvent


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AirRaidAlarmService:
    """
    Main service orchestrator that connects Telegram monitoring,
    the detection engine, and MQTT publishing.
    """

    def __init__(self):
        """Initialize the service with configuration from environment."""
        # Load environment variables
        self.telegram_api_id = os.getenv('TELEGRAM_API_ID')
        self.telegram_api_hash = os.getenv('TELEGRAM_API_HASH')
        self.telegram_phone = os.getenv('TELEGRAM_PHONE')
        
        self.mqtt_broker = os.getenv('MQTT_BROKER', 'localhost')
        self.mqtt_port = int(os.getenv('MQTT_PORT', '1883'))
        self.mqtt_topic = os.getenv('MQTT_TOPIC', 'alerts/air_raid')
        self.mqtt_username = os.getenv('MQTT_USERNAME')
        self.mqtt_password = os.getenv('MQTT_PASSWORD')
        
        config_path = os.getenv('CONFIG_PATH', 'data/threat_config.yml')
        self.config_path = Path(config_path)
        
        # Validate required configuration
        if not self.telegram_api_id or not self.telegram_api_hash:
            raise ValueError(
                "TELEGRAM_API_ID and TELEGRAM_API_HASH must be set. "
                "Get them from https://my.telegram.org"
            )
        
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {self.config_path}"
            )
        
        # Initialize components
        self.telegram_client = None
        self.mqtt_client = None
        self.detection_engine = None
        self.running = False

    def _setup_mqtt(self):
        """Set up MQTT client and connect to broker."""
        logger.info(f"Connecting to MQTT broker at {self.mqtt_broker}:{self.mqtt_port}")
        
        self.mqtt_client = mqtt.Client()
        
        # Set authentication if provided
        if self.mqtt_username and self.mqtt_password:
            self.mqtt_client.username_pw_set(self.mqtt_username, self.mqtt_password)
        
        # Set up callbacks
        self.mqtt_client.on_connect = self._on_mqtt_connect
        self.mqtt_client.on_disconnect = self._on_mqtt_disconnect
        
        try:
            self.mqtt_client.connect(self.mqtt_broker, self.mqtt_port, 60)
            self.mqtt_client.loop_start()
            logger.info("MQTT client connected and loop started")
        except Exception as e:
            logger.error(f"Failed to connect to MQTT broker: {e}")
            raise

    def _on_mqtt_connect(self, client, userdata, flags, rc):
        """Callback when MQTT client connects."""
        if rc == 0:
            logger.info("Successfully connected to MQTT broker")
        else:
            logger.error(f"Failed to connect to MQTT broker, return code: {rc}")

    def _on_mqtt_disconnect(self, client, userdata, rc):
        """Callback when MQTT client disconnects."""
        if rc != 0:
            logger.warning(f"Unexpected MQTT disconnection, return code: {rc}")

    def _setup_detection_engine(self):
        """Initialize the detection engine with configuration."""
        logger.info(f"Loading detection engine from {self.config_path}")
        
        self.detection_engine = ConfigurableEngine(str(self.config_path))
        
        # Register event listener for detections
        self.detection_engine.add_event_listener(self._on_detection_event)
        
        # Log statistics
        stats = self.detection_engine.get_statistics()
        logger.info(f"Detection engine loaded: {stats}")

    def _on_detection_event(self, event: DetectionEvent):
        """
        Handle detection events by publishing to MQTT.
        
        Args:
            event: The detection event to publish
        """
        logger.warning(
            f"ALERT DETECTED! Channel: {event.channel_name}, "
            f"Keywords: {event.matched_keywords}, "
            f"Locations: {event.matched_locations}, "
            f"Priority: {event.priority.value}"
        )
        
        # Prepare MQTT payload
        payload = {
            'timestamp': event.timestamp.isoformat(),
            'channel_id': event.channel_id,
            'channel_name': event.channel_name,
            'message': event.message,
            'matched_keywords': event.matched_keywords,
            'matched_locations': event.matched_locations,
            'priority': event.priority.value,
            'rule_name': event.rule_name
        }
        
        # Publish to MQTT
        try:
            result = self.mqtt_client.publish(
                self.mqtt_topic,
                json.dumps(payload),
                qos=1,
                retain=False
            )
            
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                logger.info(f"Alert published to MQTT topic: {self.mqtt_topic}")
            else:
                logger.error(f"Failed to publish to MQTT: {result.rc}")
        except Exception as e:
            logger.error(f"Error publishing to MQTT: {e}")

    async def _setup_telegram(self):
        """Set up Telegram client and event handlers."""
        logger.info("Initializing Telegram client")
        
        # Create session file in a safe location
        session_name = 'air_raid_alarm_session'
        
        self.telegram_client = TelegramClient(
            session_name,
            int(self.telegram_api_id),
            self.telegram_api_hash
        )
        
        # Connect to Telegram
        await self.telegram_client.start(phone=self.telegram_phone)
        logger.info("Telegram client connected")
        
        # Get active channel IDs from detection engine
        active_channels = self.detection_engine.get_active_channels()
        channel_ids = [ch.telegram_id for ch in active_channels]
        
        logger.info(f"Monitoring {len(channel_ids)} Telegram channels")
        
        # Register message handler for monitored channels
        @self.telegram_client.on(events.NewMessage(chats=channel_ids))
        async def message_handler(event):
            """Handle new messages from monitored channels."""
            try:
                # Find matching channel configuration
                chat_id = event.chat_id
                channel_config = None
                
                for ch in active_channels:
                    if ch.telegram_id == chat_id:
                        channel_config = ch
                        break
                
                if not channel_config:
                    return
                
                # Extract message text
                message_text = event.message.message
                if not message_text:
                    return
                
                logger.debug(
                    f"Received message from {channel_config.name}: "
                    f"{message_text[:50]}..."
                )
                
                # Ingest message into detection engine
                detection = self.detection_engine.ingest_message(
                    channel_id=channel_config.id,
                    message=message_text,
                    message_id=event.message.id
                )
                
                # Detection event is automatically sent to listeners
                # including MQTT publisher
                
            except Exception as e:
                logger.error(f"Error processing message: {e}", exc_info=True)

    async def run(self):
        """Start and run the service."""
        logger.info("Starting Air Raid Alarm Detection Service")
        
        try:
            # Set up MQTT
            self._setup_mqtt()
            
            # Set up detection engine
            self._setup_detection_engine()
            
            # Set up Telegram
            await self._setup_telegram()
            
            self.running = True
            logger.info("Service is running. Press Ctrl+C to stop.")
            
            # Keep running until interrupted
            await self.telegram_client.run_until_disconnected()
            
        except KeyboardInterrupt:
            logger.info("Received interrupt signal, shutting down...")
        except Exception as e:
            logger.error(f"Service error: {e}", exc_info=True)
            raise
        finally:
            await self.shutdown()

    async def shutdown(self):
        """Clean shutdown of all components."""
        logger.info("Shutting down service...")
        
        self.running = False
        
        # Disconnect Telegram
        if self.telegram_client:
            try:
                await self.telegram_client.disconnect()
                logger.info("Telegram client disconnected")
            except Exception as e:
                logger.error(f"Error disconnecting Telegram: {e}")
        
        # Disconnect MQTT
        if self.mqtt_client:
            try:
                self.mqtt_client.loop_stop()
                self.mqtt_client.disconnect()
                logger.info("MQTT client disconnected")
            except Exception as e:
                logger.error(f"Error disconnecting MQTT: {e}")
        
        logger.info("Service shutdown complete")


def main():
    """Main entry point for the service."""
    # Create and run service
    service = AirRaidAlarmService()
    
    try:
        asyncio.run(service.run())
    except KeyboardInterrupt:
        logger.info("Service stopped by user")
    except Exception as e:
        logger.error(f"Service failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
