from confluent_kafka import Producer

# Define Kafka producer configuration
producer_config = {
    'bootstrap.servers': 'your_broker_address',
    'client.id': 'python-producer'
}

# Create a Kafka producer instance
producer = Producer(producer_config)

# Produce a message to a Kafka topic
topic = 'your_topic'
message_key = 'key'
message_value = 'Hello, Kafka!'
producer.produce(topic, key=message_key, value=message_value)
producer.flush()  # Flushes any buffered messages
