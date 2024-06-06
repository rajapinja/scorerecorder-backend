from confluent_kafka import Consumer, KafkaError

# Define Kafka consumer configuration
consumer_config = {
    'bootstrap.servers': 'your_broker_address',
    'group.id': 'python-consumer',
    'auto.offset.reset': 'earliest'  # Start consuming from the beginning of the topic
}

# Create a Kafka consumer instance
consumer = Consumer(consumer_config)

# Subscribe to a Kafka topic
topic = 'your_topic'
consumer.subscribe([topic])

# Start consuming messages
while True:
    msg = consumer.poll(1.0)  # Poll for messages (adjust the timeout as needed)

    if msg is None:
        continue

    if msg.error():
        if msg.error().code() == KafkaError._PARTITION_EOF:
            print(f"Reached end of partition, offset {msg.offset()}")
        else:
            print(f"Error while consuming: {msg.error()}")
    else:
        print(f"Received message: {msg.value().decode('utf-8')}")

consumer.close()
