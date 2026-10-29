import pytest

from launchpad.worker.app import producer_factory

SECURITY_ENV_VARS = (
    "KAFKA_SECURITY_PROTOCOL",
    "KAFKA_SASL_MECHANISM",
    "KAFKA_SASL_USERNAME",
    "KAFKA_SASL_PASSWORD",
    "KAFKA_SSL_CA_LOCATION",
    "KAFKA_SSL_CERTIFICATE_LOCATION",
    "KAFKA_SSL_KEY_LOCATION",
)

DEFAULT_CONFIG = {
    "bootstrap.servers": "127.0.0.1:9092",
    "compression.type": "lz4",
    "message.max.bytes": 50000000,
}


@pytest.fixture(autouse=True)
def clean_kafka_environment(monkeypatch):
    for name in ("KAFKA_BOOTSTRAP_SERVERS", *SECURITY_ENV_VARS):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def kafka_producer(mocker):
    return mocker.patch("launchpad.worker.app.KafkaProducer")


def test_default_configuration(kafka_producer):
    result = producer_factory("taskworker")

    kafka_producer.assert_called_once_with(DEFAULT_CONFIG)
    assert result is kafka_producer.return_value


def test_sasl_ssl_configuration(monkeypatch, kafka_producer):
    password = "  secret$with spaces  "

    environment = {
        "KAFKA_BOOTSTRAP_SERVERS": "broker1:9093,broker2:9093",
        "KAFKA_SECURITY_PROTOCOL": "SASL_SSL",
        "KAFKA_SASL_MECHANISM": "SCRAM-SHA-256",
        "KAFKA_SASL_USERNAME": "launchpad",
        "KAFKA_SASL_PASSWORD": password,
        "KAFKA_SSL_CA_LOCATION": "/etc/kafka/ca.crt",
        "KAFKA_SSL_CERTIFICATE_LOCATION": "/etc/kafka/client.crt",
        "KAFKA_SSL_KEY_LOCATION": "/etc/kafka/client.key",
    }

    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    result = producer_factory("taskworker")

    kafka_producer.assert_called_once_with({
        **DEFAULT_CONFIG,
        "bootstrap.servers": "broker1:9093,broker2:9093",
        "security.protocol": "SASL_SSL",
        "sasl.mechanism": "SCRAM-SHA-256",
        "sasl.username": "launchpad",
        "sasl.password": password,
        "ssl.ca.location": "/etc/kafka/ca.crt",
        "ssl.certificate.location": "/etc/kafka/client.crt",
        "ssl.key.location": "/etc/kafka/client.key",
    })
    assert result is kafka_producer.return_value


def test_empty_security_parameters_are_ignored(monkeypatch, kafka_producer):
    for name in SECURITY_ENV_VARS:
        monkeypatch.setenv(name, "")

    producer_factory("taskworker")

    kafka_producer.assert_called_once_with(DEFAULT_CONFIG)
