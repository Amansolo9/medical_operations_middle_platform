from pure_backend.services.metrics_logic import validate_metric_item


def test_metric_validation_missing_field():
    item = {"metric_type": "attendance", "metric_value": 5}
    assert validate_metric_item(item) == "Missing field: source_key"


def test_metric_validation_out_of_bounds():
    item = {
        "metric_type": "attendance",
        "metric_value": 25,
        "source_key": "k1",
        "recorded_at": "2026-03-24T10:00:00",
    }
    assert validate_metric_item(item) == "Out-of-bounds metric_value"


def test_metric_validation_ok():
    item = {
        "metric_type": "attendance",
        "metric_value": 8,
        "source_key": "k2",
        "recorded_at": "2026-03-24T10:00:00",
    }
    assert validate_metric_item(item) is None
