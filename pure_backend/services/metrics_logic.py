from datetime import datetime

BOUNDS = {
    "attendance": (0, 24),
    "expenses": (0, 1_000_000),
    "sla": (0, 100),
    "work_order_sla": (0, 100),
}


def validate_metric_item(item: dict) -> str | None:
    required_fields = ["metric_type", "metric_value", "source_key", "recorded_at"]
    for field in required_fields:
        if field not in item:
            return f"Missing field: {field}"
    metric_type = item["metric_type"]
    if metric_type not in BOUNDS:
        return "Unsupported metric_type"
    lower, upper = BOUNDS[metric_type]
    value = item["metric_value"]
    if value < lower or value > upper:
        return "Out-of-bounds metric_value"
    try:
        datetime.fromisoformat(item["recorded_at"])
    except ValueError:
        return "Invalid recorded_at"

    message_reach = item.get("message_reach", 0)
    if message_reach < 0 or message_reach > 100:
        return "Out-of-bounds message_reach"
    return None
