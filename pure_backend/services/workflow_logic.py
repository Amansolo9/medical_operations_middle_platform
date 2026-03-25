VALID_TRANSITIONS = {
    "PENDING": {"APPROVED", "REJECTED", "TIMED_OUT"},
    "APPROVED": set(),
    "REJECTED": set(),
    "TIMED_OUT": set(),
}


def can_transition(current: str, target: str) -> bool:
    return target in VALID_TRANSITIONS.get(current, set())
