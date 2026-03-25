from pure_backend.services.workflow_logic import can_transition


def test_valid_transition_from_pending_to_approved():
    assert can_transition("PENDING", "APPROVED") is True


def test_invalid_transition_from_approved_to_pending():
    assert can_transition("APPROVED", "PENDING") is False
