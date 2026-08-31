import argparse
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack import ACKNOWLEDGEMENT, main, parse_args, validate_target


@pytest.mark.parametrize("target", ["127.0.0.1", "10.0.0.5", "172.16.2.3", "192.168.1.9"])
def test_target_validator_accepts_private_and_loopback(target):
    assert validate_target(target) == target


@pytest.mark.parametrize("target", [
    "example.com", "8.8.8.8", "169.254.1.1", "224.0.0.1", "0.0.0.0", "192.0.2.1",
])
def test_target_validator_rejects_unsafe_targets(target):
    with pytest.raises(argparse.ArgumentTypeError):
        validate_target(target)


def test_default_and_missing_acknowledgement_perform_no_network(monkeypatch):
    monkeypatch.setattr("attack.socket.socket", lambda *args, **kwargs: pytest.fail("network used"))
    assert main([]) == 0
    assert main(["port-scan", "--target", "127.0.0.1"]) == 2
    args = parse_args(["port-scan", "--target", "127.0.0.1",
                       "--i-understand-and-am-authorized", ACKNOWLEDGEMENT])
    assert args.target == "127.0.0.1"
