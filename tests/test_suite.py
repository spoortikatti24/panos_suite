import pytest
from unittest.mock import MagicMock
from panos.firewall import Firewall
from panos_suite.auditor import PolicyAuditor
from panos_suite.sanitizer import TextSanitizer

def test_sanitizer_ip_redaction():
    sanitizer = TextSanitizer()
    text = "Connecting to 192.168.1.50 and 10.0.0.1"
    sanitized, mapping = sanitizer.sanitize(text)
    assert "192.168.1.50" not in sanitized
    assert "10.0.0.1" not in sanitized
    assert len(mapping) == 2

def test_auditor_mock_execution():
    mock_fw = MagicMock(spec=Firewall)
    auditor = PolicyAuditor(mock_fw)
    
    from panos.objects import AddressGroup, AddressObject
    from panos.policies import SecurityRule
    AddressObject.refreshall = lambda dev: []
    AddressGroup.refreshall = lambda dev: []
    SecurityRule.refreshall = lambda rulebase: []
    
    results = auditor.audit()
    assert "unused_objects" in results
    assert "missing_logging" in results
    assert "shadowed_rules" in results
