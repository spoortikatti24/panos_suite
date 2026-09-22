from typing import Any, Dict, List
from panos.firewall import Firewall
from panos.objects import AddressGroup, AddressObject
from panos.policies import Rulebase, SecurityRule

class PolicyAuditor:
    def __init__(self, device: Firewall):
        self.device = device

    def audit(self) -> Dict[str, List[Dict[str, Any]]]:
        results = {"unused_objects": [], "missing_logging": [], "shadowed_rules": []}

        addr_objects = AddressObject.refreshall(self.device)
        addr_groups = AddressGroup.refreshall(self.device)

        rulebase = Rulebase()
        self.device.add(rulebase)
        sec_rules = SecurityRule.refreshall(rulebase)

        used_object_names = set()
        for rule in sec_rules:
            used_object_names.update(rule.source or [])
            used_object_names.update(rule.destination or [])

        for group in addr_groups:
            used_object_names.update(group.static_value or [])

        for obj in addr_objects:
            if obj.name not in used_object_names:
                results["unused_objects"].append({"name": obj.name, "value": obj.value, "type": obj.type})

        seen_rules = []
        for rule in sec_rules:
            if not rule.log_start and not rule.log_end:
                results["missing_logging"].append({"name": rule.name, "from": rule.fromzone, "to": rule.tozone, "action": rule.action})

            rule_signature = (
                tuple(sorted(rule.fromzone or [])),
                tuple(sorted(rule.tozone or [])),
                tuple(sorted(rule.source or [])),
                tuple(sorted(rule.destination or [])),
                tuple(sorted(rule.application or [])),
                tuple(sorted(rule.service or [])),
            )

            for prev_rule_name, prev_signature, prev_action in seen_rules:
                if rule_signature == prev_signature:
                    results["shadowed_rules"].append({
                        "rule_name": rule.name,
                        "shadowed_by": prev_rule_name,
                        "reason": f"Exact match signature with higher-priority rule '{prev_rule_name}'"
                    })
                    break

            seen_rules.append((rule.name, rule_signature, rule.action))

        return results
