import yaml
from typing import Dict
from panos.firewall import Firewall
from panos.network import Zone
from panos.objects import AddressObject, AddressGroup
from panos.policies import Rulebase, SecurityRule

class BulkDeployer:
    def __init__(self, device: Firewall):
        self.device = device

    def deploy_from_yaml(self, yaml_path: str) -> Dict[str, int]:
        with open(yaml_path, "r") as f:
            config = yaml.safe_load(f)

        stats = {"zones": 0, "addresses": 0, "groups": 0, "rules": 0}

        for z_data in config.get("zones", []):
            zone = Zone(name=z_data["name"], mode=z_data.get("mode", "layer3"))
            self.device.add(zone)
            zone.create()
            stats["zones"] += 1

        for addr in config.get("addresses", []):
            obj = AddressObject(name=addr["name"], value=addr["value"], type=addr.get("type", "ip-netmask"))
            self.device.add(obj)
            obj.create()
            stats["addresses"] += 1

        for grp in config.get("address_groups", []):
            group = AddressGroup(name=grp["name"], static_value=grp.get("members", []))
            self.device.add(group)
            group.create()
            stats["groups"] += 1

        rulebase = Rulebase()
        self.device.add(rulebase)

        for r_data in config.get("security_rules", []):
            rule = SecurityRule(
                name=r_data["name"],
                fromzone=r_data.get("from_zones", ["any"]),
                tozone=r_data.get("to_zones", ["any"]),
                source=r_data.get("source", ["any"]),
                destination=r_data.get("destination", ["any"]),
                application=r_data.get("application", ["any"]),
                service=r_data.get("service", ["application-default"]),
                action=r_data.get("action", "allow"),
                log_end=r_data.get("log_end", True),
            )
            rulebase.add(rule)
            rule.create()
            stats["rules"] += 1

        return stats
