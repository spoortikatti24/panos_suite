import argparse
import json
import sys
from unittest.mock import MagicMock

try:
    from rich.console import Console
    from rich.table import Table
    from panos.firewall import Firewall
    from panos_suite.auditor import PolicyAuditor
    from panos_suite.deployer import BulkDeployer
    from panos_suite.sanitizer import TextSanitizer
    console = Console()
    HAS_DEPENDENCIES = True
except ImportError as e:
    HAS_DEPENDENCIES = False
    MISSING_DEP = str(e)


def create_mock_firewall():
    mock_fw = MagicMock(spec=Firewall)

    obj1 = MagicMock()
    obj1.name = "Web_Server_01"
    obj1.value = "10.0.1.10"
    obj1.type = "ip-netmask"

    obj2 = MagicMock()
    obj2.name = "Legacy_DB_Server"
    obj2.value = "10.0.2.50"
    obj2.type = "ip-netmask"

    grp1 = MagicMock()
    grp1.name = "App_Group"
    grp1.static_value = ["Web_Server_01"]

    rule1 = MagicMock()
    rule1.name = "Allow_Web_Traffic"
    rule1.fromzone = ["TRUST"]
    rule1.tozone = ["UNTRUST"]
    rule1.source = ["Web_Server_01"]
    rule1.destination = ["any"]
    rule1.action = "allow"
    rule1.log_start = False
    rule1.log_end = True

    rule2 = MagicMock()
    rule2.name = "Unlogged_Rule"
    rule2.fromzone = ["TRUST"]
    rule2.tozone = ["UNTRUST"]
    rule2.source = ["10.0.1.0/24"]
    rule2.destination = ["any"]
    rule2.action = "allow"
    rule2.log_start = False
    rule2.log_end = False

    rule3 = MagicMock()
    rule3.name = "Shadowed_Duplicate_Rule"
    rule3.fromzone = ["TRUST"]
    rule3.tozone = ["UNTRUST"]
    rule3.source = ["10.0.1.0/24"]
    rule3.destination = ["any"]
    rule3.action = "allow"
    rule3.log_start = False
    rule3.log_end = True

    mock_fw.add.side_effect = lambda child: child
    return mock_fw, [obj1, obj2], [grp1], [rule1, rule2, rule3]


def run_audit(mock=False, sanitize=False, host="127.0.0.1", api_key="mock_key"):
    if mock:
        console.print("[bold yellow]Running in OFFLINE MOCK mode...[/bold yellow]")
        dev, mock_objs, mock_grps, mock_rules = create_mock_firewall()
        auditor = PolicyAuditor(dev)

        from panos.objects import AddressGroup, AddressObject
        from panos.policies import SecurityRule
        AddressObject.refreshall = lambda device: mock_objs
        AddressGroup.refreshall = lambda device: mock_grps
        SecurityRule.refreshall = lambda rulebase: mock_rules
    else:
        console.print(f"[bold blue]Connecting to PAN-OS device at {host}...[/bold blue]")
        dev = Firewall(hostname=host, api_key=api_key)
        auditor = PolicyAuditor(dev)

    with console.status("[bold green]Running audit..."):
        results = auditor.audit()

    if sanitize:
        sanitizer = TextSanitizer(custom_redactions=[host, "Legacy_DB_Server", "Web_Server_01"])
        raw_json = json.dumps(results, indent=2)
        sanitized_json, _ = sanitizer.sanitize(raw_json)
        results = json.loads(sanitized_json)

    t_unused = Table(title="Unused Address Objects")
    t_unused.add_column("Name", style="cyan")
    t_unused.add_column("Value", style="magenta")
    t_unused.add_column("Type", style="green")
    for item in results["unused_objects"]:
        t_unused.add_row(item["name"], str(item["value"]), item["type"])
    console.print(t_unused)

    t_log = Table(title="Rules Lacking Logging")
    t_log.add_column("Rule Name", style="yellow")
    t_log.add_column("From", style="blue")
    t_log.add_column("To", style="blue")
    t_log.add_column("Action", style="red")
    for item in results["missing_logging"]:
        t_log.add_row(item["name"], str(item["from"]), str(item["to"]), item["action"])
    console.print(t_log)

    t_shadow = Table(title="Shadowed Rules Detected")
    t_shadow.add_column("Rule Name", style="red")
    t_shadow.add_column("Shadowed By", style="yellow")
    t_shadow.add_column("Reason", style="white")
    for item in results["shadowed_rules"]:
        t_shadow.add_row(item["rule_name"], item["shadowed_by"], item["reason"])
    console.print(t_shadow)


def main():
    if not HAS_DEPENDENCIES:
        print(f"[ERROR] Missing required library: {MISSING_DEP}")
        print("Please run: pip install pan-os-python typer rich pyyaml pydantic")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="PAN-OS Suite Automation CLI")
    subparsers = parser.add_subparsers(dest="command")

    audit_parser = subparsers.add_parser("audit", help="Run policy & object audit")
    audit_parser.add_argument("--mock", "-m", action="store_true", help="Run in offline mock mode")
    audit_parser.add_argument("--sanitize", "-s", action="store_true", help="Sanitize/redact IP addresses")
    audit_parser.add_argument("--host", default="127.0.0.1", help="Firewall IP")
    audit_parser.add_argument("--api-key", "-k", default="mock_key", help="PAN-OS API Key")

    args = parser.parse_args()

    if args.command == "audit":
        run_audit(mock=args.mock, sanitize=args.sanitize, host=args.host, api_key=args.api_key)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
