"""SOAR (Security Orchestration, Automation and Response) layer.

Every enforcement is recorded as a SecurityRule with an automatic expiry so a
false positive can never cause a permanent outage. OS-level enforcement
(iptables / netsh / hosts-file sinkhole) only runs when SOAR_DRY_RUN is
disabled; by default actions are recorded and logged but not applied.

Targets are validated before they get anywhere near a shell or a file: IPs
must parse as IP addresses and domains must be RFC 1123 hostnames, and
commands are always built as argument lists (never shell strings).
"""
import ipaddress
import logging
import os
import re
import subprocess
from datetime import timedelta
from typing import Dict, Optional

from config import settings
from database import DNSAuditLog, SecurityRule, SessionLocal, Whitelist, iso_utc, utcnow

logger = logging.getLogger("DNSentinel.SOAR")

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9_-]{1,63}(?<!-)(\.(?!-)[a-z0-9_-]{1,63}(?<!-))*$"
)
SINKHOLE_TAG = "# DNSentinel_Sinkhole"

# Infrastructure that must never be blocked automatically.
ESSENTIALS = [
    ("0.0.0.0", "Unspecified address (unknown source)"),
    ("::", "Unspecified address (unknown source, IPv6)"),
    ("127.0.0.1", "Localhost"),
    ("::1", "Localhost (IPv6)"),
    ("192.168.1.1", "Network gateway"),
    ("8.8.8.8", "Google DNS resolver"),
    ("1.1.1.1", "Cloudflare DNS resolver"),
]


def validate_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        return None


def validate_domain(value: str) -> Optional[str]:
    value = (value or "").strip().lower().rstrip(".")
    return value if _HOSTNAME_RE.match(value) else None


class ActionOrchestrator:
    DEFAULT_COOLDOWN_HOURS = 24

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self._whitelist_ready = False

    # ------------------------------------------------------------------ utils
    def _ensure_whitelist(self, db):
        if self._whitelist_ready:
            return
        for entity, reason in ESSENTIALS:
            if not db.query(Whitelist).filter(Whitelist.entity == entity).first():
                db.add(Whitelist(entity=entity, reason=reason))
        db.commit()
        self._whitelist_ready = True

    def _normalise(self, entity: str, rule_type: str) -> Optional[str]:
        return validate_ip(entity) if rule_type == "IP_BLOCK" else validate_domain(entity)

    # ------------------------------------------------------ OS enforcement
    def execute_firewall_command(self, ip: str, action: str = "BLOCK") -> bool:
        """Apply or remove an inbound drop rule for `ip` (already validated)."""
        if os.name == "nt":
            name = f"name=DNSentinel_Block_{ip}"
            cmd = (["netsh", "advfirewall", "firewall", "add", "rule", name,
                    "dir=in", "action=block", f"remoteip={ip}"]
                   if action == "BLOCK" else
                   ["netsh", "advfirewall", "firewall", "delete", "rule", name])
        else:
            iptables = "ip6tables" if ":" in ip else "iptables"
            flag = "-A" if action == "BLOCK" else "-D"
            cmd = [iptables, flag, "INPUT", "-s", ip, "-j", "DROP"]

        if self.dry_run:
            logger.info("[DRY-RUN] would execute: %s", " ".join(cmd))
            return True
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=10)
            logger.info("Firewall %s applied for %s", action, ip)
            return True
        except (subprocess.SubprocessError, OSError) as e:
            logger.error("Firewall automation error for %s: %s", ip, e)
            return False

    def sinkhole_domain(self, domain: str, action: str = "BLOCK") -> bool:
        """Point `domain` (already validated) at 127.0.0.1 via the hosts file."""
        hosts = r"C:\Windows\System32\drivers\etc\hosts" if os.name == "nt" else "/etc/hosts"
        entry = f"127.0.0.1 {domain} {SINKHOLE_TAG}"
        if self.dry_run:
            verb = "add" if action == "BLOCK" else "remove"
            logger.info("[DRY-RUN] would %s hosts entry: %s", verb, entry)
            return True
        try:
            if action == "BLOCK":
                with open(hosts, "a", encoding="utf-8") as f:
                    f.write(entry + "\n")
            else:
                with open(hosts, encoding="utf-8") as f:
                    lines = f.readlines()
                with open(hosts, "w", encoding="utf-8") as f:
                    # Only remove the exact line we added -- never user entries.
                    f.writelines(line for line in lines if line.strip() != entry)
            return True
        except OSError as e:
            logger.error("Sinkhole error for %s (needs admin/root): %s", domain, e)
            return False

    # --------------------------------------------------------- rule store
    def trigger_block(self, entity: str, reason: str, rule_type: str = "IP_BLOCK",
                      risk_score: float = 100.0) -> Dict:
        if rule_type not in ("IP_BLOCK", "DOMAIN_SINKHOLE"):
            return {"status": "INVALID", "message": f"unknown rule_type {rule_type!r}"}
        target = self._normalise(entity, rule_type)
        if target is None:
            return {"status": "INVALID", "message": f"{entity!r} is not a valid target for {rule_type}"}

        with SessionLocal() as db:
            self._ensure_whitelist(db)
            if db.query(Whitelist).filter(Whitelist.entity == target).first():
                return {"status": "DENIED", "message": f"{target} is on the protected whitelist."}

            expires_at = utcnow() + timedelta(hours=self.DEFAULT_COOLDOWN_HOURS)
            rule = db.query(SecurityRule).filter(SecurityRule.target == target).first()
            if rule and rule.is_active:
                return {"status": "SKIPPED", "message": "Enforcement already active.", "entity": target}
            if rule is None:
                # One row per target (unique); a later re-block reactivates it.
                rule = SecurityRule(target=target)
                db.add(rule)
            rule.rule_type = rule_type
            rule.action = "BLOCK"
            rule.reason = reason
            rule.risk_score = risk_score
            rule.is_active = True
            rule.added_at = utcnow()
            rule.expires_at = expires_at
            db.commit()

        if rule_type == "IP_BLOCK":
            success = self.execute_firewall_command(target, "BLOCK")
        else:
            success = self.sinkhole_domain(target, "BLOCK")

        return {
            "status": "SUCCESS" if success else "ENFORCEMENT_FAILED",
            "entity": target,
            "type": rule_type,
            "dry_run": self.dry_run,
            "cooldown_end": iso_utc(expires_at),
        }

    def trigger_unblock(self, entity: str) -> Dict:
        target = validate_ip(entity) or validate_domain(entity)
        if target is None:
            return {"status": "INVALID", "message": f"{entity!r} is not a valid IP or domain"}
        with SessionLocal() as db:
            rule = db.query(SecurityRule).filter(
                SecurityRule.target == target, SecurityRule.is_active.is_(True)
            ).first()
            if not rule:
                return {"status": "NOT_FOUND", "message": "No active rule found for entity."}
            rule.is_active = False
            rule_type = rule.rule_type
            db.commit()

        if rule_type == "IP_BLOCK":
            success = self.execute_firewall_command(target, "UNBLOCK")
        else:
            success = self.sinkhole_domain(target, "UNBLOCK")
        return {"status": "REMOVED" if success else "PERSISTENCE_ONLY", "entity": target}

    def list_active(self) -> list:
        with SessionLocal() as db:
            rules = (db.query(SecurityRule)
                     .filter(SecurityRule.is_active.is_(True))
                     .order_by(SecurityRule.added_at.desc())
                     .all())
            return [r.to_dict() for r in rules]

    def cleanup_expired_rules(self) -> int:
        """Revoke every active rule whose expiry has passed. Returns the count."""
        with SessionLocal() as db:
            targets = [r.target for r in db.query(SecurityRule).filter(
                SecurityRule.is_active.is_(True), SecurityRule.expires_at < utcnow()
            ).all()]
        for target in targets:
            self.trigger_unblock(target)
        if targets:
            logger.info("SOAR cleanup: revoked %d expired rule(s).", len(targets))
        return len(targets)

    # ------------------------------------------------------ analyst loop
    def mark_false_positive(self, log_id: int) -> Dict:
        with SessionLocal() as db:
            log = db.query(DNSAuditLog).filter(DNSAuditLog.id == log_id).first()
            if not log:
                return {"status": "NOT_FOUND"}
            log.is_false_positive = True
            log.prediction = "Normal"
            log.risk_level = "Low"
            log.risk_score = 5.0
            log.is_blocked = False
            source_ip = log.source_ip
            db.commit()
        unblock = self.trigger_unblock(source_ip)
        return {"status": "FEEDBACK_RECORDED", "log_id": log_id, "unblock": unblock["status"]}

    def generate_incident_report(self, log_id: int) -> Optional[str]:
        """Markdown incident report for one audit record, or None if missing."""
        with SessionLocal() as db:
            log = db.query(DNSAuditLog).filter(DNSAuditLog.id == log_id).first()
            if not log:
                return None

            ts = log.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if log.timestamp else "N/A"
            lines = [
                f"# DNSentinel Incident Report - SOC-{log.id}",
                "",
                "## 1. Summary",
                f"- **Incident ID:** SOC-{log.id}",
                f"- **Timestamp:** {ts}",
                f"- **Source IP:** {log.source_ip}",
                f"- **Query:** `{log.query}`",
                f"- **Record Type:** {log.qtype}",
                f"- **Classification:** {log.prediction}",
                f"- **Risk Score:** {log.risk_score} ({log.risk_level})",
                f"- **Priority:** {log.priority} ({log.priority_score})",
                f"- **Blocked:** {'Yes' if log.is_blocked else 'No'}",
                f"- **Analyst verdict:** {'False positive' if log.is_false_positive else 'Not reviewed'}",
                "",
                "## 2. Technical Analysis",
                log.explanation or "No detailed explanation recorded.",
                "",
                "## 3. MITRE ATT&CK Mapping",
            ]
            if log.mitre_data:
                for tid, technique in log.mitre_data.items():
                    if isinstance(technique, dict):
                        lines.append(f"- **{tid} - {technique.get('Name', '')}**")
                        if technique.get("Description"):
                            lines.append(f"  - _Detection:_ {technique['Description']}")
                        if technique.get("Mitigation"):
                            lines.append(f"  - _Mitigation:_ {technique['Mitigation']}")
                    else:
                        lines.append(f"- **{tid}:** {technique}")
            else:
                lines.append("- No MITRE techniques mapped for this event.")
            lines += [
                "",
                "## 4. Recommended Actions",
                "- Review the source endpoint for related activity.",
                "- Confirm containment (block/sinkhole) if malicious.",
                "- Mark as false positive if benign to feed the analyst feedback loop.",
                "",
                "_Generated automatically by DNSentinel SOAR._",
            ]
            return "\n".join(lines)


orchestrator = ActionOrchestrator(dry_run=settings.SOAR_DRY_RUN)
