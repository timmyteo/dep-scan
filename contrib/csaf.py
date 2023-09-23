import json
from datetime import datetime

import tomli
import tomli_w

from depscan.lib.utils import get_version


class CsafOccurence:
    def __init__(self, res):
        self.cve = res["id"]
        # TODO: Deal with formatting, inquire as to how the spec deals with multiple CWEs since currently allows only one per vulnerability
        # TODO: Populate name of CWE as it is required by spec
        self.cwe = {
            "id": res["problem_type"][0],
            "name": "",
        }
        self.score = res["cvss_score"]
        self.cvss_v3 = parse_cvss(res["cvss_v3"])
        self.package_issue = res["package_issue"]
        self.product_status = {"fixed": [res["package_issue"]["fixed_location"]]}
        self.description = res["short_description"]
        self.references = res["related_urls"]
        self.type = (res["type"],)
        self.pkg = res["vdetails"]["package"]
        self.severity = (res["severity"])


def parse_cvss(cvss_v3):
    return {
        "base_score": cvss_v3["base_score"],
        "confidentiality_impact": cvss_v3["confidentiality_impact"],
        "integrity_impact": cvss_v3["integrity_impact"],
        "availability_impact": cvss_v3["availability_impact"],
        "attack_vector": cvss_v3["attack_vector"],
        "attack_complexity": cvss_v3["attack_complexity"],
        "privileges_required": cvss_v3["privileges_required"],
        "user_interaction": cvss_v3["user_interaction"],
        "scope": cvss_v3["scope"],
        "impact_score": str(cvss_v3["impact_score"]),
    }


def export_csaf_vuln(c):
    c.cvss_v3.update({"products": [c.pkg]})
    return {
        "cve": c.cve,
        "cwe": c.cwe,
        "product_status": c.product_status,
        "notes": [
            {
                "category": "general",
                "text": c.description,
                "details": "Vulnerability Description",
            },
        ],
        # "references": c.references,
        "scores": [c.cvss_v3],
    }


# TODO: Autoincrementing functionality for revisions
def parse_revision_history(rev_hx):
    new_hx = []
    for v in rev_hx.values():
        y = {
            "date": str(v["date"]),
            "number": v["number"],
            "summary": v["summary"],
        }
        if v["filepath"] != "":
            y["filepath"]: v["filepath"]
        new_hx.append(y)
    return new_hx


def parse_toml(metadata):
    rev_hx = parse_revision_history(metadata["revision_history"])
    # dist = parse_dist()
    dt = get_date()
    refs = []
    [refs.append(v) for k, v in metadata["references"].items()]
    notes = []
    [notes.append(v) for k, v in metadata["notes"].items()]
    output = {
        "document": {
            "aggregate_severity": {},
            "category": metadata["document"]["category"],
            "title": metadata["document"]["title"] or "Test",
            "csaf_version": "2.0",
            "distribution": metadata["distribution"],
            "lang": "en",
            "notes": notes,
            "publisher": {
                "category": metadata["publisher"]["category"],
                "contact_details": metadata["publisher"]["contact_details"],
                "name": metadata["publisher"]["name"],
                "namespace": metadata["publisher"]["namespace"],
            },
            "references": refs,
            "tracking": {
                "id": metadata["tracking"]["id"],
                "current_release_date": metadata["tracking"]["current_release_date"] or dt,
                # TODO: Check revision history if not in initial_release_date
                "initial_release_date": metadata["tracking"]["initial_release_date"] or dt,
                "revision_history": rev_hx,
                "status": metadata["tracking"]["status"],
                "generator": {
                    "date": dt,
                    "engine": {"name": "OWASP Depscan", "version": get_version()},
                },
                "version": str(metadata["tracking"]["version"]),
            },
        },
        # "product_tree": {"full_product_names": metadata["product_tree"]["full_product_names"]},
        "vulnerabilities": [],
    }
    if output["document"]["tracking"]["initial_release_date"] > output["document"]["tracking"]["initial_release_date"]:
        raise Exception("You cannot have an initial release date later than the current date. The most likely cause "
                        "of this error is that you have included a current_release_date in your toml but not an "
                        "initial_release_date, and we have had to use the current date/time.")
    return output


def get_date():
    return datetime.now().isoformat()


def export_csaf(results):
    metadata = import_csaf_toml()
    template = parse_toml(metadata)
    # TODO: autoincrement document versions and revisions if enabled in config
    agg_score = []
    for r in results:
        severity_ref = {
            "CRITICAL": 1,
            "HIGH": 2,
            "MEDIUM": 3,
            "LOW": 4,
        }
        c = CsafOccurence(r)
        new_vuln = export_csaf_vuln(c)
        template["vulnerabilities"].append(new_vuln)
        agg_score.append(severity_ref.get(c.severity))
    if len(agg_score) > 0:
        agg_score.sort()
        severity_ref = {v: k for k, v in severity_ref.items()}
        agg_severity = (
            severity_ref[agg_score[0]][0] + severity_ref[agg_score[0]][1:].lower()
        )
        template["document"]["aggregate_severity"]["text"] = agg_severity
    json.dump(template, open("sample.json", "w"), ensure_ascii=False, indent=4)


def import_csaf_toml():
    with open("csaf.toml", "rb") as f:
        try:
            data = tomli.load(f)
        except tomli.TOMLDecodeError:
            print("Invalid TOML. Please make sure you do not have any duplicate keys.")
            exit(1)
    return data["depscan"]["csaf"]


def main():
    results = [
        {
            "id": "CVE-2020-15366",
            "problem_type": "['CWE-915', 'CWE-1321']",
            "type": "npm",
            "severity": "MEDIUM",
            "cvss_score": "5.0",
            "cvss_v3": {
                "base_score": 5.0,
                "exploitability_score": 5.0,
                "impact_score": 5.0,
                "attack_vector": "NETWORK",
                "attack_complexity": "MODERATE",
                "privileges_required": "NONE",
                "user_interaction": "REQUIRED",
                "scope": "UNCHANGED",
                "confidentiality_impact": "MEDIUM",
                "integrity_impact": "MEDIUM",
                "availability_impact": "MEDIUM",
            },
            "package_issue": {
                "affected_location": '{"cpe_uri": "cpe:2.3:a:npm:ajv:*:*:*:*:*:*:*:*", "package": "ajv", "version": "<6.12.3"}',
                "fixed_location": "6.12.3",
            },
            "short_description": "# Prototype Pollution in Ajv\nAn issue was discovered in ajv.validate() in Ajv (aka Another JSON Schema Validator) 6.12.2. A carefully crafted JSON schema could be provided that allows execution of other code by prototype pollution. (While untrusted schemas are recommended against, the worst case of an untrusted schema should be a denial of service, not execution of code.)\nUpgrade to version 6.12.3 or later",
            "long_description": None,
            "related_urls": [],
            "effective_severity": "MEDIUM",
            "matched_by": "1089034|ajv|5.5.2",
            "vdetails": {
                "cpe_uri": "cpe:2.3:a:npm:ajv:*:*:*:*:*:*:*:*",
                "package": "ajv",
                "mii": "*",
                "mai": "*",
                "mie": None,
                "mae": "6.12.3",
                "severity": "UNSPECIFIED",
                "description": None,
                "fixed_location": "cpe:2.3:a:npm:ajv:6.12.3:*:*:*:*:*:*:*",
                "package_type": "npm",
                "is_obsolete": None,
                "source_update_time": "2023-01-27T05:08:06.000Z",
            },
        },
        {
            "id": "CVE-2020-28469",
            "problem_type": "['CWE-400']",
            "type": "npm",
            "severity": "HIGH",
            "cvss_score": "7.5",
            "cvss_v3": {
                "base_score": 7.5,
                "exploitability_score": 7.5,
                "impact_score": 7.5,
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "REQUIRED",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
            },
            "package_issue": {
                "affected_location": '{"cpe_uri": "cpe:2.3:a:npm:glob-parent:*:*:*:*:*:*:*:*", "package": "glob-parent", "version": "<5.1.2"}',
                "fixed_location": "5.1.2",
            },
            "short_description": "# glob parent before 5.1.2 vulnerable to Regular Expression Denial of Service in enclosure regex\nThis affects the package glob parent before 5.1.2. The enclosure regex used to check for strings ending in enclosure containing path separator.\nUpgrade to version 5.1.2 or later",
            "long_description": None,
            "related_urls": [],
            "effective_severity": "HIGH",
            "matched_by": "1091181|glob-parent|3.1.0",
            "vdetails": {
                "cpe_uri": "cpe:2.3:a:npm:glob-parent:*:*:*:*:*:*:*:*",
                "package": "glob-parent",
                "mii": "*",
                "mai": "*",
                "mie": None,
                "mae": "5.1.2",
                "severity": "UNSPECIFIED",
                "description": None,
                "fixed_location": "cpe:2.3:a:npm:glob-parent:5.1.2:*:*:*:*:*:*:*",
                "package_type": "npm",
                "is_obsolete": None,
                "source_update_time": "2023-02-28T22:39:43.000Z",
            },
        },
        {
            "id": "CVE-2023-29017",
            "problem_type": "['CWE-913']",
            "type": "npm",
            "severity": "CRITICAL",
            "cvss_score": "9.0",
            "cvss_v3": {
                "base_score": 9.0,
                "exploitability_score": 9.0,
                "impact_score": 9.0,
                "attack_vector": "NETWORK",
                "attack_complexity": "CRITICAL",
                "privileges_required": "NONE",
                "user_interaction": "REQUIRED",
                "scope": "UNCHANGED",
                "confidentiality_impact": "CRITICAL",
                "integrity_impact": "CRITICAL",
                "availability_impact": "CRITICAL",
            },
            "package_issue": {
                "affected_location": '{"cpe_uri": "cpe:2.3:a:npm:vm2:*:*:*:*:*:*:*:*", "package": "vm2", "version": "<3.9.15"}',
                "fixed_location": "3.9.15",
            },
            "short_description": "# vm2 vulnerable to sandbox escape\nvm2 was not properly handling host objects passed to `Error.prepareStackTrace` in case of unhandled async errors.\n\n\tvm2 version: ~3.9.14\n\tNode version: 18.15.0, 19.8.1, 17.9.1\n\n### Impact\nA threat actor can bypass the sandbox protections to gain remote code execution rights on the host running the sandbox.\n\n### Patches\nThis vulnerability was patched in the release of version `3.9.15` of `vm2`.\n\n### Workarounds\nNone.\nUpgrade to version 3.9.15 or later",
            "long_description": None,
            "related_urls": [],
            "effective_severity": "CRITICAL",
            "matched_by": "1091646|vm2|3.9.13",
            "vdetails": {
                "cpe_uri": "cpe:2.3:a:npm:vm2:*:*:*:*:*:*:*:*",
                "package": "vm2",
                "mii": "*",
                "mai": "*",
                "mie": None,
                "mae": "3.9.15",
                "severity": "UNSPECIFIED",
                "description": None,
                "fixed_location": "cpe:2.3:a:npm:vm2:3.9.15:*:*:*:*:*:*:*",
                "package_type": "npm",
                "is_obsolete": None,
                "source_update_time": "2023-04-07T20:35:04.000Z",
            },
        },
        {
            "id": "CVE-2023-29199",
            "problem_type": "['CWE-913']",
            "type": "npm",
            "severity": "CRITICAL",
            "cvss_score": "9.0",
            "cvss_v3": {
                "base_score": 9.0,
                "exploitability_score": 9.0,
                "impact_score": 9.0,
                "attack_vector": "NETWORK",
                "attack_complexity": "CRITICAL",
                "privileges_required": "NONE",
                "user_interaction": "REQUIRED",
                "scope": "UNCHANGED",
                "confidentiality_impact": "CRITICAL",
                "integrity_impact": "CRITICAL",
                "availability_impact": "CRITICAL",
            },
            "package_issue": {
                "affected_location": '{"cpe_uri": "cpe:2.3:a:npm:vm2:*:*:*:*:*:*:*:*", "package": "vm2", "version": "<3.9.16"}',
                "fixed_location": "3.9.16",
            },
            "short_description": "# vm2 Sandbox Escape vulnerability\nThere exists a vulnerability in source code transformer (exception sanitization logic) of vm2 for versions up to 3.9.15, allowing attackers to bypass `handleException()` and leak unsanitized host exceptions which can be used to escape the sandbox and run arbitrary code in host context.\n\n### Impact\nA threat actor can bypass the sandbox protections to gain remote code execution rights on the host running the sandbox.\n\n### Patches\nThis vulnerability was patched in the release of version `3.9.16` of `vm2`.\n\n### Workarounds\nNone.\n\n### References\nGithub Issue\t https://github.com/patriksimek/vm2/issues/516\nPoC\t https://gist.github.com/leesh3288/f05730165799bf56d70391f3d9ea187c\n\n### For more information\n\nIf you have any questions or comments about this advisory:\n\n\tOpen an issue in [VM2 (https://github.com/patriksimek/vm2)\n\nThanks to [Xion (https://twitter.com/0x10n) (SeungHyun Lee) of [KAIST Hacking Lab (https://kaist hacking.github.io/) for disclosing this vulnerability.\nUpgrade to version 3.9.16 or later",
            "long_description": None,
            "related_urls": [],
            "effective_severity": "CRITICAL",
            "matched_by": "1091727|vm2|3.9.13",
            "vdetails": {
                "cpe_uri": "cpe:2.3:a:npm:vm2:*:*:*:*:*:*:*:*",
                "package": "vm2",
                "mii": "*",
                "mai": "*",
                "mie": None,
                "mae": "3.9.16",
                "severity": "UNSPECIFIED",
                "description": None,
                "fixed_location": "cpe:2.3:a:npm:vm2:3.9.16:*:*:*:*:*:*:*",
                "package_type": "npm",
                "is_obsolete": None,
                "source_update_time": "2023-04-14T21:35:02.000Z",
            },
        },
        {
            "id": "CVE-2023-30547",
            "problem_type": "['CWE-74']",
            "type": "npm",
            "severity": "CRITICAL",
            "cvss_score": "9.0",
            "cvss_v3": {
                "base_score": 9.0,
                "exploitability_score": 9.0,
                "impact_score": 9.0,
                "attack_vector": "NETWORK",
                "attack_complexity": "CRITICAL",
                "privileges_required": "NONE",
                "user_interaction": "REQUIRED",
                "scope": "UNCHANGED",
                "confidentiality_impact": "CRITICAL",
                "integrity_impact": "CRITICAL",
                "availability_impact": "CRITICAL",
            },
            "package_issue": {
                "affected_location": '{"cpe_uri": "cpe:2.3:a:npm:vm2:*:*:*:*:*:*:*:*", "package": "vm2", "version": "<3.9.17"}',
                "fixed_location": "3.9.17",
            },
            "short_description": "# vm2 Sandbox Escape vulnerability\nThere exists a vulnerability in exception sanitization of vm2 for versions up to 3.9.16, allowing attackers to raise an unsanitized host exception inside `handleException()` which can be used to escape the sandbox and run arbitrary code in host context.\n\n### Impact\nA threat actor can bypass the sandbox protections to gain remote code execution rights on the host running the sandbox.\n\n### Patches\nThis vulnerability was patched in the release of version `3.9.17` of `vm2`.\n\n### Workarounds\nNone.\n\n### References\nPoC\t https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244\n\n### For more information\n\nIf you have any questions or comments about this advisory:\n\n\tOpen an issue in [VM2 (https://github.com/patriksimek/vm2)\n\nThanks to [Xion (https://twitter.com/0x10n) (SeungHyun Lee) of [KAIST Hacking Lab (https://kaist hacking.github.io/) for disclosing this vulnerability.\nUpgrade to version 3.9.17 or later",
            "long_description": None,
            "related_urls": [],
            "effective_severity": "CRITICAL",
            "matched_by": "1091758|vm2|3.9.13",
            "vdetails": {
                "cpe_uri": "cpe:2.3:a:npm:vm2:*:*:*:*:*:*:*:*",
                "package": "vm2",
                "mii": "*",
                "mai": "*",
                "mie": None,
                "mae": "3.9.17",
                "severity": "UNSPECIFIED",
                "description": None,
                "fixed_location": "cpe:2.3:a:npm:vm2:3.9.17:*:*:*:*:*:*:*",
                "package_type": "npm",
                "is_obsolete": None,
                "source_update_time": "2023-04-20T14:37:53.000Z",
            },
        },
        {
            "id": "CVE-2023-32314",
            "problem_type": "['CWE-74']",
            "type": "npm",
            "severity": "CRITICAL",
            "cvss_score": "9.0",
            "cvss_v3": {
                "base_score": 9.0,
                "exploitability_score": 9.0,
                "impact_score": 9.0,
                "attack_vector": "NETWORK",
                "attack_complexity": "CRITICAL",
                "privileges_required": "NONE",
                "user_interaction": "REQUIRED",
                "scope": "UNCHANGED",
                "confidentiality_impact": "CRITICAL",
                "integrity_impact": "CRITICAL",
                "availability_impact": "CRITICAL",
            },
            "package_issue": {
                "affected_location": '{"cpe_uri": "cpe:2.3:a:npm:vm2:*:*:*:*:*:*:*:*", "package": "vm2", "version": "<3.9.18"}',
                "fixed_location": "3.9.18",
            },
            "short_description": "# vm2 Sandbox Escape vulnerability\nA sandbox escape vulnerability exists in vm2 for versions up to 3.9.17. It abuses an unexpected creation of a host object based on the specification of `Proxy`.\n\n### Impact\nA threat actor can bypass the sandbox protections to gain remote code execution rights on the host running the sandbox.\n\n### Patches\nThis vulnerability was patched in the release of version `3.9.18` of `vm2`.\n\n### Workarounds\nNone.\n\n### References\nPoC\t https://gist.github.com/arkark/e9f5cf5782dec8321095be3e52acf5ac\n\n### For more information\n\nIf you have any questions or comments about this advisory:\n\n\tOpen an issue in [VM2 (https://github.com/patriksimek/vm2)\n\nThanks to @arkark (Takeshi Kaneko) of GMO Cybersecurity by Ierae, Inc. for disclosing this vulnerability.\nUpgrade to version 3.9.18 or later",
            "long_description": None,
            "related_urls": [],
            "effective_severity": "CRITICAL",
            "matched_by": "1092072|vm2|3.9.13",
            "vdetails": {
                "cpe_uri": "cpe:2.3:a:npm:vm2:*:*:*:*:*:*:*:*",
                "package": "vm2",
                "mii": "*",
                "mai": "*",
                "mie": None,
                "mae": "3.9.18",
                "severity": "UNSPECIFIED",
                "description": None,
                "fixed_location": "cpe:2.3:a:npm:vm2:3.9.18:*:*:*:*:*:*:*",
                "package_type": "npm",
                "is_obsolete": None,
                "source_update_time": "2023-05-15T21:39:13.000Z",
            },
        },
        {
            "id": "CVE-2023-32313",
            "problem_type": "['CWE-74']",
            "type": "npm",
            "severity": "MEDIUM",
            "cvss_score": "5.0",
            "cvss_v3": {
                "base_score": 5.0,
                "exploitability_score": 5.0,
                "impact_score": 5.0,
                "attack_vector": "NETWORK",
                "attack_complexity": "MODERATE",
                "privileges_required": "NONE",
                "user_interaction": "REQUIRED",
                "scope": "UNCHANGED",
                "confidentiality_impact": "MEDIUM",
                "integrity_impact": "MEDIUM",
                "availability_impact": "MEDIUM",
            },
            "package_issue": {
                "affected_location": '{"cpe_uri": "cpe:2.3:a:npm:vm2:*:*:*:*:*:*:*:*", "package": "vm2", "version": "<3.9.18"}',
                "fixed_location": "3.9.18",
            },
            "short_description": "# vm2 vulnerable to Inspect Manipulation\nIn versions 3.9.17 and lower of vm2 it was possible to get a read write reference to the node `inspect` method and edit options for `console.log`.\n\n### Impact\nA threat actor can edit options for `console.log`.\n\n### Patches\nThis vulnerability was patched in the release of version `3.9.18` of `vm2`.\n\n### Workarounds\nAfter creating a vm make the `inspect` method readonly with `vm.readonly(inspect)`.\n\n### References\nPoC\t https://gist.github.com/arkark/c1c57eaf3e0a649af1a70c2b93b17550\n\n### For more information\n\nIf you have any questions or comments about this advisory:\n\n\tOpen an issue in [VM2 (https://github.com/patriksimek/vm2)\n\nThanks to @arkark (Takeshi Kaneko) of GMO Cybersecurity by Ierae, Inc. for disclosing this vulnerability.\nUpgrade to version 3.9.18 or later",
            "long_description": None,
            "related_urls": [],
            "effective_severity": "MEDIUM",
            "matched_by": "1092074|vm2|3.9.13",
            "vdetails": {
                "cpe_uri": "cpe:2.3:a:npm:vm2:*:*:*:*:*:*:*:*",
                "package": "vm2",
                "mii": "*",
                "mai": "*",
                "mie": None,
                "mae": "3.9.18",
                "severity": "UNSPECIFIED",
                "description": None,
                "fixed_location": "cpe:2.3:a:npm:vm2:3.9.18:*:*:*:*:*:*:*",
                "package_type": "npm",
                "is_obsolete": None,
                "source_update_time": "2023-05-17T03:49:38.000Z",
            },
        },
        {
            "id": "CVE-2023-32695",
            "problem_type": "['CWE-20', 'CWE-754']",
            "type": "npm",
            "severity": "HIGH",
            "cvss_score": "7.5",
            "cvss_v3": {
                "base_score": 7.5,
                "exploitability_score": 7.5,
                "impact_score": 7.5,
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "REQUIRED",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
            },
            "package_issue": {
                "affected_location": '{"cpe_uri": "cpe:2.3:a:npm:socket.io-parser:*:*:*:*:*:*:*:*", "package": "socket.io-parser", "version": ">=4.0.4-<4.2.3"}',
                "fixed_location": "4.2.3",
            },
            "short_description": "# Insufficient validation when decoding a Socket.IO packet\n### Impact\n\nA specially crafted Socket.IO packet can trigger an uncaught exception on the Socket.IO server, thus killing the Node.js process.\n\n```\nTypeError: Cannot convert object to primitive value\n\t\t\t at Socket.emit (node:events:507:25)\n\t\t\t at .../node_modules/socket.io/lib/socket.js:531:14\n```\n\n### Patches\n\nA fix has been released today (2023/05/22):\n\n\thttps://github.com/socketio/socket.io parser/commit/3b78117bf6ba7e99d7a5cfc1ba54d0477554a7f3, included in `socket.io parser@4.2.3`\n\thttps://github.com/socketio/socket.io parser/commit/2dc3c92622dad113b8676be06f23b1ed46b02ced, included in `socket.io parser@3.4.3`\n\n| `socket.io` version | `socket.io parser` version\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t| Needs minor update?\t\t\t\t\t\t\t\t\t|\n|\t\t\t\t\t\t\t\t\t\t |\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t |\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t|\n| `4.5.2...latest`\t\t| `~4.2.0` ([ref (https://github.com/socketio/socket.io/commit/9890b036cf942f6b6ad2afeb6a8361c32cd5d528)) | `npm audit fix` should be sufficient |\n| `4.1.3...4.5.1`\t\t | `~4.1.1` ([ref (https://github.com/socketio/socket.io/commit/7c44893d7878cd5bba1eff43150c3e664f88fb57)) | Please upgrade to `socket.io@4.6.x`\t|\n| `3.0.5...4.1.2`\t\t | `~4.0.3` ([ref (https://github.com/socketio/socket.io/commit/752dfe3b1e5fecda53dae899b4a39e6fed5a1a17)) | Please upgrade to `socket.io@4.6.x`\t|\n| `3.0.0...3.0.4`\t\t | `~4.0.1` ([ref (https://github.com/socketio/socket.io/commit/1af3267e3f5f7884214cf2ca4d5282d620092fb0)) | Please upgrade to `socket.io@4.6.x`\t|\n| `2.3.0...2.5.0`\t\t | `~3.4.0` ([ref (https://github.com/socketio/socket.io/commit/cf39362014f5ff13a17168b74772c43920d6e4fd)) | `npm audit fix` should be sufficient |\n\n\n### Workarounds\n\nThere is no known workaround except upgrading to a safe version.\n\n### For more information\n\nIf you have any questions or comments about this advisory:\n\n\tOpen a discussion [here (https://github.com/socketio/socket.io/discussions)\n\nThanks to [@rafax00 (https://github.com/rafax00) for the responsible disclosure.\n\nUpgrade to version 4.2.3 or later",
            "long_description": None,
            "related_urls": [],
            "effective_severity": "HIGH",
            "matched_by": "1092174|socket.io-parser|4.0.5",
            "vdetails": {
                "cpe_uri": "cpe:2.3:a:npm:socket.io-parser:*:*:*:*:*:*:*:*",
                "package": "socket.io-parser",
                "mii": "4.0.4",
                "mai": "*",
                "mie": None,
                "mae": "4.2.3",
                "severity": "UNSPECIFIED",
                "description": None,
                "fixed_location": "cpe:2.3:a:npm:socket.io-parser:4.2.3:*:*:*:*:*:*:*",
                "package_type": "npm",
                "is_obsolete": None,
                "source_update_time": "2023-06-05T21:07:58.000Z",
            },
        },
    ]
    export_csaf(results)


if __name__ == "__main__":
    main()
