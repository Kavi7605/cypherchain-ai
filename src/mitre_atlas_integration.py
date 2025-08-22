# src/mitre_atlas_integration.py

import json
from typing import List, Dict

class MITREAtlasIntegration:
    atlas_techniques = {
        'AML.T0018': {
            'name': 'Supply Chain Compromise',
            'description': 'Adversaries may manipulate ML models or data in the supply chain',
            'tactic': 'Initial Access'
        },
        'AML.T0020': {
            'name': 'Poison Training Data',
            'description': 'Adversaries may poison training data to manipulate model behavior',
            'tactic': 'ML Attack Staging'
        },
        'AML.T0043': {
            'name': 'ML Model Backdoor',
            'description': 'Adversaries may insert backdoors into ML models',
            'tactic': 'Persistence'
        },
        'AML.T0051': {
            'name': 'Exploit ML Service',
            'description': 'Exploitation of vulnerabilities in ML services',
            'tactic': 'Initial Access'
        }
    }

    def map_threats(self, threats: List[str]) -> List[Dict]:
        """Map detected threat keywords to MITRE ATLAS techniques."""
        mapped_techniques = []
        for threat in threats:
            t = threat.lower()
            if 'backdoor' in t:
                mapped_techniques.append(self.atlas_techniques['AML.T0043'])
            elif 'poison' in t:
                mapped_techniques.append(self.atlas_techniques['AML.T0020'])
            elif 'supply chain' in t or 'typosquat' in t:
                mapped_techniques.append(self.atlas_techniques['AML.T0018'])
            elif 'vulnerability' in t or 'cve' in t:
                mapped_techniques.append(self.atlas_techniques['AML.T0051'])
        return mapped_techniques

    def generate_report(self, threats: List[str]) -> str:
        mapped = self.map_threats(threats)
        if not mapped:
            return "No MITRE ATLAS techniques matched."

        lines = ["MITRE ATLAS Threat Mapping Report:"]
        for technique in mapped:
            lines.append(f"- {technique['name']} ({technique['tactic']}): {technique['description']}")
        return "\n".join(lines)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python mitre_atlas_integration.py '<threat1>'+','+'<threat2>'+','+'...'")
        sys.exit(1)
    threats = sys.argv[1].split(',')
    integrated = MITREAtlasIntegration()
    print(integrated.generate_report(threats))
