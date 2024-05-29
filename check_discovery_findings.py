import requests
import sys
import json

def check_discovery_findings(endpoint, token, applications):
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    response = requests.get(endpoint, headers=headers)
    
    if response.status_code != 200:
        print(f"Failed to fetch data from endpoint. Status code: {response.status_code}")
        sys.exit(1)
    
    data = response.json()
    
    for app in applications:
        for entry in data:
            if entry['Name'] == app:
                if 'UpperViolations' in entry:
                    print(f"UpperViolations: {entry['UpperViolations']}")
                if 'SideViolations' in entry:
                    print(f"SideViolations: {entry['SideViolations']}")
                if 'CyclicViolations' in entry:
                    print(f"CyclicViolations: {entry['CyclicViolations']}")
                if 'UpperViolations' in entry or 'SideViolations' in entry or 'CyclicViolations' in entry:
                    print(f"Infractions found for application: {app}")
                    sys.exit(1)
    
    print("No infractions found for the provided applications.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python check_discovery_findings.py <endpoint> <token> <applications>")
        sys.exit(1)
    
    endpoint = sys.argv[1]
    token = sys.argv[2]
    applications = json.loads(sys.argv[3])
    
    check_discovery_findings(endpoint, token, applications)
