"""
date: 2024-02-05
source: https://support.bloodhoundenterprise.io/hc/en-us/articles/11311053342619-Working-with-the-BloodHound-API
description: modified version for upload function + search query
version: 0.1 PreAplpha xD

To utilize this example please install requests. The rest of the dependencies are part of the Python 3 standard
library.

# pip install --upgrade requests

Note: this script was written for Python 3.6.X or greater.

Insert your BHE API creds in the BHE constants and change the PRINT constants to print desired data.
"""

import hmac
import hashlib
import base64
import os
import requests
import datetime
import json
import sys
import shutil
import optparse

from typing import Optional


BHE_DOMAIN = "localhost"
BHE_PORT = 8080
BHE_SCHEME = "http"
BHE_TOKEN_ID = "a2b5c65d-9ae9-4983-baff-055aa661d97b"
BHE_TOKEN_KEY = "TCvIDPG8qN0Gw7Gky7UNto5hscMmwLu8K9wmdFXC7xhNJHt+G8jNbA=="

PRINT_PRINCIPALS = False
PRINT_ATTACK_PATH_TIMELINE_DATA = False
PRINT_POSTURE_DATA = False

DATA_START = "1970-01-01T00:00:00.000Z"
DATA_END = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z' # Now

class Credentials(object):
    def __init__(self, token_id: str, token_key: str) -> None:
        self.token_id = token_id
        self.token_key = token_key


class APIVersion(object):
    def __init__(self, api_version: str, server_version: str) -> None:
        self.api_version = api_version
        self.server_version = server_version


class Domain(object):
    def __init__(self, name: str, id: str, collected: bool, domain_type: str, impact_value: int) -> None:
        self.name = name
        self.id = id
        self.type = domain_type
        self.collected = collected
        self.impact_value = impact_value

class Users(object):
    def __init__(self, name: str, id: str, collected: bool, domain_type: str, impact_value: int) -> None:
        self.name = name
        self.id = id
        self.type = domain_type
        self.collected = collected
        self.impact_value = impact_value

class AttackPath(object):
    def __init__(self, id: str, title: str, domain: Domain) -> None:
        self.id = id
        self.title = title
        self.domain_id = domain.id
        self.domain_name = domain.name.strip()

    def __lt__(self, other):
        return self.exposure < other.exposure


class Client(object):
    def __init__(self, scheme: str, host: str, port: int, credentials: Credentials) -> None:
        self._scheme = scheme
        self._host = host
        self._port = port
        self._credentials = credentials

    def _format_url(self, uri: str) -> str:
        formatted_uri = uri
        if uri.startswith("/"):
            formatted_uri = formatted_uri[1:]

        return f"{self._scheme}://{self._host}:{self._port}/{formatted_uri}"

    def _request(self, method: str, uri: str, body: Optional[bytes] = None) -> requests.Response:
        # Digester is initialized with HMAC-SHA-256 using the token key as the HMAC digest key.
        digester = hmac.new(self._credentials.token_key.encode(), None, hashlib.sha256)

        # OperationKey is the first HMAC digest link in the signature chain. This prevents replay attacks that seek to
        # modify the request method or URI. It is composed of concatenating the request method and the request URI with
        # no delimiter and computing the HMAC digest using the token key as the digest secret.
        #
        # Example: GET /api/v1/test/resource HTTP/1.1
        # Signature Component: GET/api/v1/test/resource
        digester.update(f"{method}{uri}".encode())

        # Update the digester for further chaining
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        # DateKey is the next HMAC digest link in the signature chain. This encodes the RFC3339 formatted datetime
        # value as part of the signature to the hour to prevent replay attacks that are older than max two hours. This
        # value is added to the signature chain by cutting off all values from the RFC3339 formatted datetime from the
        # hours value forward:
        #
        # Example: 2020-12-01T23:59:60Z
        # Signature Component: 2020-12-01T23
        datetime_formatted = datetime.datetime.now().astimezone().isoformat("T")
        digester.update(datetime_formatted[:13].encode())

        # Update the digester for further chaining
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        # Body signing is the last HMAC digest link in the signature chain. This encodes the request body as part of
        # the signature to prevent replay attacks that seek to modify the payload of a signed request. In the case
        # where there is no body content the HMAC digest is computed anyway, simply with no values written to the
        # digester.
        if body is not None:
            digester.update(body)

        # Perform the request with the signed and expected headers
        return requests.request(
            method=method,
            url=self._format_url(uri),
            headers={
                "User-Agent": "bhe-python-sdk 0001",
                "Authorization": f"bhesignature {self._credentials.token_id}",
                "RequestDate": datetime_formatted,
                "Signature": base64.b64encode(digester.digest()),
                "Content-Type": "application/json",
            },
            data=body,
        )

    def get_version(self) -> APIVersion:
        response = self._request("GET", "/api/version")
        payload = response.json()

        return APIVersion(api_version=payload["data"]["API"]["current_version"], server_version=payload["data"]["server_version"])

    def get_users(self) -> Users:
        response = self._request('GET', '/api/v2/bloodhound-users')
        payload = response.json()['data']

        print("[+] Users on Bloodhound instance:")
        for entry in payload["users"]:
            email = entry["email_address"]
            roles = entry["roles"]
            principal_name = entry["principal_name"]

            print("\n")
            print("Login name: "+principal_name)
            print("Email: "+email)
            print("First role: "+roles[0]["name"])
            


    def get_domains(self) -> list[Domain]:
        response = self._request('GET', '/api/v2/available-domains')
        payload = response.json()['data']

        domains = list()
        for domain in payload:
            domains.append(Domain(domain["name"], domain["id"], domain["collected"], domain["type"], domain["impactValue"]))

        return domains

    def get_paths(self, domain: Domain) -> list:
        response = self._request('GET', '/api/v2/domains/' + domain.id + '/available-types')
        path_ids = response.json()['data']

        paths = list()
        for path_id in path_ids:
            # Get nice title from API and strip newline
            path_title = self._request('GET', '/ui/findings/' + path_id + '/title.md')

            # Create attackpath object
            path = AttackPath(path_id, path_title.text.strip(), domain)
            paths.append(path)

        return paths

    def get_path_principals(self, path: AttackPath) -> list:
        # Get path details from API
        response = self._request('GET', '/api/v2/domains/' + path.domain_id + '/details?finding=' + path.id + '&skip=0&limit=0&Accepted=eq:False')
        payload = response.json()

        # Build dictionary of impacted pricipals
        if 'count' in payload:
            path.impacted_principals = list()
            for path_data in payload['data']:
                # Check for both From and To to determine whether relational or configuration path
                if (path.id.startswith('LargeDefault')):
                    from_principal = path_data['FromPrincipalProps']['name']
                    to_principal = path_data['ToPrincipalProps']['name']
                    principals = {
                        'Group': from_principal,
                        'Principal': to_principal
                    }
                elif ('FromPrincipalProps' in path_data) and ('ToPrincipalProps' in path_data):
                    from_principal = path_data['FromPrincipalProps']['name']
                    to_principal = path_data['ToPrincipalProps']['name']
                    principals = {
                        'Non Tier Zero Principal': from_principal,
                        'Tier Zero Principal': to_principal
                    }
                else:
                    principals = {
                        'User': path_data['Props']['name']
                    }
                path.impacted_principals.append(principals)
                path.principal_count = payload['count']
        else:
            path.principal_count = 0

        return path

    def get_path_timeline(self, path: AttackPath, from_timestamp: str, to_timestamp: str):
        # Sparkline data
        response = self._request('GET', '/api/v2/domains/' + path.domain_id + '/sparkline?finding=' + path.id + '&from=' + from_timestamp + '&to=' + to_timestamp)
        exposure_data = response.json()['data']

        events = list()
        for event in exposure_data:
            e = {}
            e['finding_id'] = path.id
            e['domain_id'] = path.domain_id
            e['path_title'] = path.title
            e['exposure'] = event['CompositeRisk']
            e['finding_count'] = event['FindingCount']
            e['principal_count'] = event['ImpactedAssetCount']
            e['id'] = event['id']
            e['created_at'] = event['created_at']
            e['updated_at'] = event['updated_at']
            e['deleted_at'] = event['deleted_at']

            # Determine severity from exposure
            e['severity'] = self.get_severity(e['exposure'])
            events.append(e)

        return events

    def get_posture(self, from_timestamp: str, to_timestamp: str) -> list:
        response = self._request('GET', '/api/v2/posture-stats?from=' + from_timestamp + '&to=' + to_timestamp)
        payload = response.json()
        return payload["data"]

    def get_severity(self, exposure: int) -> str:
        severity = 'Low'
        if exposure > 40: severity = 'Moderate'
        if exposure > 80: severity = 'High'
        if exposure > 95: severity = 'Critical'
        return severity
    
    def upload(self) -> str:
        response = self._request("POST","/api/v2/file-upload/start")
        payload = response.json()
        print(payload["data"]["id"])
        return payload["data"]["id"]
    
    def upload_file(self,id,file) -> str:
        files = "".join(open(file,'r').readlines()).encode('utf-8')
        #print(json.loads(files))
        response = self._request("POST","/api/v2/file-upload/"+str(id), body=files)

        payload = response.status_code
        print(payload)
    
    def get_uploads(self) -> list:
        response = self._request("GET","/api/v2/file-upload")
        payload = response.json()
        for x in payload["data"]:
            if "Ingest timeout" not in str(x["status_message"]):
                    print(x["id"])
                
                
            
    def stop_uploads(self,id) -> list:
        response = self._request("POST",f"/api/v2/file-upload/{id}/end")
        payload = response.status_code
        print(payload)

    def findComputersWithoutPassword(self, cla):
        response = self._request('POST', '/api/v2/graphs/cypher', bytes('{"query": "' + cla + '"}', 'ascii'))
        data = response.json()['data'] 
        for node in data['nodes']:
            oid = data['nodes'][node]['objectId']
            responseUser = self._request('GET', f'/api/v2/computers/{oid}')
            name = responseUser.json()['data']['props']['name']
            print(name)
    
    def findUsersWithoutPassword(self, cla):
        response = self._request('POST', '/api/v2/graphs/cypher', bytes('{"query": "' + cla + '"}', 'ascii'))
        data = response.json()['data'] 
        for node in data['nodes']:
            oid = data['nodes'][node]['objectId']
            responseUser = self._request('GET', f'/api/v2/users/{oid}')
            name = responseUser.json()['data']['props']['name']
            print(name)
        





def main() -> None:
    parser = optparse.OptionParser('-n argument -u user')
    parser.add_option('-n', dest='computerquery', type='string', help='specify argument')
    parser.add_option('-u', dest='userquery', type='string', help='specify argument')

    (options, args) = parser.parse_args()
    ccommand = options.computerquery
    ucommand = options.userquery
    # This might be best loaded from a file
    credentials = Credentials(
        token_id=BHE_TOKEN_ID,
        token_key=BHE_TOKEN_KEY,
    )

    # Create the client and perform an example call using token request signing
    client = Client(scheme=BHE_SCHEME, host=BHE_DOMAIN, port=BHE_PORT, credentials=credentials)

    # just adopt the code to upload files ;-)
    id = client.upload()
    files = [pos_json for pos_json in os.listdir() if pos_json.endswith('.json')]
    [client.upload_file(id, file) for file in files]
    client.stop_uploads(id)

    if ccommand:
        client.findComputersWithoutPassword(ccommand)

    if ucommand:
        client.findUsersWithoutPassword(ucommand)
    #client.findExchangeServers()

    # take this example to create your own queries ;-)
    #response = client._request('POST', '/api/v2/graphs/cypher', bytes('{"query": "MATCH (n:User) WHERE n.hasspn=true RETURN n"}', 'ascii'))
    #data = response.json()['data']
    #for node in data['nodes']:
     #   oid = data['nodes'][node]['objectId']
      #  responseUser = client._request('GET', f'/api/v2/users/{oid}')
       # spns = responseUser.json()['data']['props']['serviceprincipalnames']
        #print(spns)
    
  
    


if __name__ == "__main__":
    main()

