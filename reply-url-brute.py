from requests import post, get, Session
import json
from urllib.parse import urlparse, urlencode, parse_qs
import socket
import re
import yaml
import os
import sys
import ipaddress
import argparse
from lxml import html


# Request access_tokens
def get_token(session, app_id, scope, reply_url):
    url_authorize_base = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
    url_token_base = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"
    get_params_authorize = {
        "client_id": app_id, 
        "redirect_uri": reply_url,
        "scope": scope,
        "response_type": "code",
        "response_mode": "query",

        "code_challenge": "r28qDfmtnCyRedcGckQkfvFQHcBZA3_vLRPxWm8UWF4",
        "code_challenge_method": "S256",
        "nonce": "aaaaa"
    }
    url_authorize = f"{url_authorize_base}?{urlencode(get_params_authorize)}"
    print(f"[*] Send Authorize for scope: {scope}")
    res = session.get(url_authorize, allow_redirects=False)

    if (not res.status_code == 302):
        print("[-] No 302, exiting")
        exit(1)

    url_location = urlparse(res.headers["Location"])
    fragment = parse_qs(url_location.fragment)
    query = parse_qs(url_location.query)
    if (not "code" in query):
        print("[-] No code in Location header, exiting")
        exit(1)
        
    auth_code =  query["code"][0]

    post_token = {
        "client_id": app_id, 
        "redirect_uri": reply_url,

        "grant_type": "authorization_code",
        "code": auth_code,

        "code_verifier": "aWiBCBNOF4xzGOCjmTA0IdQdSXj4lbS9oNiywvRYIAM"
    }

    print(f"[*] Send Token request for scope: {scope}")
    res = session.post(url_token_base, data=post_token, headers={"Origin": "aaa"})
    if (not res.status_code == 200):
        print("[-] No 200, exiting")
        exit(1)
    res_body = res.json()

    if (not "access_token" in res_body):
        print("[-] No access token, exiting")
        exit(1)
    
    return res_body["access_token"]


def get_sps(sps=None, url="https://graph.microsoft.com/v1.0/servicePrincipals", appId=None):
    if(sps is None):
        sps = []

    if(appId):
        url = f"{url}?$filter=AppId%20eq%20%27{appId}%27"
        
    header_auth = { "Authorization": f"Bearer {token_ms}"}
    res = get(url, headers=header_auth)
    if (res.status_code != 200):
        print(f"[-] Response: {res.status_code}, {url}, {res.text}")
        exit(1)

    res_body = res.json()
    sps.extend(res_body["value"])
    print(f"[+] Response: {res.status_code}, Service Principals: {len(sps)}")
    if ("@odata.nextLink" in res_body):
        return get_sps(sps, res_body["@odata.nextLink"])
    else:
        return sps
        
def get_reply_urls_from_azuread(app_id):
    headers = {
        "Authorization": f"Bearer {token_azad}",
        "Content-Type": "application/json"
    }
    url_azad_reply_url = f"https://graph.windows.net/{tenant_id}/applicationRefs/{app_id}?api-version=1.61-internal"
    res = get(url_azad_reply_url, headers=headers)
    res_body = res.json()
    if (res.status_code == 200 and res_body["replyUrls"]):
        return res_body["replyUrls"], res_body["displayName"]
    return "",""

def is_available_query(domain, resource_type):
    headers = { 
        "Authorization": f"Bearer {token_arm}",
        "Content-Type": "application/json"
    }
    url_available = "https://management.azure.com"
    url_available_subs = f"{url_available}/subscriptions/{subscription_id}"

    match resource_type:
        # App Services > Create > Web App
        case "azurewebsites.net":
            post_body = {
                "name": domain.replace(".azurewebsites.net", ""),
                "type": "Microsoft.Web/sites"
            }
            url_available = (
                f"{url_available_subs}/providers/Microsoft.Web/checkNameAvailability?api-version=2019-08-01")
                
        # Front Door and CDN Profiles > Create > (Explore other offerings and Azure CDN Standard from Microsoft (classic)) >
        # > Create a new CDN endpoint
        case "azureedge.net":
            post_body = {
                "name": domain.replace(".azureedge.net", ""),
                "type": "microsoft.cdn/profiles/endpoints"
            }
            url_available = (
                f"{url_available_subs}/providers/microsoft.cdn/checkNameAvailability?api-version=2023-05-01")
                
        # Traffic Manager > Create
        case "trafficmanager.net":
            post_body = {
                "name": domain.replace(".trafficmanager.net", ""),
                "type": "Microsoft.Network/trafficManagerProfiles"
            }
            url_available = (
                f"{url_available_subs}/providers/Microsoft.Network/checkTrafficManagerNameAvailabilityV2?api-version=2022-04-01")
                
        # Front Door and CDN Profiles > Create > (Explore other offerings and Azure Front Door (classic)) >
        # > Configuration > + Frontends/domains
        case "azurefd.net":
            post_body = {
                "name": domain.replace(".azurefd.net", ""),
                "type": "Microsoft.Network/frontdoors"
            }
            url_available = (
                f"{url_available}/providers/Microsoft.Network/checkFrontdoorNameAvailability?api-version=2020-05-01")

        # Storage Accounts > Create > (Go to resource) > Container > Create Container > Go to Container > Properties
        case "blob.core.windows.net":
            post_body = {
                "name": domain.replace(".blob.core.windows.net", ""),
                "type": "Microsoft.Storage/storageAccounts"
            }
            url_available = (
                f"{url_available_subs}/providers/Microsoft.Storage/checkNameAvailability?api-version=2019-06-01")

        # Storage Accounts > Create > (Go to resource) > Static website > Enable and Save
        # Note: depends on region, subdomain added like: dsdfsdfsf13.z6.web.core.windows.net (Static website)
        case "web.core.windows.net":
            domain = domain.replace(".web.core.windows.net", "")
            domain = re.sub('\.[a-z][0-9]', "", domain)
            post_body = {
                "name": domain,
                "type": "Microsoft.Storage/storageAccounts"
            }
            url_available = (
                f"{url_available_subs}/providers/Microsoft.Storage/checkNameAvailability?api-version=2019-06-01")

        # Api Management Service > Create (Follow wizard, wait like 15 minutes for the resource to create) > 
        # Go to resource > APIs > Add HTTP (Define new API)
        case "azure-api.net":
            post_body = {
                "name": domain.replace(".azure-api.net", ""),
                "type": "Microsoft.ApiManagement/service"
            }
            url_available = (
                f"{url_available_subs}/providers/Microsoft.ApiManagement/checkNameAvailability?api-version=2022-08-01")

        case _:
            print(f"[-] No method to check availability for {resource_type}, weird")
            return False

    print(f"[*] Checking availability for {domain}: ", end="")
    res = post(url_available, data=json.dumps(post_body), headers=headers)
    if (res.status_code != 200):
        print("not 200, weird")
        return False
    res_body = res.json()
    if("nameAvailability" in res_body and not (res_body["nameAvailability"] == "Available")):
        print("not available")
        return False
    elif("nameAvailable" in res_body and not res_body["nameAvailable"]):
        print("not available")
        return False
    print("Available!")
    return True
    
def is_available_batch(domain, resource_type):
    headers = { 
        "Authorization": f"Bearer {token_arm}",
        "Content-Type": "application/json"
    }
    url_available = "https://management.azure.com/batch?api-version=2020-06-01"
    
    match resource_type:
        # App Services > Create > Web App
        case "cloudapp.azure.com":
            sub_domain = domain.replace(".cloudapp.azure.com", "")
            zone = sub_domain.split(".")[1]
            sub_domain2 = sub_domain.split(".")[0]
            post_body = {
                "requests": [{
                    "httpMethod": "GET",
                    "url": f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/locations/{zone}/CheckDnsNameAvailability?domainNameLabel={sub_domain2}&api-version=2017-09-01"
                }]
            }
        case "cloudapp.net":
            post_body = {
                "requests": [{
                    "content": {
                        "name": domain.replace(".cloudapp.net", "")
                    },
                    "httpMethod": "POST",
                    "url": f"/subscriptions/{subscription_id}/providers/Microsoft.ClassicCompute/checkDomainNameAvailability?api-version=2015-06-01"
                }]
            }

    print(f"[*] Checking availability for {domain}: ", end="")
    res = post(url_available, data=json.dumps(post_body), headers=headers)
    if (res.status_code != 200):
        print("not 200, weird")
        return False
    res_body = res.json()

    content = res_body["responses"][0]["content"]
    if("available" in content and content["available"]):
        print("Available!")
        return True
    print("not available")
    return False

def is_domain_in_takeover_list(domain):
    takeover_list = ["file.core.windows.net","azurecontainer.io","database.windows.net","azuredatalakestore.net","search.windows.net","azurecr.io","redis.cache.windows.net","servicebus.windows.net",".cloudfront.net",".s3-website",".s3.amazonaws.com","w.amazonaws.com","1.amazonaws.com","2.amazonaws.com","s3-external","s3-accelerate.amazonaws.com",".herokuapp.com",".herokudns.com",".wordpress.com",".pantheonsite.io","domains.tumblr.com",".zendesk.com",".github.io",".global.fastly.net",".helpjuice.com",".helpscoutdocs.com",".ghost.io","cargocollective.com","redirect.feedpress.me",".myshopify.com",".statuspage.io",".uservoice.com",".surge.sh",".bitbucket.io","custom.intercom.help","proxy.webflow.com","landing.subscribepage.com","endpoint.mykajabi.com",".teamwork.com",".thinkific.com","clientaccess.tave.com","wishpond.com",".aftership.com","ideas.aha.io","domains.tictail.com","cname.mendix.net",".bcvp0rtal.com",".brightcovegallery.com",".gallery.video",".bigcartel.com",".activehosted.com",".createsend.com",".acquia-test.co",".proposify.biz","simplebooklet.com",".gr8.com",".vendecommerce."]

    for i in takeover_list:
        if(i in domain):
            return True
    return False

def domain_exists(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False
    except:
        print(f"[-] Not socket.error, weird error trying to resolve the domain for: {domain}")
        return True

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False
    except:
        print(f"[-] Not ValueError, weird error trying to parse the IP: {ip}")
        return False

def print_vuln_app(type, sp, reply_url, resource, scope):
    if(resource == "00000003-0000-0000-c000-000000000000"):
        resource = "Microsoft Graph"
    print(
        f"[+] Found vulnerable reply URL:\n"
        f"      Type: {type}\n"
        f"      Display name: {sp['appDisplayName']}\n"
        f"      Appid: {sp['appId']}\n"
        f"      Reply URL: {reply_url}\n"
        f"      Token resource: {resource}\n"
        f"      Token scope: {scope}\n"
    )

def give_consent_user(res):
    print("[*] Automatically giving user consent: ", end="")
    # get config within the response
    tree = html.fromstring(res.content.decode(res.encoding))
    config = tree.xpath('/html/head/script')[0].text_content()
    config = config[20:-7] # nasty //<![CDATA[ before and after the json
    config = json.loads(config)
    # https://login.microsoftonline.com/{tenant_id}/Consent/Set
    url = f"https://login.microsoftonline.com{config['urlPost']}"
    post_token = {
        "acceptConsent": "true", 
        "ctx": config['sCtx'],
        "flowToken": config['sFT'],
        "canary": config['canary'],
    }
    res = sess_user_ro.post(url, data=post_token, allow_redirects=False)
    return res

def get_error_res(res):
    if (
        (res.status_code == 302 or res.status_code == 200) and
        "AADSTS90095" in res.text
        ):
        print("Maybe, can request admin consent")
        return "needsConsentAdmin"

    if (
        (res.status_code == 302 or res.status_code == 200) and
        "AADSTS90094" in res.text
        ):
        print("Maybe, needs admin consent")
        return "needsConsentAdmin"

    if (
        (res.status_code == 302 or res.status_code == 200) and
        "arrScopes" in res.text # No error code for this
        ):
        print("Maybe, needs user consent")
        return "needsConsentUser"

    if (
        (res.status_code == 302 or res.status_code == 200) and
        "AADSTS65002" in res.text
        ):
        print("Maybe, first party app and resource needs preauthorization")
        return "needsAuthFirstParty"

    if (
        (res.status_code == 302 or res.status_code == 200) and
        "AADSTS650053" in res.text
        ):
        print("Maybe, scope not valid")
        return "needsDifferentScope"

    if (
        (res.status_code == 302 or res.status_code == 200) and
        "AADSTS650057" in res.text
        ):
        print("Maybe, resource not valid")
        return "needsDifferentScope"

    if (
        (res.status_code == 302 or res.status_code == 200) and
        "AADSTS650056" in res.text
        ):
        # Possible the app needs admin consent, but not even admins will get the option during the login flow
        print("Maybe, missconfigured application")
        return "needsDifferentScope"

    if (
        (res.status_code == 302 or res.status_code == 200) and
        "AADSTS500117" in res.text
        ):
        print("NO, reply url needs https")
        return "otherError"

    if (
        (res.status_code == 302 or res.status_code == 200) and
        "AADSTS700016" in res.text
        ):
        print("NO, app not in tenant")
        return "otherError"
    
    if (
        (res.status_code == 302 or res.status_code == 200) and
        "AADSTS650058" in res.text
        ):
        print("NO, app needs access to a service that's not enabled or subscribed in the tenant")
        return "otherError"
     
    if (
        (res.status_code == 302 or res.status_code == 200) and
        "AADSTS650052" in res.text
        ):
        print("NO, app depends on service whose SP is not available in the tenant")
        return "otherError"
 
    if (
        (res.status_code == 302 or res.status_code == 200) and
        "AADSTS700051" in res.text
        ):
        print("NO, response_type 'token' not enabled, implicing grant disabled")
        return "otherError"
    
    if (
        (res.status_code == 302 or res.status_code == 200) and
        "AADSTS50011" in res.text
        ):
        print("NO, reply url not found")
        return "otherError"

    if (res.status_code == 400 and "AADSTS9002326" in res.text):
        print("NO, invalid request, not a SPA")
        return "otherError"

    if(res.status_code == 401 and "AADSTS7000218" in res.text):
        print("NO, invalid client, not Desktop client, is Web without impl. grant")
        return "otherError"

    return False

def try_implicit_flow(get_params_authorize, sp, reply_url, auto_consent_user=False):
    get_params_authorize["response_type"] = "token"
    get_params_authorize["response_mode"] = "fragment"
    url_authorize = f"{url_authorize_base}?{urlencode(get_params_authorize)}"

    print(f"[*] Authorize request, Implicit: ", end='')
    res = sess_user_ro.get(url_authorize, allow_redirects=False)

    error = get_error_res(res)
    if(isinstance(error, str)):
        if(auto_consent_user and "needsConsentUser" in error):
            res = give_consent_user(res)
            if(get_error_res(res)):
                return False
        else:
            return False

    if (not res.status_code == 302):
        print(f"No redirect, weird response, next flow")
        return False

    url_location = urlparse(res.headers["Location"])
    fragment = parse_qs(url_location.fragment)

    if (not "scope" in fragment):
        print(f"No scope in res, weird response, next flow")
        return False

    print("YES!")
    print_vuln_app("Web Client - Implicit Grant", sp, reply_url,
        "resource not returned in the response for web implicit flows", fragment["scope"])
    return True

def try_spa_flow(post_token, sp, reply_url):
    print(f"[*] Token request, SPA (origin): ", end='')
    res = sess_user_ro.post(url_token_base, data=post_token, headers={"Origin": "aaa"})

    if(get_error_res(res)):
        return False

    res_body = res.json()
    if (not "scope" in res_body):
        print("Weird response, next flow")
        return False

    print("YES!")
    print_vuln_app("SPA", sp, reply_url, res_body["resource"], res_body["scope"])
    return True
    
def try_desktop_flow(post_token, sp, reply_url):
    print(f"[*] Token request, Desktop Client (no origin): ", end='')
    res = sess_user_ro.post(url_token_base, data=post_token)

    if(get_error_res(res)):
        return False

    res_body = res.json()
    if (not "scope" in res_body):
        print("Weird response, next flow")
        return False

    print("YES!")
    print_vuln_app("Desktop Client", sp, reply_url, res_body["resource"], res_body["scope"])
    return True

def try_non_implicit_flow(get_params_authorize, sp, reply_url, auto_consent_user=False):
    get_params_authorize["response_type"] = "code"
    get_params_authorize["response_mode"] = "query"
    url_authorize = f"{url_authorize_base}?{urlencode(get_params_authorize)}"
    print(f"[*] Authorize request, SPA: ", end='')
    res = sess_user_ro.get(url_authorize, allow_redirects=False)

    error = get_error_res(res)
    if(isinstance(error, str)):
        if(auto_consent_user and "needsConsentUser" in error):
            res = give_consent_user(res)
            if(get_error_res(res)):
                return False
        else:
            return False
    

    if (not res.status_code == 302):
        print(f"No redirect, weird response, next flow")
        return False
        
    url_location = urlparse(res.headers["Location"])
    query = parse_qs(url_location.query)
    
    if (not "code" in query):
        print(f"No code in res, weird response, next flow")
        return False

    print("Auth code found")
    auth_code = query["code"][0]

    post_token = {
        "client_id": sp["appId"],
        "redirect_uri": reply_url,

        "grant_type": "authorization_code",
        "code": auth_code,

        "code_verifier": "aWiBCBNOF4xzGOCjmTA0IdQdSXj4lbS9oNiywvRYIAM"
    }

    if(try_spa_flow(post_token, sp, reply_url)):
        return True

    if(try_desktop_flow(post_token, sp, reply_url)):
        return True
    
    return False


parser = argparse.ArgumentParser(description='Reply URL Brute')
parser.add_argument('--appId', type=str, required=False, help='Specify an App ID to check')
parser.add_argument('--auto-consent-user', action='store_true', required=False, help='Automatically accept consent for MS graph user.read to improve results fidelity')
parser.add_argument('--scope', type=str, required=False, help='Specify the scope to check during the scope brute force step')
parser.add_argument('--scope-list', type=str, required=False, help='Specify the path to file which contains a list of scopes to check during the scope brute force step')
args = parser.parse_args()

    
# Load config from YAML
file_config = "config.yaml"
script_directory = os.path.dirname(os.path.abspath(sys.argv[0]))
file_config_fullpath = f"{script_directory}/{file_config}"
print(f"[*] Loading tenant informacion and cookies from config.yaml file: {file_config_fullpath}")
with open(file_config_fullpath, "r") as yaml_config:
    yaml_data = yaml.safe_load(yaml_config)

tenant_id = yaml_data["tenant_id"]
subscription_id = yaml_data["subscription_id"]
token_user_ro = yaml_data["token_user_ro"]

print(f"[*] Tenand ID: {tenant_id}")
print(f"[*] Subscription ID: {subscription_id}")

# constants
url_authorize_base = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
url_token_base = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"

# Create sessions with each token, ESTSAUTHPERSISTENT is refreshed after every request
sess_user_ro = Session()
sess_user_ro.cookies.set("ESTSAUTHPERSISTENT", token_user_ro, domain="login.microsoftonline.com")


print("\nSTEP: Get tokens for MS Graph and AAD")
token_ms = get_token(
    sess_user_ro,
    "1b730954-1685-4b74-9bfd-dac224a7b894", # Azure Active Directory PowerShell, scope, reply_url
    "https://graph.microsoft.com/Directory.AccessAsUser.All",
    "https://login.microsoftonline.com/common/oauth2/nativeclient")
token_azad = get_token(
    sess_user_ro,
    "1b730954-1685-4b74-9bfd-dac224a7b894", # Azure Active Directory PowerShell, scope, reply_url
    "https://graph.windows.net/user_impersonation",
    "https://login.microsoftonline.com/common/oauth2/nativeclient")

if(not args.appId):
    print("\nSTEP: Get SPs from tenant")
    sps = get_sps()
    print(f"[*] SP in tenant: {len(sps)}")

    appIds_tenant = []
    for sp in sps:
        appIds_tenant.append(sp["appId"])

if (args.appId):
    print("")
    print("STEP: Single AppId mode")

    print("[*] Quering AppId")
    sps = get_sps(appId=args.appId)
    if(not sps):
        print(f"[-] AppId was not present in the tenant, setting appIds_error so we can check in AZAD.")
        appIds_error = [args.appId]

if("sps" in globals() and sps):
    print("")
    print("STEP: Query reply URLs via Windows Graph")
    for sp in sps:
        reply_url_before = len(sp['replyUrls'])
        reply_url_azad,_ = get_reply_urls_from_azuread(sp["appId"])
        if reply_url_azad:
            sp["replyUrls"] += reply_url_azad
            sp["replyUrls"] = list(set(sp["replyUrls"]))
        reply_url_after = len(sp["replyUrls"])
        diff = reply_url_after - reply_url_before
        print(f"[*] Reply URLs from Windows Graph, SP: {sp['appDisplayName']}: +{diff}")

if("appIds_error" in globals()):
    # Check AppIds errors have URLs from AZAD
    print("")
    print("STEP: Query reply URLs via Windows Graph for AppIds that were not added to the tenant")
    print(f"[*] Total AppIds which were not added to the tenant: {len(appIds_error)}")
    for app_id in appIds_error:
        reply_url_azad, displayName = get_reply_urls_from_azuread(app_id)
        if reply_url_azad:
            print(f"[*] Found reply URLs for errored SP: {displayName}: {len(reply_url_azad)}")
            sps.append({
                "id": None,
                "appId": app_id,
                "appDisplayName": displayName,
                "replyUrls": reply_url_azad
            })
    if(sps):
        print(f"[*] SP in memory after Windows Graph reply URL query: {len(sps)}")
    else:
        print("[-] No SPs in memory, exiting")
        exit(1)

if(args.appId):
    sp = sps[0]
    print("")
    print(f"RECAP: The appId could be found:")
    print(f"[*] {sp['appDisplayName']}, {sp['appId']}, replyUrls:")
    for replyUrl in sp["replyUrls"]:
        print(f"    {replyUrl}")


print("")
print("STEP: Get tokens for ARM")
token_arm = get_token(
    sess_user_ro,
    "1950a258-227b-4e31-a9cf-717495945fc2", # Microsoft Azure PowerShell
    "https://management.azure.com/.default",
    "http://localhost/")

print("")
print("STEP: Starting DNS resolution of reply URLs")
sps_reply_url_yes = []
sps_reply_url_no = []
for sp in sps:
    reply_urls_missing_yes = []
    reply_urls_missing_no = []
    for reply_url in sp["replyUrls"]:
        domain = urlparse(reply_url).netloc

        # Discard registered domains
        if(domain_exists(domain)):
            continue

        # Discard non http or non https urls
        if(not ("http://" in reply_url or "https://" in reply_url)):
            continue

        # Discard localhost or private IPs
        if("localhost:" in domain or "localhost/" in domain or is_private_ip(domain.split(':')[0])):
            continue

        if (
            ("azurewebsites.net" in reply_url and is_available_query(domain, "azurewebsites.net")) or
            ("azureedge.net" in reply_url and is_available_query(domain, "azureedge.net")) or
            ("trafficmanager.net" in reply_url and is_available_query(domain, "trafficmanager.net")) or
            ("blob.core.windows.net" in reply_url and is_available_query(domain, "blob.core.windows.net")) or
            ("web.core.windows.net" in reply_url and is_available_query(domain, "web.core.windows.net")) or
            ("azure-api.net" in reply_url and is_available_query(domain, "azure-api.net")) or
            (
                "azurefd.net" in reply_url and 
                # Filter our urls like: aaa-byf4hrc7eqe3hdbg.a03.azurefd.net (can't take over)
                not bool(re.search('\.[a-z][0-9]{2}\.azurefd.net', reply_url)) and
                is_available_query(domain, "azurefd.net")
            ) or
            ("cloudapp.net" in reply_url and is_available_batch(domain, "cloudapp.net")) or
            ("cloudapp.azure.com" in reply_url and is_available_batch(domain, "cloudapp.azure.com"))
            ):
            print(f"[+] Domain not found, take over: Yes,   SP: {sp['appDisplayName']}, {reply_url}")
            reply_urls_missing_yes.append(reply_url)
            continue
            
        if(is_domain_in_takeover_list(domain)):
            print(f"[+] Domain not found, take over: Maybe, SP: {sp['appDisplayName']}, {reply_url}")
            reply_urls_missing_yes.append(reply_url)
            continue
        
        print(f"[*] Domain not found, take over: No,    SP: {sp['appDisplayName']}, {reply_url}")
        reply_urls_missing_no.append(reply_url)

    if(reply_urls_missing_yes):
        sps_reply_url_yes.append({
            "id": sp["id"],
            "appId": sp["appId"],
            "appDisplayName": sp["appDisplayName"],
            "replyUrlsMissing": reply_urls_missing_yes
        })
    elif(reply_urls_missing_no):
        sps_reply_url_no.append({
            "id": sp["id"],
            "appId": sp["appId"],
            "appDisplayName": sp["appDisplayName"],
            "replyUrlsMissing": reply_urls_missing_no
        })       
print(f"[*] SP with missing reply URLs + take over (Yes, Maybe): {len(sps_reply_url_yes)}")
print(f"[*] SP with missing reply URLs but no take over: {len(sps_reply_url_no)}, this won't be checked")

print("")
print("STEP: Starting flow bruteforce")

# Find out which reply url return token
sps_reply_url_vuln = []
for sp in sps_reply_url_yes:
    reply_urls_vuln = []
    vuln_implicit = ""
    vuln_non_implicit = ""
    for reply_url in sp["replyUrlsMissing"]:
        print(f"[*] {sp['appDisplayName']}, {reply_url}, scope: https://graph.microsoft.com/User.Read")

        # Build authorize URL
        get_params_authorize = {
            "client_id": sp["appId"],
            "redirect_uri": reply_url,
            "scope": "https://graph.microsoft.com/User.Read",
            "code_challenge": "r28qDfmtnCyRedcGckQkfvFQHcBZA3_vLRPxWm8UWF4",
            "code_challenge_method": "S256",
            "nonce": "aaaaa"
        }

        # Implicit flow
        if (try_implicit_flow(get_params_authorize, sp, reply_url, args.auto_consent_user)):
            reply_urls_vuln.append(reply_url)
            vuln_implicit = reply_url
            continue

        # SPA/Desktop flow
        if (try_non_implicit_flow(get_params_authorize, sp, reply_url, args.auto_consent_user)):
            reply_urls_vuln.append(reply_url)
            vuln_non_implicit = reply_url
            continue

    if (reply_urls_vuln):
        sp["replyUrlsVuln"] = reply_urls_vuln
        sp["vulnImplicit"] = vuln_implicit
        sp["vulnNonImplicit"] = vuln_non_implicit
        sps_reply_url_vuln.append(sp)

print(f"[*] Total vulnerable Apps: {len(sps_reply_url_vuln)}")
if (len(sps_reply_url_vuln) == 0):
    print("[*] No vulnerable reply urls no bruteforce resource necessary")
    exit(0)


print("")
print("STEP: Starting scope bruteforcing")

scopes = [
    "https://graph.microsoft.com/User.Read",
    "https://graph.microsoft.com/Directory.ReadWrite.All",
    "https://graph.windows.net/user_impersonation",
    "https://graph.windows.net/Directory.AccessAsUser.All",
    "https://graph.windows.net/Directory.ReadWrite.All",
    "https://microsoft.sharepoint.com/AllSites.FullControl",
    "https://microsoft.sharepoint.com/AllSites.Manage",
    "https://app.vssps.visualstudio.com/user_impersonation",
    "https://auth.msft.communication.azure.com/Teams.ManageChats",
    "https://vault.azure.net/user_impersonation",
    "https://management.azure.com/user_impersonation"
]
if(not args.scope and not args.scope_list):
    print("[*] Using default scope list")

if(args.scope):
    scopes = [args.scope]
    print(f"[*] Using scope passed in the CLI argument list: {args.scope}")

if(args.scope_list):
    with open(args.scope_list, 'r') as scope_list:
        scopes = scope_list.readlines()
    print(f"[*] Scopes loaded from file: {args.scope_list}")

print(f"[*] Scopes to bruteforce: {len(scopes)}")

sps_reply_url_vuln_scopes = []
for sp in sps_reply_url_vuln:
    # Build authorize URL
    get_params_authorize = {
        "client_id": sp["appId"],
        "code_challenge": "r28qDfmtnCyRedcGckQkfvFQHcBZA3_vLRPxWm8UWF4",
        "code_challenge_method": "S256",
        "nonce": "aaaaa"
    }
    scopes_valid = []
    if(sp["vulnImplicit"] and not sp["vulnNonImplicit"]):
        # Web - Implicit flow only
        reply_url = sp["vulnImplicit"]
        get_params_authorize["redirect_uri"] = reply_url
        for scope in scopes:
            print(f"[*] SP: {sp['appDisplayName']}, {reply_url} (Web), scope: {scope}")
            get_params_authorize["scope"] = scope
            if(try_implicit_flow(get_params_authorize, sp, reply_url)):
                scopes_valid.append({
                    "scope": scope,
                    "consent": "Granted!"
                })

    else:
        # SPA/Desktop flow only or if web also available also spa
        reply_url = sp["vulnNonImplicit"]
        get_params_authorize["redirect_uri"] = reply_url
        for scope in scopes:
            print(f"[*] SP: {sp['appDisplayName']}, {reply_url} (SPA/Desktop), scope: {scope}")
            get_params_authorize["scope"] = scope
            if(try_non_implicit_flow(get_params_authorize, sp, reply_url)):
                scopes_valid.append({
                    "scope": scope,
                    "consent": "Granted!"
                })

    if(scopes_valid):
        sp["scopesValid"] = scopes_valid
        sps_reply_url_vuln_scopes.append(sp)


print(f"[*] Final total vulnerable Apps: {len(sps_reply_url_vuln_scopes)}")
if(len(sps_reply_url_vuln_scopes) == 0):
    print("[*] No vulnerable applications found")
    exit(0)

# Report:
print("\n")
print("REPORTING: Reporting SP - reply - scopes")
if(args.auto_consent_user):
    print("[*] Automatically grant consents enabled")
for sp in sps_reply_url_vuln_scopes:
    if(sp["scopesValid"][0] == "scopeNotFound"):
        print(f"[*] SP: {sp['appDisplayName']}, app vulnerable but scope not found, consider additional bruteforcing")
    for scope in sp["scopesValid"]:
        print(f"[*] SP: {sp['appDisplayName']}, scope: {scope['scope']}, consent: {scope['consent']}")
    for reply_url in sp["replyUrlsVuln"]:
        print(f"[*] SP: {sp['appDisplayName']}, Reply Url: {reply_url}")
    print("")


# Saving new cookies to yaml file
print("[+] Saving cookies to config.yaml")
def get_sess_token(session):
    for cookie in session.cookies:
        if (cookie.name == "ESTSAUTHPERSISTENT" and cookie.secure):
            return cookie.value
            
yaml_data["token_user_ro"] = get_sess_token(sess_user_ro)

with open(file_config_fullpath, 'w') as yaml_file:
    yaml.dump(yaml_data, yaml_file)