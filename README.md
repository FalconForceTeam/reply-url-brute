# Reply URL Brute
Tool that looks for unregistered reply URLs of service principals and checks if they can be used in a reply URL hijack attack. Works for local and multitenant applications.

More information about this tool in its blog post [here](TODO).

Tool main steps:
1. **Initialize** variables and request access tokens for Microsoft Graph (graph.microsoft.com), Azure Active Directory Graph (graph.windows.net) and several others.
2. **Request service principals** in the tenant using the Microsoft Graph API.
3. **Enrich service principals'** reply URLs using the undocumented Azure Active Directory Graph.
4. Start **DNS resolution** of all reply URLs; keep the ones that aren't found.
5. Check in **Azure Resource Manager** if the resource to take over the domain is available. More often than not, the resource name that would allow to take over a certain domain is unavailable. I imagine this is due to the fact a developer created the resource, but then left it in a disabled step. Even though writing checks for most of the resources was an awfully time-intensive endeavor, it really helped in bringing down the number of false positives. Shout out to the guys at Stratus Security for collecting a very [comprehensive list of Azure domains take over](https://www.stratussecurity.com/post/azure-subdomain-takeover-guide).
6. **Determine if a given reply URL can be taken advantage of**. Check the blog post linked in the beginning for more details. Optional: consent user scope automatically.
7. Reapply the same process in point 6 but for a **set of different scopes**.
8. Take all the information gathered in the previous points and present it in a human-friendly way.
9. Every time a request to the authorize endpoint is made, Azure returns a new `ESTSAUTHPERSISTENT` cookie. At the end of the enumeration, the script will overwrite the values in the `config.yaml` file, so the cookies are always up to date.

# How to use it
Clone the project and open the `config_doc.yaml`:

```
git clone https://github.com/FalconForceTeam/reply-url-brute
```

You need to provide several pieces of information before running the script for the first time. Set the tenant ID and the subscription ID in the appropriate fields:

```
subscription_id: 4493ad17-...
tenant_id: 2a0002d5-2368-...
...
```

Now, we need to set the `ESTSAUTHPERSISTENT` cookie. To get it, I recommend to open Microsoft Edge, navigate to https://portal.azure.com and log in. When it asks you to stay signed in, click "Yes", so the `ESTSAUTHPERSISTENT` is properly set. Then go to "Settings" > "Cookies and site permissions" > "Manage and delete cookies and site data" > "See all coolies and site data". Expand the domain "microsoftonline.com" and then "login.microsoftonline.com". Then copy the value for the `ESTSAUTHPERSISTENT` cookie.

Some considerations to keep in mind:
- No special rights in Entra ID are required for the user.
- To check for Azure resource availability, the user must have access to a subscription. The easiest way is to provide read-only access to the subscription, but access to any resource should work anyway.
- You could also use the `ESTSAUTH`, but then it's possible you'd get some issues in the long term, since it doesn't last as long.

```
subscription_id: 4493ad17-...
tenant_id: 2a0002d5-2368-...
token_user_ro: 0.AV8AzUIqqYy...
```

Finally, save the file as `config.yaml`.

To run the script against all the service principals available in the tenant, just run it without arguments. Alternatively, you can also use some of the available **CLI arguments**:
- `--appId`: only checks one specific application. Thanks to the undocumented internal Azure Active Directory API, the application doesn't need to be present in the tenant.
- `--auto-consent-user`: Automatically accept consent for `https://graph.microsoft.com/user.read` scope to improve results fidelity.
- `--scope`: by default, there are 11 scopes hardcoded in the script. Pass this option to overwrite them.
- `--scope-list`: you can also pass the path to a file with a list of scopes to check. Every scope must be in a new line.

**Output:**
- The output is similar, regardless if a single application is tested or all the ones present in the tenant. The same is true when it comes to the number of scopes tested.
- Depending on the number of service principals, the script can take a lot of time, but it greatly depends on the number of reply URLs per application and the scopes to test. For example, for a tenant with 1000 service principals and the default scope list, it can take more than 30 minutes.
- The script output is very verbose, skip to the reporting step to have a quick summary of the findings.
- **DNS resolution step**:
    - `No`: an unregistered reply URL has been found, but the domain can't be taken over.
    - `Maybe`: an unregistered reply URL has been found, but there's no method to check whether the resource that would register the domain is available.
    - `Yes`: an unregistered reply URL has been found and the resource is available.
- **Flow and scope brute force step**:
    - `Maybe`: the application asked for consent and therefore it's not sure if the reply URL is vulnerable or not. Consider using `--auto-consent-user`.
    - `YES!`: the application returned access tokens for the given scope.
- **Reporting step**:
    - Summary of all the applications vulnerable to the reply URL hijack that return tokens without asking for consent.
    - If you don't care whether the consent is shown or not, make sure you check the output during the flow brute force step.

```
python reply-url-brute.py --appId 89efd99e-0ec9-4bcf-9e5c-74c31b45f181

[*] Loading tenant informacion and cookies from config.yaml file: config.yaml
[*] Tenand ID: a92a42cd-bf8c-46ba-aa4e-64cbc9e030d9
[*] Subscription ID: 80110e3c-3ec4-4567-b06d-7d47a72562f5

STEP: Get tokens for MS Graph, APP MGMT and AAD
[*] Send Authorize for scope: https://graph.microsoft.com/Directory.AccessAsUser.All
[*] Send Token request for scope: https://graph.microsoft.com/Directory.AccessAsUser.All
[*] Send Authorize for scope: https://graph.windows.net/user_impersonation
[*] Send Token request for scope: https://graph.windows.net/user_impersonation
[*] Send Authorize for scope: https://appmanagement.activedirectory.microsoft.com/user_impersonation
[*] Send Token request for scope: https://appmanagement.activedirectory.microsoft.com/user_impersonation

STEP: Single AppId mode
[*] Quering AppId
[+] Response: 200, Service Principals: 1

STEP: Query reply URLs via Windows Graph
[*] Reply URLs from Windows Graph, SP: app-demo: +0

RECAP: The appId could be found:
[*] app-demo, 89efd99e-0ec9-4bcf-9e5c-74c31b45f181, replyUrls:
    https://localhost
    https://idontexist23843.azurewebsites.net

STEP: Get tokens for ARM
[*] Send Authorize for scope: https://management.azure.com/.default
[*] Send Token request for scope: https://management.azure.com/.default

STEP: Starting DNS resolution of reply URLs
[*] Checking availability for idontexist23843.azurewebsites.net: Available!
[+] Domain not found, take over: Yes,   SP: app-demo, https://idontexist23843.azurewebsites.net
[*] SP with missing reply URLs + take over (Yes, Maybe): 1
[*] SP with missing reply URLs but no take over: 0, this won't be checked

STEP: Starting flow bruteforce
[*] app-demo, https://idontexist23843.azurewebsites.net, scope: https://graph.microsoft.com/User.Read
[*] Authorize request, Web: NO, response_type 'token' not enabled, implicing grant disabled
[*] Authorize request, SPA: Maybe, needs user consent
...
[*] Total vulnerable Apps: 1

STEP: Starting scope bruteforcing
[*] Scopes to bruteforce: 17
[*] SP: app-demo, https://idontexist23843.azurewebsites.net (SPA/Desktop), scope: https://graph.microsoft.com/.default
[*] Authorize request, SPA: Auth code found
[*] Token request, SPA (origin): YES!
[+] Found vulnerable reply URL:
      Type: SPA
      Display name: app-demo
      Appid: 89efd99e-0ec9-4bcf-9e5c-74c31b45f181
      Reply URL: https://idontexist23843.azurewebsites.net
      Token resource: https://graph.microsoft.com
      Token scope: Directory.AccessAsUser.All

[*] SP: app-demo, https://idontexist23843.azurewebsites.net (SPA/Desktop), scope: https://graph.microsoft.com/User.Read
...
[*] Final total vulnerable Apps: 1


REPORTING: Reporting SP - reply - scopes
[*] SP: app-demo, scope: https://graph.microsoft.com/user.read, consent: Granted!
[*] SP: app-demo, scope: https://graph.windows.net/Directory.AccessAsUser.All, consent: Granted!
[*] SP: app-demo, Reply Url: https://idontexist23843.azurewebsites.net

[+] Saving cookies to config.yaml
```

In this example, we see how the `app-demo` has the reply URL `https://idontexist23843.azurewebsites.net` set as a SPA. We also see how the application has defined several OAuth permissions, but most of them require a consent by the user or an admin. However, the scope `https://graph.windows.net/Directory.AccessAsUser.All` has been granted and the application returned tokens for that. Therefore, if we register the `idontexist23843` as a new Azure website, we could impersonate the user in the tenant, just by luring him to follow a link.