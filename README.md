# bloodhound-ce-api
This repository is used for certain tests with the Bloodhound Community Edition API.

# Prerequisites
In order for the scripts to work, you need a Bloodhound Community Edition up and running (https://support.bloodhoundenterprise.io/hc/en-us/article_attachments/24776286827547). Furthermore, there needs to be an API access configured: https://support.bloodhoundenterprise.io/hc/en-us/articles/11311053342619-Working-with-the-BloodHound-API
The API Key aswell as the Key ID need to be placed inside the python script. 

## Sending Bloodhound Query Results via Post Request
Using the "any_query_post.py" script, you can run any query via the Bloodhound API, the results will be sent via post request on "http://localhost:333". If you want to send the data to another location, modify line 377. For testing purposes on the localhost, open Netcat like this: `nc -l -p 333` to receive the data. 
Flags:
- -c the query you want to run in Bloodhound

### Usage
`python any_query_post.py -c "MATCH (n:User) WHERE n.hasspn=true RETURN n"`

## Developed by: HanseSecure
- Twitter: [HanseSecure](https://twitter.com/HanseSecure)