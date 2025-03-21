import json
import random
import string
import time
import urllib3
import click
import requests
import yaml


import colorlog

handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter('%(log_color)s%(levelname)s:%(name)s:%(message)s'))

logging = colorlog.getLogger('deploy-test')
logging.addHandler(handler)
logging.setLevel('INFO')

MAX_TRIES = 15

urllib3.disable_warnings()

product_yaml = """
info:
  version: 2.0.0
  title: 'Publish Test Product'
  name: publish-test-product
apis:
  publish-test:
    name: publish-test:1.0.1
gateways:
  - datapower-api-gateway
plans:
  default-plan:
    title: Default Plan
    description: Default Plan
    approval: false
    rate-limits:
      default:
        value: 100/1hour
product: 1.0.0
visibility:
  view:
    enabled: true
    type: public
    tags: []
    orgs: []
  subscribe:
    enabled: true
    type: authenticated
    tags: []
    orgs: []
"""


def get_token(hostname, api_key, username, password, 
              realm, client_id, client_secret, verify=True):
    """ Get token from API Manager """
    token_request = None
    if api_key:
        # Use API Key as preferred approach
        token_request = {
          "client_id": client_id,
          "client_secret": client_secret,
          "api_key": api_key,
          "grant_type": "api_key"
        }
    elif password:
        # Username and password
        token_request = {
          "client_id": client_id,
          "client_secret": client_secret,
          "username": username,
          "password": password,
          "realm": realm,
          "grant_type": "password"
        }
    else:
        logging.critical("No authentication method to use")
    response = requests.post(
      url="https://{}/api/token".format(hostname),
      headers={
        "Accept": "application/json",
        "Content-Type": "application/json",
      },
      data=json.dumps(token_request),
      verify=verify
    )
    if response.status_code == 200: 
        logging.info('Retrieve token - status: {status_code}'.format(
          status_code=response.status_code))
        return response.json().get('access_token', None)
    else: 
        logging.error('Retrieve token - status: {status_code}, response: {text}'.format(
          status_code=response.status_code, text=response.text))
        return None


def publish_api(hostname, token, organisation, catalog, eyecatcher, filename, verify=True):
    """ publish the API replacing 'RESPONSE' with the eyecatcher """
    with open("api-deploy-check/" + filename, 'r') as openapi_file:
        openapi_yaml = "\n".join(openapi_file.readlines())
    openapi = yaml.safe_load(openapi_yaml)
    api_name = "{x-ibm-name}:{version}".format(**(openapi['info']))
    api_definition = openapi_yaml.replace('RESPONSE', eyecatcher)
    product_definition = product_yaml.replace('publish-test:1.0.1', api_name)
    logging.debug(api_definition)
    files = {
      'product': ('product.yaml', product_definition, 'application/yaml'),
      'openapi': ('openapi.yaml', api_definition, 'application/yaml')
    }

    response = requests.post(
      url="https://{}/api/catalogs/{}/{}/publish".format(
        hostname, organisation, catalog),
      headers={
        "Authorization": "Bearer {}".format(token),
        "Accept": "application/json"
      },
      files=files,
      verify=verify
    )
    logging.info('Publish publish-test API - status: {status_code}'.format(
      status_code=response.status_code))
    if 'updated_at' in response.json():
        logging.info('Publish response shows updated at: {updated_at}'.format(
          **response.json()))
        return openapi['info']['x-ibm-name']
    else:
        logging.error(response.content)
        exit(8)


def get_analytics_records(
        hostname, token,
        organisation, catalog,
        analytics_service, api_name, verify):
    """ Call the APIC Analytics API to find the record for the transaction """

    response = requests.get(
        url="https://{}/analytics/{}/catalogs/{}/{}/events?api_name={}&timeframe=last15minutes".format(
          hostname, analytics_service, organisation, catalog, api_name),
        headers={
            "Authorization": "Bearer {}".format(token),
            "Accept": "application/json"
        },
        verify=verify
    )
    # TODO handle errors
    return response.json()


def get_catalog_details(hostname, token, org, catalog, verify):
    """ Get the base url for APIs in this catalog """
    response = requests.get(
        url="https://{}/api/catalogs/{}/{}/configured-gateway-services".format(
          hostname, org, catalog),
        headers={
            "Authorization": "Bearer {}".format(token),
            "Accept": "application/json"
        },
        verify=verify
    )
    # TODO handle errors
    cgs = response.json()
    if cgs["total_results"] > 1:
        logging.warn("Catalog has multiple gateway services defined, using {}".format(
          cgs['results'][0]["title"]))
    details = {
      "analytics": cgs['results'][0]["analytics_service_url"].split('/')[-1],
      "api_base": cgs['results'][0]['catalog_base']
    }
    return details

@click.command()
@click.option('--server', '-s', required=True, help='Platform API hostname')
@click.option('--org', '-o', required=True, help='Organisation')
@click.option('--catalog', '-c', required=True, help='Catalog')
@click.option('--verify/--no-verify', required=True, help='Verify certificates')
@click.option('--apikey', '-a', required=False, help='API Key', envvar='APIC_API_KEY')
@click.option('--username', '-u', required=False, help='Username', envvar='APIC_USERNAME')
@click.option('--password', '-p', required=False, help='Password', envvar='APIC_PASSWORD')
@click.option('--realm', '-r', required=False, help='Realm', default='provider/default-idp-2', envvar='APIC_REALM')
@click.option('--filename', '-f', required=False, help='API Definition to use', default='set-variable.yaml')
@click.option('--client_id', '-i', default="599b7aef-8841-4ee2-88a0-84d49c4d6ff2", envvar='CLIENT_ID', help='client id required to retrieve a bearer token from apim')
@click.option('--client_secret', '-i', default="0ea28423-e73b-47d4-b40e-ddb45c48bb0c", envvar='CLIENT_SECRET', help='client secret required to retrieve a bearer token from apim')
def deploy_test_cli(
  server=None,
  apikey=None,
  username=None,
  password=None,
  realm=None,
  org=None,
  catalog="sandbox",
  verify=True,
  client_id=None,
  client_secret=None,
  filename='set-variable.yaml'):
    """ CLI wrapper for deploy test"""
    deploy_test(
        server, verify,
        apikey,
        username, password, realm,
        org, catalog,
        client_id, client_secret,
        filename)


def deploy_test(
  server=None, verify=True,
  apikey=None,
  username=None, password=None, realm=None,
  org=None, catalog="sandbox",
  client_id="599b7aef-8841-4ee2-88a0-84d49c4d6ff2",
  client_secret="0ea28423-e73b-47d4-b40e-ddb45c48bb0c",
  filename='set-variable.yaml'):
    """ deploy an API and test it """
    platform_api_host = server
    # Obtain a bearer token for this user to make further API calls
    token = get_token(platform_api_host, apikey, username, password, realm, client_id, client_secret, verify)

    if token:
        eyecatcher = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(25))
        logging.info("Eyecatcher for API is: {}".format(eyecatcher))
        api_name = publish_api(platform_api_host, token, org, catalog, eyecatcher, filename, verify)
        logging.debug(api_name)

        catalog_details = get_catalog_details(platform_api_host, token, org, catalog, verify)

        api_base_path = "publish-test"
        new_api = "{}/{}".format(catalog_details['api_base'], api_base_path)
        logging.info('Published API URL: {}'.format(new_api))

        attempt = 0
        transaction_id = None
        updated = False
        while attempt < MAX_TRIES:
            attempt += 1
            response = requests.get(
                                    "{}?eyecatcher={}&attempt={}".format(
                                      new_api,
                                      eyecatcher,
                                      attempt), verify=verify)

            if eyecatcher in response.text:
                logging.info('Invoke {} / {}: status: {status_code}, response: {text} - Success!'.format(attempt, MAX_TRIES, status_code=response.status_code, text=response.text[:50]))
                logging.warning("API response matches for {}".format(eyecatcher))
                transaction_id = response.headers['x-global-transaction-id']
                updated = True
                break
            else:
                try:
                    logging.info("Request ID: {x-request-id} GTID: {x-global-transaction-id}, CF-RAY: {CF-RAY}".format(**response.headers))
                except KeyError:
                    logging.info(response.headers)
                logging.warning('Invoke {} / {}: status: {status_code}, response: {text}'.format(attempt, MAX_TRIES, status_code=response.status_code, text=response.text[:50]))
                time.sleep(5) 
        if updated:
            logging.info("API is updated")
            # Now look in Analytics...
            attempt = 0
            found = False
            while attempt < MAX_TRIES:
                events = get_analytics_records(platform_api_host, token, org, catalog, catalog_details['analytics'], api_name, verify)
                for event in events['events']:
                    if event['global_transaction_id'] == transaction_id:
                        logging.info("Matched transaction id ({}) of successful call in analytics".format(transaction_id))
                        logging.info("API response in {time_to_serve_request}ms for {query_string}".format(**event))
                        found = True
                if found:
                    break
                else:
                    logging.warning('Analytics {} / {}: events: {events}'.format(attempt, MAX_TRIES, events=events['total']))
                    time.sleep(5) 
            if not found:
                logging.critical("API record not in analytics after {} seconds".format(MAX_TRIES * 5))
                return 1

        else:
            logging.critical("API not updated after {} seconds".format(MAX_TRIES * 5))
            return 1
    else:
        logging.critical("Unable to retrieve token")
        return 4


if __name__ == '__main__':
    deploy_test_cli()






#@hostname = api-manager.d-j01.apiconnect.dev.automation.ibm.com
#
#GET 'https://{{hostname}}/analytics/5124699d-40ec-40d4-a964-6be04a1988ac/orgs/e5f3e142-f76f-4c94-87b4-e5a2dd159617/events?timeframe=last30days&limit=50&offset=0'
#Accept: application/json
