import sys
import json
import random
import string
import time
import urllib3
import click
import requests
import yaml
import zipfile
import io
import os

try:
    # Optional support to use colorlog for coloured output 
    import colorlog
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter('%(log_color)s%(message)s'))
    logger = colorlog.getLogger('deploy-test')
    logger.addHandler(handler)
    logger.setLevel('INFO')
except ImportError:
    import logging
    logger = logging.getLogger('deploy-test')
    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)


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
        logger.critical("No authentication method to use")
    response = requests.post(
      url=f"https://{hostname}/api/token",
      headers={
        "Accept": "application/json",
        "Content-Type": "application/json",
      },
      data=json.dumps(token_request),
      verify=verify
    )
    if response.status_code == 200: 
        logger.info('Retrieve token - status: %d',
          response.status_code)
        return response.json().get('access_token', None)

    logger.error('Retrieve token - status: %d, response: %s',
      response.status_code, response.text)
    return None


def publish_api(hostname, token, org, catalog, eyecatcher, filename, verify=True):
    """ publish the API replacing 'RESPONSE' with the eyecatcher """

    # Load the template API to use
    with open("templates/" + filename,
              'r', encoding='utf-8') as openapi_file:
        openapi_yaml = "\n".join(openapi_file.readlines())

    openapi = yaml.safe_load(openapi_yaml)
    api_name = "{x-ibm-name}:{version}".format(**(openapi['info']))

    # Replace RESPONSE with the eyecatcher to spot on update
    api_definition = openapi_yaml.replace('RESPONSE', eyecatcher)

    # Ensure the product points to the right API
    product_definition = product_yaml.replace(
        'publish-test:1.0.1', api_name)

    logger.debug(api_definition)

    # Build the body for the request
    files = {
      'product': ('product.yaml', product_definition, 'application/yaml'),
      'openapi': ('openapi.yaml', api_definition, 'application/yaml')
    }

    response = requests.post(
      url=f"https://{hostname}/api/catalogs/{org}/{catalog}/publish",
      headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
      },
      files=files,
      verify=verify,
      timeout=10
    )
    logger.info('Publish publish-test API - status code: %d', response.status_code)
    if 'updated_at' in response.json():
        logger.info('Publish response shows updated at: %s',
          response.json()['updated_at'])
        return openapi['info']['x-ibm-name']

    logger.error(response.content)
    sys.exit(8)


def publish_api_v12(hostname, token, org, catalog, eyecatcher, verify=True):
    """ publish the v12 API replacing 'RESPONSE' with the eyecatcher """
    
    # Load the v12 API files
    with open("templates/v12/quick-api.yml", 'r', encoding='utf-8') as api_file:
        api_yaml = api_file.read()
    
    # Detect the project name from the resources directory structure
    resources_dir = "templates/v12/resources"
    project_dirs = [d for d in os.listdir(resources_dir)
                   if os.path.isdir(os.path.join(resources_dir, d))]
    
    if not project_dirs:
        logger.error("Could not find project directory in resources/")
        sys.exit(8)
    
    project_name = project_dirs[0]  # Use the first (and should be only) directory
    logger.info("Detected project name from resources directory: %s", project_name)
    
    spec_path = f"templates/v12/resources/{project_name}/quick-api-spec.yml"
    with open(spec_path, 'r', encoding='utf-8') as spec_file:
        spec_yaml = spec_file.read()
    
    # Replace RESPONSE with the eyecatcher in the Set policy
    api_definition = api_yaml.replace('RESPONSE', eyecatcher)
    
    logger.debug(api_definition)
    
    # Parse the YAML to extract API name for return value
    # The v12 format has multiple documents, we need the API document
    docs = list(yaml.safe_load_all(api_definition))
    api_doc = None
    for doc in docs:
        if doc.get('kind') == 'API':
            api_doc = doc
            break
    
    if not api_doc:
        logger.error("Could not find API document in v12 definition")
        sys.exit(8)
    
    api_name = api_doc['metadata']['name']
    
    # Create a zip file in /tmp for investigation
    zip_path = '/tmp/api.zip'
    logger.debug("Creating zip file at: %s", zip_path)

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # Add the main API definition file - must use .yaml extension and project name
        zip_file.writestr(f'{project_name}.yaml', api_definition)
        # Add directory entries (required by APIC)
        zip_file.writestr('resources/', '')
        zip_file.writestr(f'resources/{project_name}/', '')
        # Add the OpenAPI spec file in resources/{project_name}/ directory
        zip_file.writestr(f'resources/{project_name}/quick-api-spec.yml', spec_yaml)
    
    # Get file size for logging
    zip_size = os.path.getsize(zip_path)
    logger.info("Created project zip file at %s with size: %d bytes", zip_path, zip_size)
    
    # List the files in the zip
    with zipfile.ZipFile(zip_path, 'r') as zip_file:
        logger.debug("Zip file contents:")
        for info in zip_file.infolist():
            logger.debug("  %s (%d bytes)", info.filename, info.file_size)
    
    # Open the zip file for reading to send in the request
    with open(zip_path, 'rb') as zip_file:
        zip_buffer = io.BytesIO(zip_file.read())
    
    zip_buffer.seek(0)
    
    logger.debug("Project name (from namespace): %s", project_name)
    logger.debug("Spec location in zip: resources/%s/quick-api-spec.yml", project_name)

    # For v12, we need to publish the API definition as a zip file
    files = {
        'project': ('api.zip', zip_buffer, 'application/zip')
    }
    
    response = requests.post(
        url=f"https://{hostname}/api/catalogs/{org}/{catalog}/publish-project",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        },
        files=files,
        verify=verify,
        timeout=10
    )
    
    logger.info('Publish v12 API - status code: %d', response.status_code)
    logger.info('X-Request-Id: %s', response.headers.get('X-Request-Id', 'Not present'))
    
    if response.status_code in [200, 201]:
        response_data = response.json()
        logger.info('Publish response: %s', response_data)
        
        # Extract gateway endpoint from response
        gateway_endpoint = None
        if 'gateway_endpoints' in response_data['results'][0] and response_data['results'][0]['gateway_endpoints']:
            gateway_endpoint = response_data['results'][0]['gateway_endpoints'][0]
            logger.info('Gateway endpoint from response: %s', gateway_endpoint)
        
        return (api_name, gateway_endpoint)
    
    logger.error('Failed to publish v12 API: %s', response.content)
    logger.error('Response headers: %s', dict(response.headers))
    sys.exit(8)


def get_analytics_records(
        hostname, token,
        org, catalog,
        a7s, api_name, verify):
    """ Call the APIC Analytics API to find the record for the transaction """

    logger.info('Getting analytics records for %s', api_name)
        

    response = requests.get(
        url=f"https://{hostname}/analytics/{a7s}/catalogs/{org}/{catalog}/events?api_name={api_name}&timeframe=last15minutes",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        },
        verify=verify,
        timeout=10
    )
    # TODO handle errors
    return (response.json(), response.headers.get('x-request-id'))


def get_catalog_details(hostname, token, org, catalog, verify):
    """ Get the base url for APIs in this catalog """
    response = requests.get(
        url=f"https://{hostname}/api/catalogs/{org}/{catalog}/configured-gateway-services",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        },
        verify=verify
    )
    # TODO handle errors
    cgs = response.json()
    if cgs["total_results"] > 1:
        logger.warning("Catalog has multiple gateway services defined, using %s",
          cgs['results'][0]["title"])
    details = {
      "analytics": cgs['results'][0]["analytics_service_url"].split('/')[-1],
      "api_base": cgs['results'][0]['catalog_base']
    }
    return details


@click.command()
@click.option('--server', '-s', required=True, help='Platform API hostname')
@click.option('--client_id', default="599b7aef-8841-4ee2-88a0-84d49c4d6ff2",
              envvar='CLIENT_ID',
              help='client id required to retrieve a bearer token')
@click.option('--client_secret', default="0ea28423-e73b-47d4-b40e-ddb45c48bb0c",
              envvar='CLIENT_SECRET',
              help='client secret required to retrieve a bearer token')
@click.option('--org', '-o', required=True, help='Organisation')
@click.option('--catalog', '-c', required=True, help='Catalog')
@click.option('--verify/--no-verify', required=True, default=True,
              help='Verify certificates')
@click.option('--apikey', '-a', required=False, help='API Key',
              envvar='APIC_API_KEY')
@click.option('--username', '-u', required=False, help='Username',
              envvar='APIC_USERNAME')
@click.option('--password', '-p', required=False, hide_input=True, help='Password',
              envvar='APIC_PASSWORD')
@click.option('--realm', '-r', required=False, help='Realm',
              default='provider/default-idp-2', envvar='APIC_REALM')
@click.option('--filename', '-f', required=False, help='API Definition to use',
              default='set-variable.yaml')
@click.option('--v12', is_flag=True, default=False,
              help='Use v12 API publish flow')
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
  filename='set-variable.yaml',
  v12=False):
    """ CLI wrapper for deploy test"""
    sys.exit(deploy_test(
        server, verify,
        apikey,
        username, password, realm,
        org, catalog,
        client_id, client_secret,
        filename, v12))


def deploy_test(
  server=None, verify=True,
  apikey=None,
  username=None, password=None, realm=None,
  org=None, catalog="sandbox",
  client_id="599b7aef-8841-4ee2-88a0-84d49c4d6ff2",
  client_secret="0ea28423-e73b-47d4-b40e-ddb45c48bb0c",
  filename='set-variable.yaml',
  v12=False):
    """ deploy an API and test it """
    platform_api_host = server
    print(server)
    # Obtain a bearer token for this user to make further API calls
    token = get_token(platform_api_host, apikey, username, password, realm, client_id, client_secret, verify)

    if token:
        eyecatcher = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(25))
        logger.info("Eyecatcher for API is: %s", eyecatcher)
        
        gateway_endpoint = None
        if v12:
            api_name, gateway_endpoint = publish_api_v12(platform_api_host, token, org, catalog, eyecatcher, verify)
        else:
            api_name = publish_api(platform_api_host, token, org, catalog, eyecatcher, filename, verify)
        logger.debug(api_name)

        # Get configuration of the catalog (needed for analytics)
        catalog_details = get_catalog_details(platform_api_host, token, org, catalog, verify)
        
        # For v12, use the gateway endpoint from the publish response
        if v12 and gateway_endpoint:
            new_api = gateway_endpoint
            logger.info('Using gateway endpoint from publish response: %s', new_api)
        else:
            # Construct URL from catalog details for non-v12 or fallback
            # Set the API base path based on version
            if v12:
                api_base_path = "quick"  # v12 API name from metadata
            else:
                api_base_path = "publish-test"
            
            new_api = "{}/{}".format(catalog_details['api_base'], api_base_path)
            logger.info('Published API URL: %s', new_api)

        attempt = 0
        updated = False
        x_gtid = None
        while attempt < MAX_TRIES:
            attempt += 1
            try:
                response = requests.get(f"{new_api}?eyecatcher={eyecatcher}&attempt={attempt}",
                                        headers={'X-Global-Transaction-Id': eyecatcher + "-" + str(attempt)},
                                        verify=verify)
                x_gtid = response.headers.get('x-global-transaction-id')
                logger.info(response.headers)
                if eyecatcher in response.text:
                    logger.info('Invoke %d / %d: status: %d, response: %s, GTID: %s - Successful match!',
                        attempt, MAX_TRIES, response.status_code,
                        response.text[:50], x_gtid)
                    logger.info("API response matches for %s", eyecatcher)
                    updated = True
                    break
                logger.warning('Invoke %d / %d: status: %d, response: %s, GTID: %s',
                    attempt, MAX_TRIES, response.status_code,
                    response.text[:50], x_gtid)
            except requests.exceptions.ReadTimeout:
                logger.warning('Invoke %d / %d: ReadTimeout - retrying',
                    attempt, MAX_TRIES)
            time.sleep(5)

        if updated:
            logger.info("API is updated")

            # Now look in Analytics...
            attempt = 0
            found = False
            while attempt < MAX_TRIES:
                attempt += 1
                (events, req_id) = get_analytics_records(platform_api_host, token, org, catalog, catalog_details['analytics'], api_name, verify)
                for event in events['events']:
                    if event.get('global_transaction_id') == x_gtid:
                        logger.info('Analytics %d / %d: events: %d, request_id %s - Transaction ID found',
                            attempt, MAX_TRIES, events['total'], req_id)
                        logger.info("Matched transaction id (%s) of successful call in analytics", x_gtid)
                        logger.info("API response in %dms for %s", event.get('time_to_serve_request'), event.get('query_string'))
                        found = True
                    elif 'response_http_headers' in event:
                        for header in event['response_http_headers']:
                            if 'x-global-transaction-id' in header:
                                logger.debug(header.get('x-global-transaction-id'))
                                if header.get('x-global-transaction-id') == x_gtid:
                                    logger.info('Analytics %d / %d: events: %d, request_id %s - Transaction ID found',
                                        attempt, MAX_TRIES, events['total'], req_id)
                                    logger.info("Matched transaction id (%s) of successful call in analytics", x_gtid)
                                    logger.info("API response in %dms for %s", event.get('time_to_serve_request'), event.get('query_string'))
                                    found = True

                if found:
                    return 0

                logger.warning('Analytics %d / %d: events: %d, request_id %s',
                    attempt, MAX_TRIES, events['total'], req_id)
                time.sleep(10)
            if not found:
                logger.critical("API record not in analytics after %d seconds", (MAX_TRIES * 5))
                return 1

        else:
            logger.critical("API not updated after %d seconds", (MAX_TRIES * 5))
            return 2
    else:
        logger.critical("Unable to retrieve token")
        return 4


if __name__ == '__main__':
    deploy_test_cli()
