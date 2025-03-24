# API Deploy Check

This script lets you do a quick validation to ensure the core functionality of API Connect is working as expected. The script will:

- Generate a token for the API Connect Platform API
- Create/update a product and API with a random 'eyecatcher' string
- Invoke the API, looping until there is a successful response up to a limit.
- Taking the global transaction id and api name, search for the record in Analytics relating to the successful call.

## Usage

    python api_deploy_check.py 
        -s, --server TEXT         Platform API hostname  [required]
        -o, --org TEXT            Organisation  [required]
        -c, --catalog TEXT        Catalog  [required]
        --verify / --no-verify    Verify certificates  [required]
        -f, --filename TEXT       API definition to use from templates directory (default is set-variable.yaml)

### API Manager Authentication

You can either use an [API Key](https://www.ibm.com/docs/en/api-connect/10.0.8?topic=applications-managing-platform-rest-api-keys) or username/password/realm to authenticate the script to API Manager.

        -a, --apikey
        -u, --username
        -p, --password
        -r, --realm
        --client_id TEXT      client id required to retrieve a bearer token from apim
        --client_secret TEXT  client secret required to retrieve a bearer tokenfrom apim

The client id and secret can be obtained from the **Tools for Download** page in API Manager where you can obtain the **Toolkit credentials** which will download a `credentials.json` file containing these values.
