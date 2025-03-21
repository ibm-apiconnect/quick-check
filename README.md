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
        -k, --apikey TEXT         API Key
        -f, --filename TEXT       API Definition to use (default is to use set-variable.yaml)
        -i, --client_id TEXT      client id required to retrieve a bearer token from apim
        -i, --client_secret TEXT  client secret required to retrieve a bearer tokenfrom apim

