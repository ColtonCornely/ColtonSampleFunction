import logging
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    secret = req.params.get('secret')
    if not secret:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            secret = req_body.get('secret')

    if secret:
        credential=DefaultAzureCredential()
        print(credential)
        
        #The keyvault name could be converted to an input.
        keyvaultname = "coltonsamplekeyvault"
        
        client = SecretClient(
            vault_url=f"https://{keyvaultname}.vault.azure.net/",
            credential=credential
        )
        
        try:
            secretvalue = client.get_secret(secret)
        except Exception:
            return func.HttpResponse(
                "Secret not found. Try again.",
                status_code=200
            )
        else: 
            return func.HttpResponse(f"KeyVault Name: {keyvaultname}\nSecret Name: {secretvalue.name}\nCreation Date: {secretvalue.properties.created_on}\nSecret Value: {secretvalue.value}")
    else:
        return func.HttpResponse(
             "Enter the name of a secret by appending ?secret={somevalue} to the end of the url.",
             status_code=200
        )