import os
import requests
import zipfile


def download_and_extract_zip(url, target_directory):
    try:
        # Send a GET request to download the ZIP file
        response = requests.get(url)
        response.raise_for_status()

        # Create the target directory if it doesn't exist
        if not os.path.exists(target_directory):
            os.makedirs(target_directory)

        # Get the filename from the URL
        filename = os.path.join(target_directory, url.split("/")[-1])

        # Save the ZIP file in the target directory
        with open(filename, "wb") as zip_file:
            zip_file.write(response.content)

        # Extract the contents of the ZIP file
        with zipfile.ZipFile(filename, "r") as zip_ref:
            zip_ref.extractall(target_directory)

        # Remove the ZIP file after extraction (optional)
        os.remove(filename)

        print(f"ZIP file downloaded and extracted successfully to {target_directory}.")
    except requests.exceptions.RequestException as e:
        print(f"Error downloading ZIP file: {e}")
    except zipfile.BadZipFile as e:
        print(f"Error extracting ZIP file: {e}")


def get_osv_ecosystems():
    eco_systems_url = 'https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt'
    return requests.get(eco_systems_url).text.strip().splitlines()


def dump_osv_records(out_path):
    for ecosystem in get_osv_ecosystems():
        ecosystem_zip_url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
        dump_dir = f"{out_path}/{ecosystem}"
        download_and_extract_zip(ecosystem_zip_url, dump_dir)


dump_osv_records('Code/resources/osv-dumps')