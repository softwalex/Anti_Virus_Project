import requests, time

def main():
    #Input of the file path by the user.                                 
    file_path = input("Enter the file path: ")

    #The JSON file of the scan resulte
    scan_result = post_file_scan(file_path)
    # Check if the file was successfully scanned
    if scan_result['response_code'] == 1:  
        #From the JSON file show the value of the key "scan_id"
        scan_id = scan_result['scan_id']
        #print the Scan ID
        print(f"Scan ID: {scan_id}")
        # Check scan status periodically until it's completed
        while True:
            scan_status = check_scan_status(scan_id)
            if scan_status == 'completed':         
                scan_report = get_file_scan(scan_id)
                #Check if there are any viruses detected
                #When the value of the key "positives" is 0, the file is "clean"
                if(scan_report['positives']==0):
                    print("All clean, no viruses detected!")
                    time.sleep(3)
                    print("Scan report:")
                    print(scan_report)
                else:
                    print("Virus was detected!")
                    print("The anti virus detected "+str(scan_report['positives'])+" viruses...")
                    time.sleep(3)
                    print("Scan report:")
                    print(scan_report)
                break
            #When the scan request is in queue, check the status every 30 seconds
            elif scan_status == 'queued' or scan_status == 'in-progress':
                print("Scan is still in progress. Waiting for completion...")
                time.sleep(30)  # Wait for 30 seconds before checking again
            else:
                print("Unexpected scan status. Terminating.")
                break
    else:
        print("File scan failed.")

#Function to send the file to Virustotal using the methon "post"
def post_file_scan(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    API_key = '9326b2dce9d84fc0981c5f62bfb7234ee78ba7cded80d19d77a2e33f41ad9e82'
    params = {'apikey':API_key}
    with open(file_path,'rb') as file:
        files = {'file':(file_path, file)}
        response = requests.post(url,files=files, params=params)
    #Return a JSON of the posting data to get scan_id
    return response.json()

#Function to get back the result of the virus scan usin the method "get"
def get_file_scan(scan_id):
    resource = scan_id
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    API_key = '9326b2dce9d84fc0981c5f62bfb7234ee78ba7cded80d19d77a2e33f41ad9e82'
    params = {'apikey':API_key, 'resource':resource}
    response = requests.get(url,params=params)
    #Return a JSON of the scan resulte
    return response.json()

#Function to check the status of the scanning while waiting it to complete
def check_scan_status(scan_id):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    API_key = '9326b2dce9d84fc0981c5f62bfb7234ee78ba7cded80d19d77a2e33f41ad9e82'
    params = {'apikey': API_key, 'resource': scan_id}
    response = requests.get(url, params=params)
    json_response = response.json()
    if json_response['response_code'] == 1:
        if 'scan_date' in json_response and 'total' in json_response:
            if json_response['total'] > 0:
                return 'completed'  # Analysis completed with results
            else:
                return 'completed'  # Analysis completed without results
        else:
            return 'in-progress'  # Analysis still in progress
    elif json_response['response_code'] <= 0:
        return 'queued'  # Analysis queued
    else:
        return 'error'

if __name__ == "__main__":
    main()