# Import required libraries
import json, requests, ssl, time, urllib3

def cleanup():
 # Delete the scan
 dummy = requests.delete(MyAXURL + '/scans/' + MyScanID, headers = MyRequestHeaders, verify=False)
 # Delete the target
 dummy = requests.delete(MyAXURL + '/targets/' + MyTargetID, headers = MyRequestHeaders, verify=False)
 
 # Declare variables

goal = int(input('whats your goal?\n 1-scann the device\n 2-see the report\nPLEASE ENTER THE NUMBER : '))
if goal == 1:
    MyAXURL = "https://localhost:3443/api/v1"
    MyAPIKEY = input('Enter your key: ')
    MyTargetURL = input('Enter your target(with https): ')
    MyTargetDESC = input('Enter your comment or describe: ')
    type_scan = int((input("which scan do yo want?\n 1-Full Scan\n 2-High Risk Vulnerabilities\n 3-Cross-site Scripting Vulnerabilities\n 4-SQL Injection Vulnerabilities\n 5-Weak Passwords\nPLEASE ENTER NUMBER: ")))
    if type_scan == 1:
        FullScanProfileID = "11111111-1111-1111-1111-111111111111"
    elif type_scan == 2:
        FullScanProfileID = "11111111-1111-1111-1111-111111111112"
    elif type_scan == 3:
        FullScanProfileID = "11111111-1111-1111-1111-111111111116"
    elif type_scan == 4:
        FullScanProfileID = "11111111-1111-1111-1111-111111111113"
    elif type_scan == 5:
        FullScanProfileID = "11111111-1111-1111-1111-111111111115"
    critical = int(input("criticality:\n 1-Low\n 2-Normal\n 3-High\n 4-Critical\n PLEASE ENTER THE NUMBER: "))
    if critical == 1:
        crit = "Low"
    elif critical == 2:
        crit = "Normal"
    elif critical == 3:
        crit = "High"
    elif critical == 4:
        crit = "Critical"
    speedscan = int(input("scan speed:\n 1-Fast\n 2-Moderate\n 3-Slow\n 4-Slower\n PLEASE ENTER THE NUMBER:"))    
    if speedscan == 1:
        speed_scan = "Fast"
    elif speedscan == 2:
        speed_scan = "Moderate"
    elif speedscan == 3:
        speed_scan = "Slow"
    elif speedscan == 4:
        speed_scan = "Slower"
    
    MyRequestHeaders = {'X-Auth':MyAPIKEY, 'Content-Type':'application/json'}

    # Create our intended target - target ID is in the JSON response
    MyRequestBody = {"address":MyTargetURL,"description":MyTargetDESC,"type":"default","criticality":10}
    MyTargetIDResponse = requests.post(MyAXURL + '/targets', json=MyRequestBody, headers = MyRequestHeaders, verify=False)
    MyTargetIDjson=json.loads(MyTargetIDResponse.content)
    MyTargetID=MyTargetIDjson["target_id"]

    # Trigger a scan on the target - scan ID is in the HTTP response headers
    MyRequestBody = {"profile_id":FullScanProfileID,"incremental":False,"criticality":crit,"scan_speed":speed_scan,"schedule":{"disable":False,"start_date":None,"time_sensitive":False},"user_authorized_to_scan":"yes","target_id":MyTargetID}
    MyScanIDResponse = requests.post(MyAXURL + '/scans', json=MyRequestBody, headers = MyRequestHeaders, verify=False)
    MyScanID = MyScanIDResponse.headers["Location"].replace("/api/v1/scans/","")

    while True:
        print('scanner is running...')
        time.sleep(30)
        MyScanStatusResponse = requests.get(MyAXURL + '/scans/' + MyScanID, headers = MyRequestHeaders, verify=False)
        MyScanStatusjson = json.loads(MyScanStatusResponse.content)
        MyScanStatus = MyScanStatusjson["current_session"]["status"]
        if MyScanStatus=="completed":
            break
        elif MyScanStatus=="Failed":
            break
    
    # Obtain the scan session ID
    MyScanSessionResponse = requests.get(MyAXURL + '/scans/' + MyScanID, headers = MyRequestHeaders, verify=False)
    MyScanSessionjson = json.loads(MyScanSessionResponse.content)
    MyScanSessionID = MyScanSessionjson["current_session"]["scan_session_id"]

    # Obtain the scan result ID
    MyScanResultResponse = requests.get(MyAXURL + '/scans/' + MyScanID + "/results", headers = MyRequestHeaders, verify=False)
    MyScanResultjson = json.loads(MyScanResultResponse.content)
    MyScanResultID = MyScanResultjson["results"][0]["result_id"]

    # Obtain scan vulnerabilities
    MyScanVulnerabilitiesResponse = requests.get(MyAXURL + '/scans/' + MyScanID + '/results/' + MyScanResultID + '/vulnerabilities', headers = MyRequestHeaders, verify=False)
        
    # print("Target ID: " + MyTargetID)
    # print("Scan ID: " + MyScanID)
    # print("Scan Session ID: " + MyScanSessionID)
    # print("Scan Result ID: " + MyScanResultID)
    # print("")
    print("")
    file_name = input('Enter the name for save report: ')
    print("")
    print("Scan Vulnerabilities")
    print("====================")
    print("")
    print(MyScanVulnerabilitiesResponse.content)
    with open(f'{file_name}.json' , 'w') as f_n:
        json.dump(str(MyScanVulnerabilitiesResponse.content),f_n)
elif goal == 2:
    report_open_name = input('which report do yo see? ')
    with open(fr'C:\Users\Danial\Desktop\API vulnerability\{report_open_name}.json' , 'r') as rep:
        print(rep.read())
cleanup