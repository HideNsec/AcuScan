#!/usr/bin/env python3
import json, requests, ssl, time, urllib3
import sys, os
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def cleanup():
    # Delete the scan
    dummy = requests.delete(MyAXURL + '/scans/' + MyScanID, headers = MyRequestHeaders, verify=False)
    # Delete the target
    dummy = requests.delete(MyAXURL + '/targets/' + MyTargetID, headers = MyRequestHeaders, verify=False)

parser = argparse.ArgumentParser(description="AWVS scanner script")
parser.add_argument('--api_key', required=True, help='API key')
parser.add_argument('--target', required=True, help='Target URL')

args = parser.parse_args()

# Declare variables
MyAXURLHalf = "https://192.168.100.60:3443"
MyAXURL = "https://192.168.100.60:3443/api/v1"
MyAPIKEY = args.api_key
MyTargetURL = args.target
MyTargetDESC = "API Scan"
FullScanProfileID = "11111111-1111-1111-1111-111111111111"
MyRequestHeaders = {'X-Auth': MyAPIKEY, 'Content-Type': 'application/json'}

def addTask(url, target, MyRequestHeaders):
    global MyTargetDESC
    try:
        url = ''.join((url, '/api/v1/targets/add'))
        data = {"targets": [{"address": target, "description": MyTargetDESC}], "groups": []}
        r = requests.post(url, headers=MyRequestHeaders, data=json.dumps(data), timeout=30, verify=False)
        result = json.loads(r.content.decode())
        return result['targets'][0]['target_id']
    except Exception as e:
        return e


def scan(url,target,profile_id,is_to_scan,MyRequestHeaders):
    global MyTargetDESC
    scanUrl = ''.join((url, '/api/v1/scans'))
    target_id = addTask(url,target,MyRequestHeaders)
    if target_id:
        try:
            configuration(url,target_id,profile_id,MyRequestHeaders)#Configure target parameters

            if is_to_scan:
                data = {"target_id": target_id, "profile_id": profile_id, "incremental": False,
                        "schedule": {"disable": False, "start_date": None, "time_sensitive": False}}
                response = requests.post(scanUrl, data=json.dumps(data), headers=MyRequestHeaders, timeout=30, verify=False)
                result = json.loads(response.content)
                return [1,result['target_id']]
            else:
                return target_id

        except Exception as e:
            print(e)

def configuration(url,target_id,default_scanning_profile_id,MyRequestHeaders):#configure target
    configuration_url = ''.join((url,'/api/v1/targets/{0}/configuration'.format(target_id)))
    data = {"scan_speed": "moderate", "login": {"kind": "none"}, "ssh_credentials": {"kind": "none"},"default_scanning_profile_id":default_scanning_profile_id,
                "sensor": False, "user_agent": 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0', "case_sensitive": "auto",
                "limit_crawler_scope": False, "excluded_paths": [],
                "authentication": {"enabled": False},
                "technologies": [], "custom_headers": [], "custom_cookies": [],
                "debug": False, "client_certificate_password": "", "issue_tracker_id": "", "excluded_hours_id": ""}

    r = requests.patch(url=configuration_url,data=json.dumps(data), headers=MyRequestHeaders, timeout=30, verify=False)
    #print(configuration_url,r.text)


# Create our intended target - target ID is in the JSON response
#MyRequestBody = {"address":MyTargetURL,"description":MyTargetDESC,"type":"default","criticality":10}
#MyTargetIDResponse = requests.post(MyAXURL + '/targets', json=MyRequestBody, headers = MyRequestHeaders, verify=False)
#MyTargetIDjson=json.loads(MyTargetIDResponse.content)


MyTargetID=scan(MyAXURLHalf,MyTargetURL,FullScanProfileID,False,MyRequestHeaders)


def delete_target(target_id,MyAXURLHalf,MyRequestHeaders):
    try:
        response = requests.delete(MyAXURLHalf+"/api/v1/targets/"+str(target_id),headers=MyRequestHeaders,timeout=30,verify=False)
    except Exception as e:
        print(str(e))
        return

def delete_scan(scan_id,MyAXURLHalf,MyRequestHeaders):
    try:
        response = requests.delete(MyAXURLHalf+"/api/v1/scans/"+str(scan_id),headers=MyRequestHeaders,timeout=30,verify=False)
        if response.status_code == "204":
            return True
        else:
            return False
    except Exception as e:
        print(str(e))
        return

def getreports(scan_id):
    # scan_id
    '''
    11111111-1111-1111-1111-111111111111    Developer
    21111111-1111-1111-1111-111111111111    XML
    11111111-1111-1111-1111-111111111119    OWASP Top 10 2013
    11111111-1111-1111-1111-111111111112    Quick
    11111111-1111-1111-1111-111111111126    New
    '''
    data = {"template_id":"11111111-1111-1111-1111-111111111111","source":{"list_type":"scans","id_list":[scan_id]}}
    try:
        response = requests.post(MyAXURLHalf+"/api/v1/reports",data=json.dumps(data),headers=MyRequestHeaders,timeout=30,verify=False)
        result = response.headers
        report = result['Location'].replace('/api/v1/reports/','/reports/download/')
        return MyAXURLHalf.rstrip('/')+report
    except Exception as e:
        print(str(e))
        return
    finally:
        delete_scan(scan_id,MyAXURLHalf,MyRequestHeaders)

def generated_report(MyAXURLHalf,scan_id,target,MyRequestHeaders,MyTargetID):
    try:
        MyRequestBody0 = {"template_id": "11111111-1111-1111-1111-111111111111","source": {"list_type": "scan_result", "id_list":[scan_id]}}
        response = requests.post(MyAXURLHalf + "/api/v1/reports", json=MyRequestBody0, headers=MyRequestHeaders, verify=False)
        print(response)
        report_url = MyAXURLHalf.strip('/') + response.headers['Location']
        print(report_url)
        requests.get(str(report_url),headers=MyRequestHeaders, verify=False)

        unique_report_id = report_url.split("/")[-1]

        while True:
            report = get_report(MyAXURLHalf,response.headers['Location'],MyRequestHeaders)
            if not report:
                time.sleep(5)
            elif report:
                break

        # Get current report download links
        reports_response = requests.get(MyAXURLHalf + "/api/v1/reports?l=20", headers=MyRequestHeaders, verify=False)
        data = json.loads(reports_response.text)

        pdf_download_link = None
        for report in data["reports"]:
            if unique_report_id in report["download"][1]:  # PDF should be the second link
                pdf_download_link = report["download"][1]
                break

        if pdf_download_link is None:
            print("[ERROR] No PDF found for report: %s" % unique_report_id)
            return

        if(not os.path.exists("reports")):
            os.mkdir("reports")

        if '://' in target:
            filename = str(target.strip('/').split('://')[1]).replace('.','_').replace('/','-')
        else:
            # Handle the case where '://' is not found in the target URL
            # You can provide a default filename or handle it according to your needs
            filename = MyTargetURL

        # Modify to PDF
        file = "reports/" + filename + "%s.pdf" % time.strftime("%Y-%m-%d-%H-%M", time.localtime(time.time()))
        report = requests.get(MyAXURLHalf + pdf_download_link,headers=MyRequestHeaders, verify=False,timeout=120)
        with open(file, "wb") as f:
            f.write(report.content)
        print("[INFO] %s report have %s.pdf is generated successfully" % (target,filename))

    except Exception as e:
        raise e

    finally:
        ###delete_scan(scan_id,MyAXURLHalf,MyRequestHeaders)
        ###delete_target(MyTargetID,MyAXURLHalf,MyRequestHeaders)
        print("Ignore Deleting")

def get_report(MyAXURLHalf,reportid,MyRequestHeaders):
    res = requests.get(url=MyAXURLHalf + reportid, timeout=10, verify=False, headers=MyRequestHeaders)
    try:
        report_url = res.json()['download'][0]
        return report_url
    except Exception as e:
        return False


# Trigger a scan on the target - scan ID is in the HTTP response headers
MyRequestBody = {"profile_id":FullScanProfileID,"incremental":False,"schedule":{"disable":False,"start_date":None,"time_sensitive":False},"user_authorized_to_scan":"yes","target_id":MyTargetID}
MyScanIDResponse = requests.post(MyAXURL + '/scans', json=MyRequestBody, headers = MyRequestHeaders, verify=False)
MyScanID = MyScanIDResponse.headers["Location"].replace("/api/v1/scans/","")
LoopCondition=True
while LoopCondition :
 MyScanStatusResponse = requests.get(MyAXURL + '/scans/' + MyScanID, headers = MyRequestHeaders, verify=False)
 MyScanStatusjson = json.loads(MyScanStatusResponse.content)
 MyScanStatus = MyScanStatusjson["current_session"]["status"]
 if (MyScanStatus=="processing"):
   print("Scan Status: Processing - waiting 30 seconds...")
 elif (MyScanStatus=="scheduled"):
   print("Scan Status: Scheduled - waiting 30 seconds...")
 elif (MyScanStatus=="completed"):
   LoopCondition=False
 elif (MyScanStatus=="failed"):
   LoopCondition=False
 else:
   print("Invalid Scan Status: Aborting")
   ###cleanup
   exit()

 MyScanStatus=""
 time.sleep(30)



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


print (" ")
print ("Target ID: " + MyTargetID)
print ("Scan ID: " + MyScanID)
print ("Scan Session ID: " + MyScanSessionID)
print ("Scan Result ID: " + MyScanResultID)


generated_report(MyAXURLHalf,MyScanSessionID,MyTargetURL,MyRequestHeaders,MyTargetID)
