#!/bin/bash

# Check if the target URL argument is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <TargetURL>"
    exit 1
fi

# The first argument after the script name will be used as MyTargetURL
MyTargetURL="$1"

# Declare functions
cleanup(){
# delete the scan
Dummy=`curl -sS -k -X DELETE "$MyAXURL/scans/{$MyScanID}" -H "Accept: application/json" -H "X-Auth: $MyAPIKEY"`
# delete the target
Dummy=`curl -sS -k -X DELETE "$MyAXURL/targets/{$MyTargetID}" -H "Accept: application/json" -H "X-Auth: $MyAPIKEY"`
}

# Declare Variables
MyAXURL="https://192.168.100.60:3443/api/v1"
MyAPIKEY="1d41896d6c24a41c2a42c9714ce9b69de323b439ec9f24a54a0e763db1721210b"
MyTargetDESC="reNgine acuscan"
FullScanProfileID="11111111-1111-1111-1111-111111111111"

# Create our intended target
MyTargetID=`curl -sS -k -X POST $MyAXURL/targets -H "Content-Type: application/json" -H "X-Auth: $MyAPIKEY" --data "{\"address\":\"$MyTargetURL\",\"description\":\"$MyTargetDESC\",\"type\":\"default\",\"criticality\":10}" | grep -Po '"target_id": *\K"[^"]*"' | tr -d '"'`
# Trigger a scan on the target
MyScanID=`curl -i -sS -k -X POST $MyAXURL/scans -H "Content-Type: application/json" -H "X-Auth: $MyAPIKEY" --data "{\"profile_id\":\"$FullScanProfileID\",\"incremental\":false,\"schedule\":{\"disable\":false,\"start_date\":null,\"time_sensitive\":false},\"user_authorized_to_scan\":\"yes\",\"target_id\":\"$MyTargetID\"}" | grep "Location: " | sed "s/Location: \/api\/v1\/scans\///" | sed "s/\r//g" | sed -z "s/\n//g"`

while true; do
 MyScanStatus=`curl -sS -k -X GET "$MyAXURL/scans/{$MyScanID}" -H "Accept: application/json" -H "X-Auth: $MyAPIKEY"`
 if [[ "$MyScanStatus" == *"\"status\": \"processing\""* ]]; then
   echo "Scan Status: Processing - waiting 30 seconds"
 elif [[ "$MyScanStatus" == *"\"status\": \"scheduled\""* ]]; then
   echo "Scan Status: Scheduled - waiting 30 seconds"
 elif [[ "$MyScanStatus" == *"\"status\": \"completed\""* ]]; then
   echo "Scan Status: Completed"
   # Break out of loop
   break
 else
   echo "Invalid Scan Status: Aborting"
   # Clean Up and Exit script
   cleanup
   exit 1
 fi
 sleep 30
done

# Obtain the Scan Session ID
MyScanSessionID=`echo "$MyScanStatus" | grep -Po '"scan_session_id": *\K"[^"]*"' | tr -d '"'`

# Obtain the Scan Result ID
MyScanResultID=`curl -sS -k -X GET "$MyAXURL/scans/{$MyScanID}/results" -H "Accept: application/json" -H "X-Auth: $MyAPIKEY" | grep -Po '"result_id": *\K"[^"]*"' | tr -d '"'`

# Obtain Scan Vulnerabilities
MyScanVulnerabilities=`curl -sS -k -X GET "$MyAXURL/scans/{$MyScanID}/results/{$MyScanResultID}/vulnerabilities" -H "Accept: application/json" -H "X-Auth: $MyAPIKEY"`

echo
echo "Target ID: $MyTargetID"
echo "Scan ID: $MyScanID"
echo "Scan Session ID: $MyScanSessionID"
echo "Scan Result ID: $MyScanResultID"
echo
echo
echo "Scan Vulnerabilities"
echo "===================="
echo
echo $MyScanVulnerabilities | jq
