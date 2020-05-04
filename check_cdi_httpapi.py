#!/usr/bin/python

import sys
import requests
import argparse
import random
import json
from datetime import datetime

# ##############################################################################
# B2STAGE Client  #
# ##############################################################################

#****** Info about the probe ****#
# enabled = you are allowed to proceed with further steps (quality checks / prod approvation) since the ingestion is completed
#1) authentication (as for the already defined probe) to get the token
#
#2) create a batch: this a POST call requiring an URL and some metrics (filesize, file checksum, number of files into the zip). This is an async call: Celery will download the zip from the provided URL, will verify the file size and the file checksum (verifying the file size is not so important, since we are verifying the checksum, but these are the specifications!), then will extract the archive and verify the number of files. For small zips this will require very few seconds IF there are avaiable workers, otherwise the request will be queued to wait for a worker (but in case of congestion the wait can potentially last for hours!)
#
#3) You can ask to the APIs if the ingestion is completed (this is a sync endpoint). Retry until the batch is flagged as enabled.
#
#4) Once completed, you can ask for a Quality check (this will use Rancher)
#
#5) as final step you can move the batch in production (batch approval). Very probably we do not want to execute this step, since once approved there is no way to remove that file from the system
#
#6) you can delete the batch
#
#=>
#
#POST batch creation
#
#for n times:
#   GET batch
#   if not completed:
#       continue
#  else:
#      request quality check
#if still not completed after n times:
#   warning(unable to test, congestion?)
#DELETE the batch

def ValidateValues(arguments):
        """ Validate values - input values """

        if arguments.timeout <= 0:
            print("\nInvalid timeout value: %s\n" % arguments.timeout)
            print_help()
            exit()

        if arguments.hostname is None:
            print("\nNo hostname provided\n")
            print_help()
            exit()

        if not arguments.hostname.startswith("http"):
            print("\nNo schema supplied with hostname, did you mean https://%s?\n" % arguments.hostname)
            print_help()
            exit()


def print_help():
        """ Print help values."""

        print("usage: check_b2stage_http-api.py -H -p")
        print("--- ---- ---- ---- ---- ---- ----\n")
        print("main arguments:")
        print("-H hostname")
        print("\n")
        print("optional arguments:")
        print(" -h, --help  show this help message and exit")
        print("-p port")
        print("-t timeout")
        print("-v verbose")
        print("-u user")
        print("-P password")

def debugValues(arguments):
    """ Print debug values.
        Args:
            arguments: the input arguments
    """
    if arguments.debug:
        print("[debugValues] - hostname: %s" % arguments.hostname)
    if arguments.port != '':
        print("[debugValues] - port: %s" % arguments.port)
    if arguments.timeout != '':
        print("[debugValues] - timeout: %s" % arguments.timeout)
    if arguments.user != '':
        print("[debugValues] - user: %s" % arguments.user)
    if arguments.password != '':
        print("[debugValues] - password: ******")


def checkHealth(URL, timeout):
    """ Check service status.
        Args:
           URL : service hostname
           timeout : how long should we wait for a response from the server
    """
    out = None
    u = URL + "/api/status"
    try:
        out = requests.get(url=u, timeout=timeout)

    except requests.exceptions.SSLError:
        description = "WARNING - Invalid SSL certificate"
        exit_code = 1
        return description, exit_code
    except requests.exceptions.ConnectionError:
        description = "CRITICAL - Service unreachable"
        exit_code = 2
        return description, exit_code

    if out is None:
        description = "UNKNOWN - Status unknown"
        exit_code = 3
        return description, exit_code

    if out.status_code != 200:
        description = "WARNING - Unexpected status code %s" % out.status_code
        exit_code = 1
        return description, exit_code

    content = out.json()
    if 'Response' in content:
        resp = content['Response']['data']
    else:
        resp = content

    if resp != "Server is alive!":
        description = "WARNING - Unexpected response: %s" % resp
        exit_code = 1
        return description, exit_code

    description = "OK - Service reachable"
    exit_code = 0
    return description, exit_code


def checkAuthentication(URL, timeout, user, password):
    """ Check service authentication.
        Args:
           URL : service hostname
           timeout : how long should we wait for a response from the server
           user : username to authenticate the session
           password : password to authenticate the session
    """

    token = None
    out = None
    u = URL + "/auth/b2safeproxy"
    try:
        payload = {'username': user, 'password': password}
        out = requests.post(url=u, timeout=timeout, data=payload)
    except BaseException as e:
        description = "UNKNOWN - (Login) Unknown error: %s" % str(e)
        exit_code = 3
        return description, exit_code, token

    if out.status_code == 401:
        description = "CRITICAL - (Login) Invalid credentials"
        exit_code = 2
        return description, exit_code, token

    if out.status_code != 200:
        description = "WARNING -(Login)  Unexpected status code %s" % out.status_code
        exit_code = 1
        return description, exit_code, token

    content = out.json()
    resp = content['Response']['data']

    if 'token' not in resp:
        description = "CRITICAL - (Login) Unable to get a valid authentication token"
        exit_code = 2
        return description, exit_code, token
    
    token = resp['token']

    description = "OK - (Login) Service reachable"
    exit_code = 0
    return description, exit_code, token


def checkLogout(URL, timeout, token):
    """ Check service authentication.
        Args:
           URL : service hostname
           timeout : how long should we wait for a response from the server
           token : authentication token received from login
    """

    u = URL + "/auth/logout"
    headers = {'Authorization': 'Bearer %s' % token}
    try:
        out = requests.get(url=u, timeout=timeout, headers=headers)
    except BaseException as e:
        description = "UNKNOWN - (logout) Unknown error: %s" % str(e)
        exit_code = 3
        return description, exit_code, token

    if out.status_code == 401:
        description = "CRITICAL - (logout) Invalid credentials"
        exit_code = 2
        return description, exit_code, token

    if out.status_code == 404:
        description = "CRITICAL - (logout) Endpoint not found"
        exit_code = 2
        return description, exit_code, token

    if out.status_code != 204:
        description = "WARNING - (logout) Unexpected status code %s" % out.status_code
        exit_code = 1
        return description, exit_code, token

    description = "OK - (logout) Service reachable"
    exit_code = 0
    return description, exit_code, token

def checkBatchPost (URL, token, exit_code, timeout):
    """ Create the new batch request
           URL : service hostname
           timeout : how long should we wait for a response from the server
           token : authentication token received from login
    """

    batch_id = "mon_"+str(random.randint(1,1001))

    now = datetime.today().strftime("%Y%m%dT%H:%M:%S")
    download_path = "https://github.com/rapydo/http-api/archive/"
    worker_task_id  = 1
    file_name = "v0.6.6.zip"
    file_checksum = "a2b241be6ff941a7c613d2373e10d316"
    file_size = "1473570"
    data_file_count = "1"
    params = {
        "request_id": batch_id, "edmo_code": 12345, "datetime": now,
        "version": "1", "api_function": "datafiles_download",
        "test_mode": "true", "parameters": {
            "backdoor": True,
            "batch_number": batch_id,
            "file_checksum": file_checksum,
            "file_size": file_size,
            "data_file_count": data_file_count,
            "download_path": download_path,
            "file_name": file_name
        }
        }
    params = json.dumps(params)

    u = URL + "/api/ingestion/"+batch_id
    headers = {'Authorization': 'Bearer %s' % token}
    try:
        out = requests.post(url=u, timeout=timeout, data=params, headers=headers)
    except BaseException as e:
        description = "UNKNOWN - (Create Batch)  Unknown error: %s" % str(e)
        exit_code = 3
        return description, exit_code, token, worker_task_id, batch_id

    if out.status_code == 401:
        description = "CRITICAL -  (Create Batch) Invalid credentials"
        exit_code = 2
        return description, exit_code, token, worker_task_id, batch_id

    
    if out.status_code == 404:
        description = "CRITICAL - (Create Batch)  Endpoint not found"
        exit_code = 2
        return description, exit_code, token, worker_task_id, batch_id

    if out.status_code != 200:
        description = "WARNING -  (Create Batch) Unexpected status code %s" % out.status_code
        exit_code = 1
        return description, exit_code, token, worker_task_id, batch_id

    content = out.json()
    resp = content['Response']['data']
    worker_task_id = resp['request_id']

    description = "OK -  (Create Batch) Batch created"
    exit_code = 0
    return description, exit_code, token, worker_task_id, batch_id

def checkBatchIfEnabled (batch_id, URL, token, exit_code, timeout):

    """ ask the APIs if the batch is enabled
           batch_id: the batch_id we are checking
           URL : service hostname
           token : authentication token received from login
           exit_code: the code that should be returned to nagios
           timeout : how long should we wait for a response from the server
    """
    out = None
    status = None
    u = URL + "/api/ingestion/"+batch_id
    headers = {'Authorization': 'Bearer %s' % token}
    for i in range(0,6):
            try:
                if status is 'enabled':
                        break;
                else:
                        out = requests.get(url=u, timeout=timeout, headers=headers)
            except BaseException as e:
                description = "UNKNOWN - (checkBatchIfEnabled) Unknown error: %s" % str(e)
                exit_code = 3
                return description, exit_code, token, status
            except requests.exceptions.RequestException as e:
                print e

            if out.status_code == 401:
                description = "CRITICAL - (checkBatchIfEnabled) Invalid credentials"
                exit_code = 2
                return description, exit_code, token, status

            if out.status_code == 404:
                description = "CRITICAL - (checkBatchIfEnabled) Endpoint with the sepicified batch_id not found"
                exit_code = 2
                return description, exit_code, token, status

            if out.status_code != 200:
                description = "Batch Enabled - WARNING - (checkBatchIfEnabled) Unexpected status code %s" % out.status_code
                exit_code = 1
                return description, exit_code, token, status

            content = out.json()
            resp = content['Response']['data']
            status = resp['status']
            #print status

            description = "OK - Batch is "+status
            exit_code = 0
    return description, exit_code, token, status
def checkQualityCheck (batch_id, URL, token, exit_code, timeout):

    """ ask the APIs if the batch is enabled
           URL : service hostname
           token : authentication token received from login
           exit_code: the code that should be returned to nagios
           timeout : how long should we wait for a response from the server
    """
    out = None
    status = None
    now = datetime.today().strftime("%Y%m%dT%H:%M:%S")
    u = URL + "/api/ingestion/"+batch_id+"/qc/ls:0.1"
    responseBody = {'request_id': batch_id,
                    'edmo_code': 12345,
                    'version': 1,
                    'test_mode': True,
                    'eudat_backdoor':True,
                    'datetime': now,
                    'api_function': 'qc',
                    'parameters': {}
                    }


    headers = {'Authorization': 'Bearer %s' % token}
    try:
        out = requests.put(url=u, timeout=timeout, headers=headers, data=json.dumps(responseBody))
    except BaseException as e:
        description = "UNKNOWN - (checkQualityCheck) Unknown error: %s" % str(e)
        exit_code = 3
        return description, exit_code, token, status

    if out.status_code == 401:
        description = "CRITICAL -(checkQualityCheck)  Invalid credentials"
        exit_code = 2
        return description, exit_code, token, status

    if out.status_code == 404:
        description = "CRITICAL -(checkQualityCheck)  Endpoint with the sepicified batch_id not found"
        exit_code = 2
        return description, exit_code, token, status

    if out.status_code != 200:
        description = "Quality Check problem - (checkQualityCheck) WARNING - Unexpected status code %s" % out.status_code
        exit_code = 1
        return description, exit_code, token, status
    
        content = out.json()
    resp = content['Response']['data']
    status = resp['status']
    description = "OK - Quality Check is "+ status
    exit_code = 0
    return description, exit_code, token, status

def deleteBatchJob( batch_id, URL, token, exit_code, timeout):

    out = None
    status = None
    now = datetime.today().strftime("%Y%m%dT%H:%M:%S")
    u = URL + "/api/ingestion/"+batch_id+"/qc/ls:0.1"
    responseBody = {'request_id': batch_id,
                    'edmo_code': 12345,
                    'datetime': now,
                    'version': 1,
                    'test_mode': True,
                    'api_function': 'delete_batch',
                    'parameters':
                        {
                        "batches": [batch_id],
                        "backdoor": True
                        }
                    }
    headers = {'Authorization': 'Bearer %s' % token}
    try:
        out = requests.delete(url=u, timeout=timeout, headers=headers, data=json.dumps(responseBody))
        print "test"
    except BaseException as e:
        description = "UNKNOWN - (deleteBatchJob) Unknown error: %s" % str(e)
        exit_code = 3
        return description, exit_code, token, status
    content = out.json()
    resp = content['Response']['data']
    status = resp['status']

    description = "OK - Batch with batch id " + batch_id  +" is "+ status
    exit_code = 0
    return description, exit_code, token, status

def checkResult( token, description, exit_code):
    """ Check the values
        Args:
            token: the token used to authenticate
            description: the nagios description
            exit_code: the code that should be returned to nagios
    """

    # Authentication failed, unable to continue
    if exit_code > 0:
        printResult(description, exit_code)

    # No valid authentication token received, unable to continue
    if token is None:
        printResult(description, exit_code)

def printResult(description, exit_code):
    """ Print the predefined values
        Args:
            description: the nagios description
            exit_code: the code that should be returned to nagios
    """

    print(description)
    sys.exit(exit_code)

def main():

    parser = argparse.ArgumentParser(description='B2STAGE probe '
                                                 'Supports healthcheck.')
    parser.add_argument("--hostname", "-H", help='The Hostname of B2STAGE service')
    parser.add_argument("--port", "-p", type=int)
    parser.add_argument("--timeout", "-t", metavar="seconds", help="Timeout in seconds. Must be greater than zero", type=int, default=30)
    parser.add_argument("--user", "-u", metavar="user", help="User name to allow checks on authenticated endpoints")
    parser.add_argument("--password", "-P", metavar="password", help="Passoword to allow checks on authenticated endpoints")
    parser.add_argument("--verbose", "-v", dest='debug', help='Set verbosity level', action='count', default=0)
    arguments = parser.parse_args()
    ValidateValues(arguments)

    if arguments.debug :
        debugValues(arguments)

    URL = arguments.hostname
    if arguments.port is not None:
        URL += ":%s" % arguments.port

    description, exit_code = checkHealth(URL, arguments.timeout)

    # Healt check failed, unable to continue
    if exit_code > 0:
        printResult(description, exit_code)

    # Authenticated tests not allowed, unable to continue
    if arguments.user is None or arguments.password is None:
        printResult(description, exit_code)

    description, exit_code, token = checkAuthentication(
        URL, arguments.timeout, arguments.user, arguments.password)

    checkResult( token, description, exit_code)

    # No valid authentication token received, unable to continue
    checkResult( token, description, exit_code)

    description, exit_code, token, task_worker_id, batch_id = checkBatchPost (
        URL, token, exit_code, arguments.timeout)

    #check if batch is enabled at the api
    description, exit_code, token, status = checkBatchIfEnabled (batch_id,
        URL, token, exit_code, arguments.timeout)
    # Authentication failed, unable to continue
    # No valid authentication token received, unable to continue
    checkResult( token, description, exit_code)

    description, exit_code, token, status = checkQualityCheck (batch_id, URL, token, exit_code, arguments.timeout)
    # Authentication failed, unable to continue
    checkResult( token, description, exit_code)

    description, exit_code, token, status = deleteBatchJob (batch_id, URL, token, exit_code, arguments.timeout)
    checkResult( token, description, exit_code)

    printResult(description, exit_code)


if __name__ == "__main__":
    main()


                                                   
