
import logging, sys
import requests
import json

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG) 

API_ENDPOINT = "https://vulners.com/api/v3/burp/software/"

def getResults(name, version):

    if not version:
      version = 1.0
      
    params = {"software": name,
              "version": version,
              "type": "software" }

    
    try:
      logging.info("Using params" + name) 
    except: 
      logging.fatal("paramateres must be set incorrectly")
      
    response = requests.get(API_ENDPOINT, params=params)
    jsonResponse = response.json()
    logging.info("Using URL %s", response.url)
    if response.status_code == 200 and jsonResponse['result'] == 'OK':
        logging.info("JSON Response %s", response.json())
        return jsonResponse
    else:
        logging.info("unsuccessful JSON Response %s", response.json())
        return jsonResponse


def getVulners(name, version):
    outputList=[]

    try:
      requests.get('https://vulners.com')
    except:
      logging.fatal("No connection to https://vulners.com")

    results = getResults(name, version)
    if results is not None:
        if (results['result'] == 'OK'):
            for i in range(len(results['data']['search'])):
                issue = results['data']['search'][i]
                outputList.append(addIssue( name, version,
                                            issue['_source']['cvelist'],
                                            issue['_source']['cvss']['score'],
                                            issue['_source']['href'],
                                            issue['_source']['description']))
    return outputList


def addIssue(name, version, cve, score, link, body):
    output = [cve, score, link, body]
    print("-=_=-"*30)
    print(name +" With assumed version "+ version)
    print(str(output[1])+ " CVE score with more info at: "+ output[2].rstrip()+ output[3].rstrip())
    return output