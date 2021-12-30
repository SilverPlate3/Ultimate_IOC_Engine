import requests, json, threading, os, subprocess, random
import API_keys

validator_path = "{}\Validation".format(os.path.dirname(__file__))

"""
The IP_query functions will be initiated by Threading.thread . 
So we need something that will store their output, as threads can't return a value.
What do we create? A holder class
"""
class Holder(object):

    def __init__(self):
        self.results_dict = {}

    def add_report(self, engine, result):
        self.results_dict[engine] = result



def hash_query_alien(hash):
    # Static values
    api_key = random.choice(API_keys.alien_api_key_list)
    response = 'Cant run the request'  # This will be modified if the request.post will be successful

    # Crafting the query
    headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json", 'User-Agent': 'Mozilla 5.0'}
    url = 'https://otx.alienvault.com:443/api/v1/indicators/file/{}/analysis'.format(hash)

    try:
        # Getting the data
        response = requests.post(url, headers=headers)

        decodedResponse = json.loads(response.text)
        checks_if_their_is_a_report = decodedResponse['analysis']['hash']
        holder.add_report('alien', True)
        return None
    except KeyError:
        holder.add_report('alien', False)
        return None
    except Exception as e:
        holder.add_report('alien', "{} ERROR:  {} ".format(response.status_code, e))



def hash_query_URLhaus(hash):
    # Static values
    related_url = []
    decodedResponse = 'Cant run the request'  # This will be modified if the request.post will be successful
    response = 'Cant run the request'  # This will be modified if the request.post will be successful

    # Crafting the query
    payload = {"sha256_hash": hash}

    try:
        # Getting the data
        response = requests.post("https://urlhaus-api.abuse.ch/v1/payload/", data=payload)

        # Formatted output
        decodedResponse = json.loads(response.text)
        query_status = decodedResponse['query_status']
        if query_status == "ok":
            tag = decodedResponse["signature"]
            SSDEEP = decodedResponse["ssdeep"]
            for i in range(len(decodedResponse["urls"][:])):
                related_url.append(decodedResponse["urls"][i]['url'])
            holder.add_report('URLhaus', [tag, SSDEEP, related_url])
            return None
        else:
            holder.add_report('URLhaus', "No available report")
            return None
    except Exception as e:
        holder.add_report('URLhaus', "{}  ERROR:  {} \n  API response:   {}".format(response.status_code, e, decodedResponse))





def hash_query_malbazzar(hash):
    # Static values
    api_key = random.choice(API_keys.malbazaar_api_key_list)
    decodedResponse = 'Cant run the request'  # This will be modified if the request.post will be successful
    response = 'Cant run the request'  # This will be modified if the request.post will be successful

    # Crafting the query
    payload = {"query": "get_info", "hash": hash, "API-KEY": api_key}

    try:
        # Getting the data
        response = requests.post("https://mb-api.abuse.ch/api/v1/", data=payload)

        # Formatted output
        decodedResponse = json.loads(response.text)
        query_status = decodedResponse['query_status']
        if query_status == 'ok':
            SSDEEP = decodedResponse['data'][0]["ssdeep"]
            tags = decodedResponse['data'][0]["tags"]
            number_of_times_this_hash_was_upload = decodedResponse['data'][0]["intelligence"]["uploads"]
            try:
                number_of_yara_rules_for_this_hash = len(decodedResponse['data'][0]["yara_rules"])
            except TypeError:
                number_of_yara_rules_for_this_hash = 0
            if "Triage" in decodedResponse['data'][0]["vendor_intel"]:
                Third_party_AV_score = r"{}".format(decodedResponse['data'][0]["vendor_intel"]["Triage"]["score"])
            else:
                Third_party_AV_score = r"{}".format(decodedResponse['data'][0]["vendor_intel"]['ReversingLabs']["scanner_match"])
            holder.add_report('malbazzar', [SSDEEP, tags, number_of_times_this_hash_was_upload, number_of_yara_rules_for_this_hash, Third_party_AV_score])
            return None
        else:
            holder.add_report('malbazzar', "No available report")
            return None
    except Exception as e:
        holder.add_report( 'malbazzar', "{} ERROR:  {} \n  API response:   {}".format(response.status_code, e, decodedResponse))



def get_highest_value(decodedResponse, length, variable):
    #Getting the first list that is longer than 0. If exists
    if type(decodedResponse[0][variable]) == list:
        for i in range(length):
            if len(decodedResponse[i][variable]) > 0:
                return decodedResponse[i][variable]

    #Getting the first string/Int that isn't zero or None
    else:
        for i in range(length):
            if decodedResponse[i][variable] != None and decodedResponse[i][variable] != 0:
                return decodedResponse[i][variable]
    return "Unavailable"



def hash_query_hybrid(hash):
    # Static values
    api_key = random.choice(API_keys.hybrid_api_key_list)
    decodedResponse = 'Cant run the request'  # This will be modified if the request.post will be successful
    response = 'Cant run the request'  # This will be modified if the request.post will be successful

    # Crafting the query
    headers = {'api-key': api_key, 'accept': 'application/json', 'user-agent': 'Mozilla/5.0', 'Content-Type': 'application/x-www-form-urlencoded'}
    payload = {'hash': hash}

    try:
        # Getting the data
        response = requests.post("https://www.hybrid-analysis.com/api/v2/search/hash", headers=headers, data=payload)

        # Checking response code


        # Formatted output
        decodedResponse = json.loads(response.text)
        #The response comes inside of a list, this checks the list length
        length_of_response = len(decodedResponse)


        if length_of_response == 0:
            holder.add_report('hybrid', "No available report")
            return None


        #Parsing out 5 important things from the full API output
        score = get_highest_value(decodedResponse, length_of_response, "threat_score")
        if score == "Unavailable":
            holder.add_report('hybrid', "No available report")
            return None

        av_detections = get_highest_value(decodedResponse, length_of_response, "av_detect")
        string_verdict = decodedResponse[0]["verdict"]
        mitre_attacks_techniuqes_found = len(get_highest_value(decodedResponse, length_of_response, "mitre_attcks"))
        identifying_tags = get_highest_value(decodedResponse, length_of_response, "classification_tags")
        if identifying_tags == "Unavailable":
            identifying_tags = ""
        holder.add_report('hybrid', [score, av_detections,string_verdict,mitre_attacks_techniuqes_found, identifying_tags])
        return None

    except Exception as e:
        holder.add_report( 'hybrid', "{}  ERROR:  {} \n  API response:   {}".format(response.status_code, e, decodedResponse))



def category_and_name_vt(decodedResponse, element1="popular_threat_category", element2="popular_threat_name" ):
    try:
        value_list = []
        for num, category in enumerate(decodedResponse['data']["attributes"]["popular_threat_classification"][element1][:2]):
            yield category['value']
            if num == 1:
                break
        for num, category in enumerate(decodedResponse['data']["attributes"]["popular_threat_classification"][element2][:2]):
            yield category['value']
            if num == 1:
                break
    except:
        yield "Issue with finding malicious tags. Probably white file."



def hash_query_vt(hash):
    # Static values
    api_key = random.choice(API_keys.vt_api_key_list)
    tags = []
    decodedResponse = 'Cant run the request'  # This will be modified if the request.post will be successful
    response = 'Cant run the request'  # This will be modified if the request.post will be successful

    # Crafting the query
    api_url = "https://www.virustotal.com/api/v3/files/{}".format(hash)
    header = {'x-apikey': api_key}

    try:
        # Getting the data
        response = requests.get(api_url, headers=header)

        # Formatted output
        decodedResponse = json.loads(response.text)
        try:
            file_not_found = decodedResponse['error']['message']
            holder.add_report('vt', "hash wasn't found")
            return None
        except:
            file_type = decodedResponse['data']["attributes"]["type_description"]
            times_submitted = decodedResponse['data']["attributes"]["times_submitted"]
            for i in category_and_name_vt(decodedResponse):
                tags.append(i)
            ssdeep = decodedResponse['data']["attributes"]["ssdeep"]
            detections = decodedResponse['data']["attributes"]["last_analysis_stats"]["malicious"]
            community = "Total community votes:    Harmless: {}    Malicious: {}     Vote score: {}".format(decodedResponse['data']["attributes"]["total_votes"]['harmless'],decodedResponse['data']["attributes"]["total_votes"]['malicious'],decodedResponse['data']["attributes"]["reputation"])


            """This part checks the most trustful AntiVirus. VirusTotal AV's verdicts
            VirusTotal's AV's can have 2 verdict (malicious, undetected) and one exception (that the AV didn't scan it at all).
            We first set the 4 Av's result to undetected, so their won't be an error if one of them didn't scan the hash"""
            ESET_NOD32, Kaspersky, microsoft, Malwarebytes = "undetected", "undetected", "undetected", "undetected"
            if "ESET-NOD32" in decodedResponse['data']["attributes"]["last_analysis_results"]:
                ESET_NOD32 = decodedResponse['data']["attributes"]["last_analysis_results"]["ESET-NOD32"]["category"]
            if "Kaspersky" in  decodedResponse['data']["attributes"]["last_analysis_results"]:
                Kaspersky = decodedResponse['data']["attributes"]["last_analysis_results"]["Kaspersky"]["category"]
            if "Microsoft" in  decodedResponse['data']["attributes"]["last_analysis_results"]:
                microsoft = decodedResponse['data']["attributes"]["last_analysis_results"]["Microsoft"]["category"]
            if "Malwarebytes" in decodedResponse['data']["attributes"]["last_analysis_results"]:
                Malwarebytes  =  decodedResponse['data']["attributes"]["last_analysis_results"]["Malwarebytes"]["category"]
            community = "Total community votes:    Harmless: {}    Malicious: {}     Vote score: {}".format(decodedResponse['data']["attributes"]["total_votes"]['harmless'], decodedResponse['data']["attributes"]["total_votes"]['malicious'], decodedResponse['data']["attributes"]["reputation"])
            holder.add_report('vt', [file_type,times_submitted, ssdeep, detections, ESET_NOD32, Kaspersky, microsoft, Malwarebytes, tags, community])
            return None

    except Exception as e:
        holder.add_report('vt', "{}  ERROR:  {} \n  API response:    {}".format(response.status_code, e, decodedResponse))



def start_all(hash, validator_number):
    # Setting a Class instance as a results holder
    global holder
    holder = Holder()

    # Starting the functions
    alien_thread = threading.Thread(target=hash_query_alien, args=[hash])
    urlhuas_thread = threading.Thread(target=hash_query_URLhaus, args=[hash])
    malbazzar_thread = threading.Thread(target=hash_query_malbazzar, args=[hash])
    vt_thread = threading.Thread(target=hash_query_vt, args=[hash])
    hybrid_thread = threading.Thread(target=hash_query_hybrid, args=[hash])
    alien_thread.start()
    urlhuas_thread.start()
    malbazzar_thread.start()
    vt_thread.start()
    hybrid_thread.start()

    #Creating a threads list
    threads = []
    threads.append(alien_thread)
    threads.append(urlhuas_thread)
    threads.append(malbazzar_thread)
    threads.append(vt_thread)
    threads.append(hybrid_thread)


    #These 3 lines will help the function know when to inable the coressponding buttons in GUI.py
    alien_done, urlhuas_done, malbazzar_done, vt_done, hybrid_done = False, False, False, False, False
    global alien_results, URLhaus_results, malbazzar_results, vt_results, hybrid_results
    counter = 0

    # We import GUI here, to overcome the 'circular imports' error
    import GUI


    while counter < 5:
        # This is for checking if the current search is still needed. See full explanation in GUI.py line 32.
        if "{}.txt".format(validator_number) not in os.listdir(validator_path):

            """The subprocess part is a double check on the if statement above.
            Because we work with a synced file system in my company, the request validation part that uses fast creation/deletion of files had issues. 
            For some reason os.listdir was aware of the deletion of the file but not the creation of a new one. (sometimes)"""
            p1 = subprocess.Popen('dir "{}"'.format(validator_path), shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            stdout, stderr = p1.communicate()
            if "{}.txt".format(validator_number) not in stdout.decode()[-200:]:
                for thread in threads:
                    thread.join()
                break


        if 'alien' in holder.results_dict and alien_done == False:
            alien_done = True
            alien_results = holder.results_dict['alien']  # [was their a report on this hash or not]
            GUI.results_window_hash('alien')
            counter += 1

        if 'URLhaus' in holder.results_dict and urlhuas_done == False:
            urlhuas_done = True
            URLhaus_results = holder.results_dict['URLhaus']  # [Tags], [SSDEEP], [URL's related to this hash]
            GUI.results_window_hash('URLhaus')
            counter += 1

        if 'malbazzar' in holder.results_dict and malbazzar_done == False:
            malbazzar_done = True
            malbazzar_results = holder.results_dict['malbazzar'] # [SSDEEP], [list of tags], [how many times this hash was uploaded], [number of yara rules it hits] [Triage AV score X\10]
            GUI.results_window_hash('malbazzar')
            counter += 1

        if 'vt' in holder.results_dict and vt_done == False:
            vt_done = True
            vt_results = holder.results_dict['vt']  # [File type], [times submited], [SSDEEP], [AV detections], [ESET],[Kaspersky],[Microsoft], [Malwarebytes], [Tags list],  [Community]
            GUI.results_window_hash('vt')
            counter += 1

        if 'hybrid' in holder.results_dict and hybrid_done == False:
            hybrid_done = True
            hybrid_results = holder.results_dict['hybrid']  # [score], [AV's detected], [verdict], [Number of mitre techniques found], [list of tags]
            GUI.results_window_hash('hybrid')
            counter += 1




#We set the variables here, so they can be directly imported using there names, by the GUI.py
alien_results, URLhaus_results, malbazzar_results, vt_results, hybrid_results = 1,2,3,4,5


