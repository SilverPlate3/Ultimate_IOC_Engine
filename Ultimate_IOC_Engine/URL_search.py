import requests, json, time, threading, os, random, subprocess
from datetime import datetime, date
import API_keys


validator_path = "{}\Validation".format(os.path.dirname(__file__))

"""
The URL_query functions will be initiated by Threading.thread . 
So we need something that will store their output, as threads can't return a value.
What do we create? A holder class
"""
class Holder(object):

    def __init__(self):
        self.results_dict = {}

    def add_report(self, engine, result):
        self.results_dict[engine] = result



def url_query_URLhaus(URL):
    # Static values
    decodedResponse = 'Cant run the request'  # This will be modified if the request.post will be successful
    response = 'Cant run the request'  # This will be modified if the request.post will be successful

    # Crafting the query
    payload = {"url": URL}

    try:
        # Getting the data
        response = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data=payload)
        decodedResponse = json.loads(response.text)

        query_status = decodedResponse['query_status']
        if query_status == "ok":
            id = decodedResponse['id']
            url_status = decodedResponse['url_status']
            date_added = decodedResponse['date_added']
            tags = decodedResponse['tags']
            holder.add_report('URLhaus', [url_status, date_added, tags, id])
            return None
        else:
            holder.add_report('URLhaus', "No available report")
            return None
    except Exception as e:
        holder.add_report('URLhaus', "{} ERROR:  {} \n  API response:   {}".format(response.status_code, e, decodedResponse))



def url_query_alien(url):
    # Static values
    api_key = random.choice(API_keys.alien_api_key_list)
    decodedResponse = 'Cant run the request'  # This will be modified if the request.post will be successful
    response = 'Cant run the request'  # This will be modified if the request.post will be successful


    # Crafting the query
    headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json", 'User-Agent': 'Mozilla 5.0'}
    url = 'https://otx.alienvault.com:443/api/v1/indicators/url/{}/url_list'.format(url)


    try:
        # Getting the data
        response = requests.post(url, headers=headers)
        decodedResponse = json.loads(response.text.lower())

        # So we wont have any variable holding None in the future
        alive, date, file_downloaded_from_url, country = "Unavailable", "Unavailable", "Unavailable", "Unavailable"
    except Exception as e:
        holder.add_report('alien', "{}  ERROR:  {} \n  API response:   {}".format(response.status_code, e, decodedResponse))
        return None


    try:
        # This part is for checking if their is a report. We will get an 'error' if their isn't
        report_available = decodedResponse["url_list"]

        # Checks if its a report that has valuable stuff
        if len(decodedResponse["url_list"]) == 0 or decodedResponse["url_list"][0]["result"] == None:
            holder.add_report('alien', "No available report")
            return None


        # Tries to parse the data
        alive = decodedResponse["url_list"][0]['result']["urlworker"]["http_code"]
        try:
            date = decodedResponse["url_list"][0]['result']["urlworker"]["http_response"]["date"][:-12][4:]
        except:
            date = decodedResponse["url_list"][0]["date"].split('t')[0]
        file_downloaded_from_url = decodedResponse["url_list"][0]['result']["urlworker"]["sha256"]
        country = decodedResponse["country_code2"]
        holder.add_report('alien', [alive, date, file_downloaded_from_url, country])
        return None

    # If any parsing attempt has failed beacuse of missing data in the response
    except KeyError:
        # Checks if the error was in the beggining of parsing. If so, it tries again from the bottom.
        if alive == 'Unavailable' or date == 'Unavailable' or file_downloaded_from_url == 'Unavailable':
            try:
                country = decodedResponse["country_code2"]
                file_downloaded_from_url = decodedResponse["url_list"][0]['result']["urlworker"]["sha256"]
                date = decodedResponse["url_list"][0]['result']["urlworker"]["http_response"]["date"][:-12][4:]
                alive = decodedResponse["url_list"][0]['result']["urlworker"]["http_code"]
            except KeyError:
                if alive == "Unavailable" and country == "Unavailable": # We only need to check the two ends
                    holder.add_report('alien', "No available report")
                    return None
                else:
                    holder.add_report('alien', [alive, date, file_downloaded_from_url, country])
                    return None
            except Exception as e:
                holder.add_report('alien', "ERROR:  {} \n  API response:   {}".format(e, decodedResponse))
        holder.add_report('alien', [alive, date, file_downloaded_from_url, country])
        return None
    except Exception as e:
        holder.add_report('alien', "ERROR:  {} \n  API response:   {}".format(e, decodedResponse))



#At the moment this doesn't seem to work
def url_query_hybrid(url):
    # Static values
    api_key = random.choice(API_keys.hybrid_api_key_list)
    decodedResponse = 'Cant run the request'  # This will be modified if the request.post will be successful
    response = 'Cant run the request'  # This will be modified if the request.post will be successful

    # Crafting the query
    headers = {'api-key': api_key, 'accept': 'application/json', 'user-agent': 'Mozilla/5.0','Content-Type': 'application/x-www-form-urlencoded'}
    payload = {'scan_type': 'all_lookup', 'url': url}

    try:
        # Getting the data
        response = requests.post("https://www.hybrid-analysis.com/api/v2/quick-scan/url-for-analysis", headers=headers, data=payload)
        decodedResponse = json.loads(response.text)

        progress = decodedResponse["scanners"][0]['progress']
        #Checking if their is a report on the URL
        if progress == 100:
            status = decodedResponse["scanners"][0]['status']
            detections = decodedResponse["scanners"][0]['positives']
            holder.add_report('hybrid', [status, detections])
            return None
        else:
            holder.add_report('hybrid', "No available report")
    except Exception as e:
        holder.add_report('hybrid', "{}  ERROR:  {} \n  API response:   {}".format(response.status_code, e, decodedResponse))
        return None



# This first uses 'Upload a URL for scanning' API and then Get a URL/file analysis
def url_query_vt(url):
    # Static values
    api_key = random.choice(API_keys.vt_api_key_list)
    av_found_as_malicious = []
    api_url = "https://www.virustotal.com/api/v3/urls"
    decodedResponse = 'Cant run the request'  # This will be modified if the request.post will be successful
    decodedResponse_2 = 'Cant run the request_2'  # This will be modified if the request.post will be successful
    response = 'Cant run the request'  # This will be modified if the request.post will be successful
    response_2 = 'Cant run the request'  # This will be modified if the request.post will be successful


    # Crafting the query_1
    url_to_scan = "url={}".format(url)
    header = {"Accept": "application/json", "x-apikey": api_key}

    try:
        # Getting the data_1
        response = requests.post(api_url, data=url_to_scan, headers=header)

        # Formatted output_1
        decodedResponse = json.loads(response.text)
        id = decodedResponse['data']['id']  # Get the ID of the query
    except Exception as e:
        holder.add_report('vt', "{}  ERROR:  {} \n  API response:   {}".format(response.status_code, e, decodedResponse))
        return None

    time.sleep(65)  # The max time it takes VT to reanalyze the URL

    # Crafting the query_2
    api_url_2 = "https://www.virustotal.com/api/v3/analyses/{}".format(id)
    header_2 = {"Accept": "application/json", "x-apikey": api_key}

    try:
        # Getting the data_2
        response_2 = requests.get(api_url_2, headers=header_2)

        # Formatted output_2
        decodedResponse_2 = json.loads(response_2.text)
        check_if_completed = decodedResponse_2['data']['attributes']['status']
        # Check if the analysis was over. If not return 'analysis wasn't done yet, please try again'
        if check_if_completed == "completed":
            malicious = decodedResponse_2['data']['attributes']["stats"]["malicious"]  # How many AV found as malicious
            suspicious = decodedResponse_2['data']['attributes']["stats"]["suspicious"]  # How many AV found as suspicious
            # If any AV flagged the URL as malicious, get the AV
            if malicious + suspicious > 0:
                for i in decodedResponse_2['data']['attributes']["results"]:
                    if decodedResponse_2['data']['attributes']["results"][i]["category"] == "malicious" or decodedResponse_2['data']['attributes']["results"][i]["category"] == "suspicious":  # Which AV's flagged the URL as malicious or suspicious
                        av_found_as_malicious.append(i)
            holder.add_report('vt', [malicious, suspicious, av_found_as_malicious, id])
            return None
        else:
            holder.add_report('vt', "Analysis wasn't completed in 80 seconds, please try again")
            return None
    except Exception as e:
        holder.add_report('vt', "{}  ERROR:  {} \n  API response:    {}".format(response.status_code, e, decodedResponse_2))
        return None



def start_all(url, validator_number):
    # Setting a Class instance as a results holder
    global holder
    holder = Holder()

    # Starting the functions
    URLhaus_thread = threading.Thread(target=url_query_URLhaus, args=[url])
    alien_thread = threading.Thread(target=url_query_alien, args=[url])
    hybrid_thread = threading.Thread(target=url_query_hybrid, args=[url])
    vt_thread = threading.Thread(target=url_query_vt, args=[url])
    URLhaus_thread.start()
    alien_thread.start()
    hybrid_thread.start()
    vt_thread.start()

    # Creating a threads list
    threads = []
    threads.append(URLhaus_thread)
    threads.append(alien_thread)
    threads.append(hybrid_thread)
    threads.append(vt_thread)


    # These 3 lines will help the function know when to inable the coressponding buttons in GUI.py
    URLhaus_done, alien_done, hybrid_done, vt_done = False, False, False, False
    global URLhaus_results, alien_results, hybrid_results, vt_results
    counter = 0

    # We import GUI here, to overcome the 'circular imports' error
    import GUI

    while counter < 4:
        # This is for checking if the current search is still needed. See full explanation in GUI.py line 32.
        if "{}.txt".format(validator_number) not in os.listdir(validator_path):

            """The subprocess part is a double check on the if statement above.
            Because we work with a synced file system in my company, the request validation part that uses fast creation/deletion of files had issues. 
            For some reason os.listdir was aware of the deletion of the file but not the creation of a new one. (sometimes)"""
            p1 = subprocess.Popen('dir "{}"'.format(validator_path), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p1.communicate()
            if "{}.txt".format(validator_number) not in stdout.decode()[-200:]:
                for thread in threads:
                    thread.join()
                break

        if 'URLhaus' in holder.results_dict and URLhaus_done == False:
            URLhaus_done = True
            URLhaus_results = holder.results_dict['URLhaus']    #URLhaus ['Was the URL alive in the last connection attempt']['When was this URL reported']['Tags']
            GUI.results_window_URL('URLhaus')
            counter += 1


        if 'alien' in holder.results_dict and alien_done == False:
            alien_done = True
            alien_results = holder.results_dict['alien']   #alien ['http code']['report date']['file downloaded from URL']['Country']
            GUI.results_window_URL('alien')
            counter += 1


        if 'hybrid' in holder.results_dict and hybrid_done == False:
            hybrid_done = True
            hybrid_results = holder.results_dict['hybrid']   #hybrid ['URL status']['detections']
            GUI.results_window_URL('hybrid')
            counter += 1


        if 'vt' in holder.results_dict and vt_done == False:
            vt_done = True
            vt_results = holder.results_dict['vt']     #vt['Num of AV detected as malicious']['Num of AV detected as suspicious']['list of AV that found it as malicious']
            GUI.results_window_URL('vt')
            counter += 1


#We set the variables here, so they can be directly imported using there names, by the GUI.py
URLhaus_results, alien_results, hybrid_results, vt_results = 1, 2, 3, 4