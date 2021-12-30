import requests, json, time, threading, os, random, subprocess
from datetime import datetime, date
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



def ip_query_abusedb(ip):
    # Static values
    abuse_db_url = 'https://api.abuseipdb.com/api/v2/check'
    abuse_db_api_key = random.choice(API_keys.abusedb_api_key_list)
    decodedResponse = 'Cant run the request'  # This will be modified if the request.post will be successful
    response = 'Cant run the request'  # This will be modified if the request.post will be successful

    # Crafting the query
    querystring = {'ipAddress': ip, 'maxAgeInDays': '30'}
    headers = {'Accept': 'application/json', 'Key': abuse_db_api_key}

    try:
        # Getting the data
        response = requests.get(url=abuse_db_url, headers=headers, params=querystring)

        # Formatted output
        decodedResponse = json.loads(response.text)
        confidence_level = decodedResponse['data']['abuseConfidenceScore']  # Malicious certanty scale 0-100
        total_reports = decodedResponse['data']['totalReports']  # How many reports on this IP in last 30 days
        last_report = decodedResponse['data']['lastReportedAt']  # When was the last report
        domain_name = decodedResponse['data']['domain']  # What is the domain of the IP
        hostnames_found = decodedResponse['data']['hostnames']  # Hostnames related to this IP
        country = decodedResponse['data']['countryCode']  # Country of the IP

        # getting rid of None and Null
        if type(last_report) != str:
            last_report = "Never"

        holder.add_report('abusedb', [confidence_level, total_reports, last_report, domain_name, hostnames_found, country])

    except Exception as e:
        holder.add_report('abusedb', " {}  ERROR:  {} \n  API response:   {}".format(response.status_code, e, decodedResponse))



def ip_query_alien(ip):
    # Static values
    Alien_api_key = random.choice(API_keys.alien_api_key_list)
    url = 'https://otx.alienvault.com:443/api/v1/indicators/IPv4/{}/general'.format(ip)
    decodedResponse = 'Cant run the request'  # This will be modified if the request.post will be successful
    response = 'Cant run the request'  # This will be modified if the request.post will be successful

    # Crafting the query
    headers = {"X-OTX-API-KEY": Alien_api_key, "Accept": "application/json", 'User-Agent': 'Mozilla 5.0'}

    try:
        # Getting the data
        response = requests.post(url, headers=headers)

        # Formatted output
        decodedResponse = json.loads(response.text)
        pulse_amount = decodedResponse['pulse_info']['count']  # How many reports on this ip
        country = decodedResponse['country_code']  # Country of the IP
        if pulse_amount == 0:
            holder.add_report('alien', [pulse_amount, 'Never', country])
            return None
        latest_modified = decodedResponse['pulse_info']['pulses'][0]['modified']  # When was the last report modified

        # getting rid of None and Null
        try:
            latest_modified = decodedResponse['pulse_info']['pulses'][0]['modified']  # When was the last report modified
        except:
            latest_modified = "Never"

        holder.add_report('alien', [pulse_amount, latest_modified, country])
    except Exception as e:
        holder.add_report('alien', "{}  ERROR:  {} \n  API response:    {}".format(response.status_code, e, decodedResponse))



# This first uses 'Upload a URL for scanning' API and then Get a URL/file analysis
def ip_query_vt(ip):
    # Static values
    api_key = random.choice(API_keys.vt_api_key_list)
    av_found_as_malicious = []
    api_url = "https://www.virustotal.com/api/v3/urls"
    decodedResponse = 'Cant run the request'  # This will be modified if the request.post will be successful
    decodedResponse_2 = 'Cant run the request_2'  # This will be modified if the request.post will be successful
    response = 'Cant run the request'  # This will be modified if the request.post will be successful
    response_2 = 'Cant run the request'  # This will be modified if the request.post will be successful

    # Crafting the query_1
    url_to_scan = "url={}".format(ip)
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

    time.sleep(65)  # The max time it takes VT to reanalyze the IP

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
            # If any AV flagged the IP as malicious, get the AV
            if malicious + suspicious > 0:
                for i in decodedResponse_2['data']['attributes']["results"]:
                    if decodedResponse_2['data']['attributes']["results"][i]["category"] == "malicious" or \
                            decodedResponse_2['data']['attributes']["results"][i]["category"] == "suspicious":  # Which AV's flagged the IP as malicious or suspicious
                        av_found_as_malicious.append(i)
            holder.add_report('vt', [malicious, suspicious, av_found_as_malicious])
            return None
        else:
            holder.add_report('vt', "Analysis wasn't completed in 80 seconds, please try again")
            return None
    except Exception as e:
        holder.add_report('vt', "{}  ERROR:  {} \n  API response:    {}".format(response_2.status_code, e, decodedResponse_2))
        return None




#########################################  Why is this part commented out? Check line 318 for explanation  #############################################
# def calculate_date_difference(today_date, parsed_date):
#     if type(parsed_date) != str:
#         return 10000   #We return a huge number so the Calculate_score functions won't calculate anything that is timeline related. This is an error
#     date_2 = str(parsed_date).split("T")[0]
#     date_1_list = today_date.split("-")
#     date_2_list = date_2.split("-")
#     d1 = date(int(date_1_list[0]),int(date_1_list[1]),int(date_1_list[2]))
#     d2 = date(int(date_2_list[0]),int(date_2_list[1]),int(date_2_list[2]))
#     delta = d1 - d2
#     return int(delta.days)
#
#
#
# def calculate_score_abusedb(abusedb_results):
#     abusedb_score = 0
#
#     # getting today's date to understand timelines
#     today_date = str(datetime.now()).split(" ")[0]
#
#     # calculate abusedb score by confidence level
#     if abusedb_results[0] > 80:
#         abusedb_score += 10
#     elif abusedb_results[0] > 60:
#         abusedb_score += 7
#     elif  abusedb_results[0] > 30:
#         abusedb_score += 4
#     elif  abusedb_results[0] > 15:
#         abusedb_score += 3
#
#     # calculate abusedb score by confidence number of reports in last 30 days, correlated with when was the last report
#     if abusedb_results[1] > 0 and calculate_date_difference(today_date, abusedb_results[2]) <= 14 and abusedb_results[0] > 0:
#         if abusedb_results[1] > 10:
#             abusedb_score += 6
#         elif abusedb_results[1] > 7:
#             abusedb_score += 4
#         elif abusedb_results[1] > 4:
#             abusedb_score += 2
#
#     return abusedb_score
#
#
# def calculate_score_alien(alien_results):
#     alien_score = 0
#
#     # getting today's date to understand timelines
#     today_date = str(datetime.now()).split(" ")[0]
#
#     # Calculate alien score by number of reports (pulses) that mention this IP
#     if calculate_date_difference(today_date, alien_results[1]) <= 31:  #If the latest report modification was in the last 31 days.
#         if alien_results[0] > 9:
#             alien_score += 10
#         elif alien_results[0] > 6:
#             alien_score += 7
#         elif alien_results[0] > 4:
#             alien_score += 5
#         elif alien_results[0] > 2:
#             alien_score += 2
#
#     return alien_score
#
#
# def calculate_score_VT(VT_results):
#     VT_score = 0
#
#     # Calculate score by how many AV's flagged this IP
#     if VT_results[0] + VT_results[1] > 7:
#         VT_score += 10
#
#     elif VT_results[0] + VT_results[1] > 6:
#         VT_score += 7
#
#     elif VT_results[0] + VT_results[1] >= 3:
#         VT_score += 4
#
#     elif VT_results[0] == 2:
#         VT_score += 2
#
#     elif VT_results[0] == 1:
#         VT_score += 1
#
#
#     #Calculate score by who flagged the IP
#     if len(VT_results[2]) > 0:
#         if "Kaspersky" in VT_results[2]:
#             VT_score += 10
#
#         if "ESET" in VT_results[2]:
#             VT_score += 7
#
#         if "Fortinet" in VT_results[2]:
#             VT_score += 6
#
#     return VT_score



def start_all(ip, validator_number):
    # Setting a Class instance as a results holder
    global holder
    holder = Holder()

    # Starting the functions
    abusedb_thread = threading.Thread(target=ip_query_abusedb, args=[ip])
    alien_thread = threading.Thread(target=ip_query_alien, args=[ip])
    vt_thread = threading.Thread(target=ip_query_vt, args=[ip])
    abusedb_thread.start()
    alien_thread.start()
    vt_thread.start()

    # Creating a threads list
    threads = []
    threads.append(abusedb_thread)
    threads.append(alien_thread)
    threads.append(vt_thread)


    # These 3 lines will help the function know when to inable the coressponding buttons in GUI.py
    alien_done, vt_done, abusedb_done = False, False, False
    global alien_results, vt_results, abusedb_results
    counter = 0

    # We import GUI here, to overcome the 'circular imports' error
    import GUI

    while counter < 3:
        #This is for checking if the current search is still needed. See full explanation in GUI.py line 32.
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

        if 'abusedb' in holder.results_dict and abusedb_done == False:
            abusedb_done = True
            abusedb_results = holder.results_dict['abusedb']   # [cofidence level 1-100  | total reports in the last 30 days   |   Last report date  |   Domain name   |  hostnames found   | country  ]
            GUI.results_window_ip('abusedb')
            counter += 1

        if 'alien' in holder.results_dict and alien_done == False:
            alien_done = True
            alien_results = holder.results_dict['alien']   # [How many reports  |  When was the last report modified  |   Country  ]
            GUI.results_window_ip('alien')
            counter += 1

        if 'vt' in holder.results_dict and vt_done == False:
            vt_done = True
            vt_results = holder.results_dict['vt'] # [ AV malicious verdict  |  AV suspicious verdict   |  Which AV's flagged it ]
            GUI.results_window_ip('vt')
            counter += 1
    return None


""" This part is for deciding if the IP is malicious. 
    We calculate that based on: amount of reports, vendors, and time frame.
    I've commented this out because i think Analysts should decide for their themselves the verdict of an IOC based on the given data (which the script provides), and the current situation their in
    If you do want to integrate the calculation into the script, be my guest...
    This calculation technique can also be used in the URL_search.py script"""

    # # Checking if we received a list of information or errors
    # if type(abusedb_results) == list:
    #     abusedb_results.append(calculate_score_abusedb(abusedb_results)) # Adds the score to the list
    #
    # if type(alien_results) == list:
    #    alien_results.append(calculate_score_alien(alien_results)) # Adds the score to the list
    #
    # if type(VT_results) == list:
    #     VT_results.append(calculate_score_VT(VT_results)) # Adds the score to the list
    #
    # print("{} \n {} \n {}".format(abusedb_results, alien_results, VT_results))




#We set the variables here, so they can be directly imported using there names, by the GUI.py
alien_results, vt_results, abusedb_results = 1, 2, 3