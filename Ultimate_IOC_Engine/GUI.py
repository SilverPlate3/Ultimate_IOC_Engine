import threading, os, shutil
import dearpygui.dearpygui as dpg
import IP_search, Hash_search, URL_search, Calc_hash
from Engines_buttons_DB import *


class tag_handler(object):

    def __init__(self):
        self.counter = 0
        self.ioc = ""

    #Creates a tag for a new window and deletes the older one
    def new_tag(self):
        if self.counter == 0:
            self.counter += 1
            return 'only_window_{}'.format(self.counter)
        else:
            dpg.delete_item('only_window_{}'.format(self.counter))
            self.counter += 1
            return 'only_window_{}'.format(self.counter)

    #Helps the user to keep track what IOC is shown in the current window
    def set_ioc(self, ioc):
        self.ioc = ioc

    def get_ioc(self):
        return self.ioc


"""
Why do we have a request_validator? 
Well each time an 'IOC engine API' gives us an answer back, it creates a new window that contains all the info given until now AND deletes the prior window.
But what if we already pressed HOME and conducted a new search? We don't want an Old API query to mess up our new IOC search.
So this help the API request check if their are still needed, by giving each search a validation number.
What is the validator? It's actually a text file that will change it's name constantly. I had to use something like this, as the script's don't always run exactly in the same time. But they still must be synced
"""
class request_validator(object):

    def __init__(self):
        self.counter = 0
        self.validator_path = "{}\Validation".format(os.path.dirname(__file__))


    def counter_add_1(self):
        self.counter += 1

        if '{}.txt'.format(self.counter - 1) in os.listdir(self.validator_path):
            os.remove("{}\{}.txt".format(self.validator_path, self.counter - 1))

        with open("{}\{}.txt".format(self.validator_path, self.counter), 'w') as f:
            pass


    def get_counter(self):
        return self.counter

    #The validator is acctually a folder that will contain a single text filf which will be deleted and created with every new search. this is acctually the Token.
    def get_validator_path(self):
        return self.validator_path




################################################# START OF HASH SEARCH ##########################################################
'''
This window will pop after the user selects the Hash option in the Start_window.
It will get a hash and send it over to -  initiate_Hash_search   '''
def search_hash():
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        text = dpg.add_text('Type the hash', pos=[350, 160])
        type_hash = dpg.add_input_text(width=560 ,pos=[115, 200])
        submit_button = dpg.add_button(label='Submit', pos=[375, 280], callback=initiate_Hash_search, user_data=type_hash)



'''
The function gets 3 arguments even though we sent only 1.
When sending a DearPyGui widget, it "splits" to 3 and only the last one is actually the parameter we sent '''
def initiate_Hash_search(sender='Ignore', app_data='Ignore', item='the element'):
    #Checks who called the function, was it Local_file OR search_hash
    if sender == 'Ignore' and app_data == 'Ignore':
        hash_to_search = item
    else:
        # Gets the value (hash) from the sent widget
        hash_to_search = dpg.get_value(item)

    Hash_button_DB['tagger'].set_ioc(hash_to_search)
    # Starting all the IOC engines API in Hash_search.py
    hash_search_thread = threading.Thread(target=Hash_search.start_all, args=[hash_to_search, Hash_button_DB['validator'].get_counter()])
    hash_search_thread.start()

    # Creating the window with all the Engines buttons. You can't on an IOC engine button until his corresponding API isnt finished
    results_window_hash()



'''When first called, this just crates a window with unpressable buttons.
Later the API's themselves call this function. When an API calls the function it sends it's name as well.
Then the Button of the API will change it text and be pressable'''
def results_window_hash(engine = 'waiting for IOC engiens to finish reports'):
    #This part checks who called the function, and acts accordingly.
    if engine == 'alien':
        Hash_button_DB['alien_hash_label'] = 'Alien Vault OTX'
        Hash_button_DB['alien_hash_true'] = True
    elif engine == 'malbazzar':
        Hash_button_DB['malbazzar_hash_label'] = 'Malware Bazaar'
        Hash_button_DB['malbazzar_hash_true'] = True
    elif engine == 'URLhaus':
        Hash_button_DB['URLhaus_hash_label'] = 'URLhaus'
        Hash_button_DB['URLhaus_hash_true'] = True
    elif engine == 'vt':
        Hash_button_DB['vt_hash_label'] = 'Virus Total'
        Hash_button_DB['vt_hash_true'] = True
    elif engine == 'hybrid':
        Hash_button_DB['hybrid_hash_label'] = 'Hybrid Analysis'
        Hash_button_DB['hybrid_hash_true'] = True

    #Creates the Window with all the buttons of the IOC engines. When pressing a button you will see the result of that engine.
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        please_wait_text = dpg.add_text('Some IOC engie may take up to 65 seconds', pos=[340, 85])
        alien_button = dpg.add_button(label=Hash_button_DB['alien_hash_label'], width=120, height=65, callback=show_alien_results_hash, pos=[15, 120], enabled=Hash_button_DB['alien_hash_true'])
        malbazaar_button = dpg.add_button(label=Hash_button_DB['malbazzar_hash_label'], width=120, height=65, callback=show_malbazaar_results_hash, pos=[15, 205], enabled=Hash_button_DB['malbazzar_hash_true'])
        URLhaus_button = dpg.add_button(label=Hash_button_DB['URLhaus_hash_label'], width=120, height=65, callback=show_URLhaus_results_hash, pos=[15, 290], enabled=Hash_button_DB['URLhaus_hash_true'])
        vt_button = dpg.add_button(label=Hash_button_DB['vt_hash_label'], width=120, height=65, callback=show_vt_results_hash, pos=[15, 375], enabled=Hash_button_DB['vt_hash_true'])
        hybrid_button = dpg.add_button(label=Hash_button_DB['hybrid_hash_label'], width=120, height=65, callback=show_hybrid_results_hash, pos=[15, 460], enabled=Hash_button_DB['hybrid_hash_true'])



'''This window shows the result of the Alien Vault OTX API.
Because the report is just a MASSIVE (up to 4MB) Static analysis, we just return if the hash was reported or not '''
def show_alien_results_hash():
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        ioc_text = dpg.add_text("IOC:  "+ Hash_button_DB['tagger'].get_ioc(), pos=[15, 45])
        please_wait_text = dpg.add_text('Alien Vault OTX results', pos=[340, 85])
        alien_button = dpg.add_button(label=Hash_button_DB['alien_hash_label'], width=120, height=65,callback=show_alien_results_hash, pos=[15, 120], enabled=False)
        malbazaar_button = dpg.add_button(label=Hash_button_DB['malbazzar_hash_label'], width=120, height=65, callback=show_malbazaar_results_hash, pos=[15, 205], enabled=Hash_button_DB['malbazzar_hash_true'])
        URLhaus_button = dpg.add_button(label=Hash_button_DB['URLhaus_hash_label'], width=120, height=65, callback=show_URLhaus_results_hash, pos=[15, 290], enabled=Hash_button_DB['URLhaus_hash_true'])
        vt_button = dpg.add_button(label=Hash_button_DB['vt_hash_label'], width=120, height=65, callback=show_vt_results_hash, pos=[15, 375], enabled=Hash_button_DB['vt_hash_true'])
        hybrid_button = dpg.add_button(label=Hash_button_DB['hybrid_hash_label'], width=120, height=65, callback=show_hybrid_results_hash, pos=[15, 460], enabled=Hash_button_DB['hybrid_hash_true'])

        # Checks if there was a report on the hash
        if Hash_search.alien_results == True:
            report_found_text = dpg.add_text('This hash was reported and analyzed at least once', pos=[170, 250], color=[144,238,144])
            full_report_text = dpg.add_text('Get full report: ', pos=[20, 570], color=[144,238,144])
            full_report_input = dpg.add_input_text(default_value="https://otx.alienvault.com/indicator/file/{}".format(Hash_button_DB['tagger'].get_ioc()), pos=[150, 570])
        else:
            report_not_found_text = dpg.add_text('This hash was never reported or analyzed', pos=[170, 250], color=[255, 0, 0])


'''This window shows the result of the Malware Bazaar API.'''
def show_malbazaar_results_hash():
    malbazzar_result = Hash_search.malbazzar_results
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        ioc_text = dpg.add_text("IOC:  "+ Hash_button_DB['tagger'].get_ioc(), pos=[15, 45])
        please_wait_text = dpg.add_text('Malware results', pos=[360, 85])
        alien_button = dpg.add_button(label=Hash_button_DB['alien_hash_label'], width=120, height=65, callback=show_alien_results_hash, pos=[15, 120], enabled=Hash_button_DB['alien_hash_true'])
        malbazaar_button = dpg.add_button(label=Hash_button_DB['malbazzar_hash_label'], width=120, height=65, callback=show_malbazaar_results_hash, pos=[15, 205], enabled=False)
        URLhaus_button = dpg.add_button(label=Hash_button_DB['URLhaus_hash_label'], width=120, height=65, callback=show_URLhaus_results_hash, pos=[15, 290], enabled=Hash_button_DB['URLhaus_hash_true'])
        vt_button = dpg.add_button(label=Hash_button_DB['vt_hash_label'], width=120, height=65, callback=show_vt_results_hash, pos=[15, 375], enabled=Hash_button_DB['vt_hash_true'])
        hybrid_button = dpg.add_button(label=Hash_button_DB['hybrid_hash_label'], width=120, height=65, callback=show_hybrid_results_hash, pos=[15, 460], enabled=Hash_button_DB['hybrid_hash_true'])

        #If the result is a list, it means malware bazaar has a report, as we get parsed data from that report in a list.
        if type(Hash_search.malbazzar_results) == list:
            ssdeep = dpg.add_text('SSDEEP:', pos=[170, 190])
            ssdeep_answer = dpg.add_input_text(default_value='{}'.format(malbazzar_result[0]), pos=[170, 210])
            tags = dpg.add_text('identification:', pos=[170, 250])
            if malbazzar_result[1] != None:
                tags_answer = dpg.add_input_text(default_value='{}'.format(", ".join(malbazzar_result[1])), pos=[170, 270])
            else:
                tags_answer = dpg.add_input_text(default_value='{}'.format(malbazzar_result[1]), pos=[170, 270])
            times_uploaded = dpg.add_text('Times uploaded by community:   {}'.format(malbazzar_result[2]), pos=[170, 325])
            yara = dpg.add_text('Number of YARA rules this file matched:   {}'.format(malbazzar_result[3]), pos=[170, 380])
            Triage_AV = dpg.add_text(r'3rd Party Anti Virus Score:   {}\10'.format(malbazzar_result[4]), pos=[170, 435])
            full_report_text = dpg.add_text('Get full report: ', pos=[20, 570], color=[144,238,144])
            full_report_input = dpg.add_input_text(default_value="https://bazaar.abuse.ch/sample/{}".format(Hash_button_DB['tagger'].get_ioc()), pos=[150, 570])



        # This means that Malware bazzar didn't have a report on the hash
        elif malbazzar_result == 'No available report':
            report_not_found_text = dpg.add_text('This hash was NOT reported', pos=[170, 250])

        #If we got an error, it will show it to the user in red.
        else:
            error = dpg.add_input_text(default_value='{}'.format(malbazzar_result), pos=[170, 125])



def show_URLhaus_results_hash():
    URLhaus_result = Hash_search.URLhaus_results
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        ioc_text = dpg.add_text("IOC:  "+ Hash_button_DB['tagger'].get_ioc(), pos=[15, 45])
        please_wait_text = dpg.add_text('URLhaus results', pos=[360, 85])
        alien_button = dpg.add_button(label=Hash_button_DB['alien_hash_label'], width=120, height=65, callback=show_alien_results_hash, pos=[15, 120], enabled=Hash_button_DB['alien_hash_true'])
        malbazaar_button = dpg.add_button(label=Hash_button_DB['malbazzar_hash_label'], width=120, height=65, callback=show_malbazaar_results_hash, pos=[15, 205], enabled=Hash_button_DB['malbazzar_hash_true'])
        URLhaus_button = dpg.add_button(label=Hash_button_DB['URLhaus_hash_label'], width=120, height=65, callback=show_URLhaus_results_hash, pos=[15, 290], enabled=False)
        vt_button = dpg.add_button(label=Hash_button_DB['vt_hash_label'], width=120, height=65, callback=show_vt_results_hash, pos=[15, 375], enabled=Hash_button_DB['vt_hash_true'])
        hybrid_button = dpg.add_button(label=Hash_button_DB['hybrid_hash_label'], width=120, height=65, callback=show_hybrid_results_hash, pos=[15, 460], enabled=Hash_button_DB['hybrid_hash_true'])


        # If the result is a list, it means URLhaus has a report, as we get parsed data from that report in a list.
        if type(Hash_search.URLhaus_results) == list:
            ssdeep = dpg.add_text('SSDEEP:', pos=[170, 180])
            ssdeep_answer = dpg.add_input_text(default_value='{}'.format(URLhaus_result[1]), pos=[170, 200])
            tags = dpg.add_text('identification:', pos=[170, 250])
            tags_answer = dpg.add_input_text(default_value='{}'.format(URLhaus_result[0]), pos=[170, 270])
            related_urls = dpg.add_text("URL's related to the hash:  {}".format(len(URLhaus_result[2])), pos=[170, 320])
            related_urls_answer = dpg.add_input_text(default_value='{}'.format("\n\n".join(URLhaus_result[2])),pos=[170, 340])
            if len(URLhaus_result[2]) > 1:
                tags = dpg.add_text('Copy the output to see all URL\'s', pos=[170, 360])
            full_report_text = dpg.add_text('Get full report: ', pos=[20, 570], color=[144,238,144])
            full_report_input = dpg.add_input_text(default_value="https://urlhaus.abuse.ch/browse.php?search={}".format(Hash_button_DB['tagger'].get_ioc()), pos=[150, 570])



        # This means that URLhaus didn't have a report on the hash
        elif URLhaus_result == 'No available report':
            report_not_found_text = dpg.add_text('This hash was NOT reported', pos=[170, 250])


        # If we got an error, it will show it to the user.
        else:
            error = dpg.add_input_text(default_value='{}'.format(URLhaus_result), pos=[170, 125])



def show_vt_results_hash():
    vt_result = Hash_search.vt_results
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        ioc_text = dpg.add_text("IOC:  "+ Hash_button_DB['tagger'].get_ioc(), pos=[15, 45])
        please_wait_text = dpg.add_text('VirusTotal results', pos=[360, 85])
        alien_button = dpg.add_button(label=Hash_button_DB['alien_hash_label'], width=120, height=65, callback=show_alien_results_hash, pos=[15, 120], enabled=Hash_button_DB['alien_hash_true'])
        malbazaar_button = dpg.add_button(label=Hash_button_DB['malbazzar_hash_label'], width=120, height=65, callback=show_malbazaar_results_hash, pos=[15, 205], enabled=Hash_button_DB['malbazzar_hash_true'])
        URLhaus_button = dpg.add_button(label=Hash_button_DB['URLhaus_hash_label'], width=120, height=65, callback=show_URLhaus_results_hash, pos=[15, 290], enabled=Hash_button_DB['URLhaus_hash_true'])
        vt_button = dpg.add_button(label=Hash_button_DB['vt_hash_label'], width=120, height=65, callback=show_vt_results_hash, pos=[15, 375], enabled=False)
        hybrid_button = dpg.add_button(label=Hash_button_DB['hybrid_hash_label'], width=120, height=65, callback=show_hybrid_results_hash, pos=[15, 460], enabled=Hash_button_DB['hybrid_hash_true'])


        # If the result is a list, it means VT has a report, as we get parsed data from that report in a list.
        if type(Hash_search.vt_results) == list:
            SSDEEP = dpg.add_text('SSDEEP: ', pos=[170, 150])
            SSDEEP_answer = dpg.add_input_text(default_value='{}'.format(vt_result[2]), pos=[170, 170])
            file_type = dpg.add_text('File type:  {}'.format(vt_result[0]), pos=[170, 220])
            AV_detctions = dpg.add_text('Number of AntiVirus detections:  {}'.format(vt_result[3]), pos=[170, 270])
            Great_4 = dpg.add_text("Most trustworthy AntiVirus scores", pos=[170, 320])
            Great_4_answer = dpg.add_input_text(default_value='ESET: {}  |  Kaspersky: {}  |   Microsoft: {}  |  MalwareBytes: {}'.format(vt_result[4], vt_result[5], vt_result[6], vt_result[7]), pos=[170, 340])
            tags = dpg.add_text('Classification: ', pos=[170, 380])
            tags_answer = dpg.add_input_text(default_value='{}'.format(", ".join(vt_result[8])), pos=[170, 400])
            times_submited = dpg.add_text('Number of users that submited this hash:  {}'.format(vt_result[1]), pos=[170, 445])
            community = dpg.add_text('{}'.format(vt_result[9]), pos=[170, 485])
            full_report_text = dpg.add_text('Get full report: ', pos=[20, 570], color=[144,238,144])
            full_report_input = dpg.add_input_text(default_value="https://www.virustotal.com/gui/file/{}".format(Hash_button_DB['tagger'].get_ioc()), pos=[150, 570])


        # This means that VirusTotal didn't have a report on the hash
        elif vt_result == "hash wasn't found":
            report_not_found_text = dpg.add_text('This hash was NOT reported', pos=[170, 250])


        # If we got an error, it will show it to the user.
        else:
            error = dpg.add_input_text(default_value='{}'.format(vt_result), pos=[170, 125])




def show_hybrid_results_hash():
    hybrid_result = Hash_search.hybrid_results
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        ioc_text = dpg.add_text("IOC:  "+ Hash_button_DB['tagger'].get_ioc(), pos=[15, 45])
        please_wait_text = dpg.add_text('Hybrid Analysis results', pos=[360, 85])
        alien_button = dpg.add_button(label=Hash_button_DB['alien_hash_label'], width=120, height=65, callback=show_alien_results_hash, pos=[15, 120], enabled=Hash_button_DB['alien_hash_true'])
        malbazaar_button = dpg.add_button(label=Hash_button_DB['malbazzar_hash_label'], width=120, height=65, callback=show_malbazaar_results_hash, pos=[15, 205], enabled=Hash_button_DB['malbazzar_hash_true'])
        URLhaus_button = dpg.add_button(label=Hash_button_DB['URLhaus_hash_label'], width=120, height=65, callback=show_URLhaus_results_hash, pos=[15, 290], enabled=Hash_button_DB['URLhaus_hash_true'])
        vt_button = dpg.add_button(label=Hash_button_DB['vt_hash_label'], width=120, height=65, callback=show_vt_results_hash, pos=[15, 375], enabled=Hash_button_DB['vt_hash_true'])
        hybrid_button = dpg.add_button(label=Hash_button_DB['hybrid_hash_label'], width=120, height=65, callback=show_hybrid_results_hash, pos=[15, 460], enabled=False)


        # If the result is a list, it means Hybrid Analysis has a report, as we get parsed data from that report in a list.
        if type(Hash_search.hybrid_results) == list:
            score = dpg.add_text('maliciousness score:  {}'.format(hybrid_result[0]), pos=[170, 180])
            AV_detections = dpg.add_text('Number of AntiVirus detections:  {}'.format(hybrid_result[1]), pos=[170, 220])
            tags = dpg.add_text('Classification: ', pos=[170, 260])
            tags_answer = dpg.add_input_text(default_value='{}'.format(", ".join(hybrid_result[4])), pos=[170, 280])
            number_of_mitre_techniques = dpg.add_text('Number of MITRE techniques used by this file:  {}'.format(hybrid_result[3]), pos=[170, 320])
            full_report_text = dpg.add_text('Get full report: ', pos=[20, 570], color=[144,238,144])
            full_report_input = dpg.add_input_text(default_value="https://www.hybrid-analysis.com/sample/{}".format(Hash_button_DB['tagger'].get_ioc()), pos=[150, 570])



        # This means that Hybrid Analysis didn't have a report on the hash
        elif hybrid_result == "No available report":
            report_not_found_text = dpg.add_text('This hash was NOT reported', pos=[170, 250])


        # If we got an error, it will show it to the user.
        else:
            error = dpg.add_input_text(default_value='{}'.format(hybrid_result), pos=[170, 125])

################################################# END OF HASH SEARCH ##########################################################


################################################# START OF IP SEARCH ##########################################################

'''
This window will pop after the user selects the IPv4 option in the Start_window.
It will get a IP and send it over to -  initiate_ip_search   '''
def search_ip():
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        text = dpg.add_text('Type the IP', pos=[350, 160])
        type_ip = dpg.add_input_text(width=560, pos=[115, 200])
        submit_button = dpg.add_button(label='Submit', pos=[375, 280], callback=initiate_ip_search,user_data=type_ip)


'''
The function gets 3 arguments even though we sent only 1.
When sending a DearPyGui widget, it "splits" to 3 and only the last one is actually the parameter we sent '''
def initiate_ip_search(sender='Ignore', app_data='Ignore', item='the element'):
    # Gets the value (IP) from the sent widget
    ip_to_search = dpg.get_value(item)

    Hash_button_DB['tagger'].set_ioc(ip_to_search)

    # Starting all the IOC engines API in IP_search.py
    IP_search_thread = threading.Thread(target=IP_search.start_all, args=[ip_to_search, Hash_button_DB['validator'].get_counter()])
    IP_search_thread.start()

    # Creating the window with all the Engines buttons. You can't on an IOC engine button until his corresponding API isnt finished
    results_window_ip()



'''When first called this just crates a window with unpressable buttons.
Later the API's themselves call this function. When an API calls the function it sends it's name as well.
Then the Button of the API will change it text and be pressable'''
def results_window_ip(engine = 'waiting for IOC engiens to finish reports'):
    # This part checks who called the function, and acts accordingly.
    if engine == 'alien':
        IP_button_DB['alien_ip_label'] = 'Alien Vault OTX'
        IP_button_DB['alien_ip_true'] = True
    elif engine == 'abusedb':
        IP_button_DB['abusedb_ip_label'] = 'AbuseDB IP'
        IP_button_DB['abusedb_ip_true'] = True
    elif engine == 'vt':
        IP_button_DB['vt_ip_label'] = 'Virus Total'
        IP_button_DB['vt_ip_true'] = True


    # Creates the Window with all the buttons of the IOC engines. When pressing a button you will see the result of that engine.
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        please_wait_text = dpg.add_text('VirusTotal report will be ready in 80 seconds, as it rescans the IP', pos=[140, 85])
        alien_button = dpg.add_button(label=IP_button_DB['alien_ip_label'], width=120, height=65, callback=show_alien_results_ip, pos=[15, 170], enabled=IP_button_DB['alien_ip_true'])
        abusedb_button = dpg.add_button(label=IP_button_DB['abusedb_ip_label'], width=120, height=65, callback=show_abusedb_results_ip, pos=[15, 270], enabled=IP_button_DB['abusedb_ip_true'])
        vt_button = dpg.add_button(label=IP_button_DB['vt_ip_label'], width=120, height=65, callback=show_vt_results_ip, pos=[15, 370], enabled=IP_button_DB['vt_ip_true'])


'''This window shows the result of the Alien Vault OTX API.'''
def show_alien_results_ip():
    alien_result = IP_search.alien_results
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        ioc_text = dpg.add_text("IOC:  " + Hash_button_DB['tagger'].get_ioc(), pos=[15, 45])
        please_wait_text = dpg.add_text('Alien Vault OTX results', pos=[360, 85])
        alien_button = dpg.add_button(label=IP_button_DB['alien_ip_label'], width=120, height=65, callback=show_alien_results_ip, pos=[15, 170], enabled=False)
        abusedb_button = dpg.add_button(label=IP_button_DB['abusedb_ip_label'], width=120, height=65, callback=show_abusedb_results_ip, pos=[15, 270], enabled=IP_button_DB['abusedb_ip_true'])
        vt_button = dpg.add_button(label=IP_button_DB['vt_ip_label'], width=120, height=65, callback=show_vt_results_ip, pos=[15, 370], enabled=IP_button_DB['vt_ip_true'])
        full_report_text = dpg.add_text('Get full report: ', pos=[20, 570], color=[144, 238, 144])
        full_report_input = dpg.add_input_text(default_value="https://otx.alienvault.com/indicator/ip/{}".format(Hash_button_DB['tagger'].get_ioc()), pos=[150, 570])

        #Not an error
        if type(alien_result) == list:
            reports_amount = dpg.add_text('Number of reports on this IP:  {}'.format(IP_search.alien_results[0]), pos=[170, 230])
            last_report_modified = dpg.add_text('Last report date:  {}'.format(IP_search.alien_results[1].replace('T', '    ')[:10]), pos=[170, 290])
            country = dpg.add_text('IP\'s country:  {}'.format(IP_search.alien_results[2]), pos=[170, 350])


        # If we got an error, it will show it to the user.
        else:
            error = dpg.add_input_text(default_value='{}'.format(alien_result), pos=[170, 125])



'''This window shows the result of the AbuseDB IP API.'''
def show_abusedb_results_ip():
    abusedb_result = IP_search.abusedb_results
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        ioc_text = dpg.add_text("IOC:  " + Hash_button_DB['tagger'].get_ioc(), pos=[15, 45])
        please_wait_text = dpg.add_text('AbuseDB IP results', pos=[360, 85])
        alien_button = dpg.add_button(label=IP_button_DB['alien_ip_label'], width=120, height=65, callback=show_alien_results_ip, pos=[15, 170], enabled=IP_button_DB['alien_ip_true'])
        abusedb_button = dpg.add_button(label=IP_button_DB['abusedb_ip_label'], width=120, height=65, callback=show_abusedb_results_ip, pos=[15, 270], enabled=False)
        vt_button = dpg.add_button(label=IP_button_DB['vt_ip_label'], width=120, height=65, callback=show_vt_results_ip, pos=[15, 370], enabled=IP_button_DB['vt_ip_true'])


        # Not an error
        if type(abusedb_result) == list:
            Malicious_score = dpg.add_text('maliciousness score:  {}'.format(abusedb_result[0]), pos=[170, 210])
            total_reports_in_last_30 = dpg.add_text('Number of reports in last 30 days:  {}'.format(abusedb_result[1]), pos=[170, 250])
            last_report_date = dpg.add_text('Last report date:  {}'.format(abusedb_result[2].replace('T', '    ')[:10]), pos=[170, 290])
            Domain = dpg.add_text('Domain name:  {}'.format(abusedb_result[3]), pos=[170, 330])
            country = dpg.add_text('IP\'s country:  {}'.format(IP_search.alien_results[2]), pos=[170, 370])
            full_report_text = dpg.add_text('Get full report: ', pos=[20, 570], color=[144,238,144])
            full_report_input = dpg.add_input_text(default_value="https://www.abuseipdb.com/check/{}".format(Hash_button_DB['tagger'].get_ioc()), pos=[150, 570])



        # If we got an error, it will show it to the user.
        else:
            error = dpg.add_input_text(default_value='{}'.format(abusedb_result), pos=[170, 125])



'''This window shows the result of the VirusTotal API.'''
def show_vt_results_ip():
    vt_result = IP_search.vt_results
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        ioc_text = dpg.add_text("IOC:  " + Hash_button_DB['tagger'].get_ioc(), pos=[15, 45])
        please_wait_text = dpg.add_text('VirusTotal results', pos=[360, 85])
        alien_button = dpg.add_button(label=IP_button_DB['alien_ip_label'], width=120, height=65, callback=show_alien_results_ip, pos=[15, 170], enabled=IP_button_DB['alien_ip_true'])
        abusedb_button = dpg.add_button(label=IP_button_DB['abusedb_ip_label'], width=120, height=65, callback=show_abusedb_results_ip, pos=[15, 270], enabled=IP_button_DB['abusedb_ip_true'])
        vt_button = dpg.add_button(label=IP_button_DB['vt_ip_label'], width=120, height=65, callback=show_vt_results_ip, pos=[15, 370], enabled=False)
        full_report_text = dpg.add_text('Get full report: ', pos=[20, 570], color=[144, 238, 144])
        full_report_input = dpg.add_input_text(default_value="https://www.virustotal.com/gui/ip-address/{}".format(Hash_button_DB['tagger'].get_ioc()), pos=[150, 570])

        # Not an error
        if type(vt_result) == list:
            Malicious_detections = dpg.add_text('How many AntiViruses marked the IP as Malicious:  {}'.format(vt_result[0]), pos=[170, 210])
            Suspicious_detections = dpg.add_text('How many AntiViruses marked the IP as Suspicious:  {}'.format(vt_result[1]), pos=[170, 260])
            Which_AV_detected = dpg.add_text('Which AntiVirus detected this IP: ', pos=[170, 310])
            Which_AV_detected_answer = dpg.add_input_text(default_value='{}'.format(", ".join(vt_result[2])), pos=[170, 330])


        # If we got an error, it will show it to the user in red.
        else:
            error = dpg.add_input_text(default_value='{}'.format(vt_result), pos=[170, 125])


################################################# END OF IP SEARCH ##########################################################


################################################# START OF URL SEARCH ##########################################################


'''
This window will pop after the user selects the URL option in the Start_window.
It will get a URL and send it over to -  initiate_ip_search   '''
def search_url():
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        text = dpg.add_text('Type the URL', pos=[350, 160])
        type_hash = dpg.add_input_text(width=560, pos=[115, 200])
        submit_button = dpg.add_button(label='Submit', pos=[375, 280], callback=initiate_url_search,user_data=type_hash)



'''
The function gets 3 arguments even though we sent only 1.
When sending a DearPyGui widget, it "splits" to 3 and only the last one is actually the parameter we sent '''
def initiate_url_search(sender='Ignore', app_data='Ignore', item='the element'):
    # Gets the value (hash) from the sent widget
    url_to_search = dpg.get_value(item)

    Hash_button_DB['tagger'].set_ioc(url_to_search)

    # Starting all the IOC engines API in IP_search.py
    url_search_thread = threading.Thread(target=URL_search.start_all, args=[url_to_search, Hash_button_DB['validator'].get_counter()])
    url_search_thread.start()

    # Creating the window with all the Engines buttons. You can't on an IOC engine button until his corresponding API isnt finished
    results_window_URL()



'''When first called, this just crates a window with unpressable buttons.
Later the API's themselves call this function. When an API calls the function it sends it's name as well.
Then the Button of the API will change it text and be pressable'''
def results_window_URL(engine = 'waiting for IOC engiens to finish reports'):
    # This part checks who called the function, and acts accordingly.
    if engine == 'URLhaus':
        URL_button_DB['URLhaus_url_label'] = 'URLhaus'
        URL_button_DB['URLhaus_url_true'] = True
    elif engine == 'alien':
        URL_button_DB['alien_url_label'] = 'Alien Vault OTX'
        URL_button_DB['alien_url_true'] = True
    elif engine == 'hybrid':
        URL_button_DB['hybrid_url_label'] = 'Hybrid Analysis'
        URL_button_DB['hybrid_url_true'] = True
    elif engine == 'vt':
        URL_button_DB['vt_url_label'] = 'Virus Total'
        URL_button_DB['vt_url_true'] = True


    # Creates the Window with all the buttons of the IOC engines. When pressing a button you will see the result of that engine.
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        please_wait_text = dpg.add_text('VirusTotal report will be ready in 80 seconds, as it rescans the URL', pos=[140, 85])
        URLhaus_button = dpg.add_button(label=URL_button_DB['URLhaus_url_label'], width=120, height=65, callback=show_URLhaus_results_url, pos=[15, 170], enabled=URL_button_DB['URLhaus_url_true'])
        alien_button = dpg.add_button(label=URL_button_DB['alien_url_label'], width=120, height=65, callback=show_alien_results_url, pos=[15, 270], enabled=URL_button_DB['alien_url_true'])
        hybrid_button = dpg.add_button(label=URL_button_DB['hybrid_url_label'], width=120, height=65, callback=show_hybrid_results_url, pos=[15, 370], enabled=URL_button_DB['hybrid_url_true'])
        vt_button = dpg.add_button(label=URL_button_DB['vt_url_label'], width=120, height=65, callback=show_vt_results_url, pos=[15, 470], enabled=URL_button_DB['vt_url_true'])


'''This window shows the result of the URLhaus API.'''
def show_URLhaus_results_url():
    URLhaus_result = URL_search.URLhaus_results
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        ioc_text = dpg.add_text("IOC:  " + Hash_button_DB['tagger'].get_ioc(), pos=[15, 45])
        please_wait_text = dpg.add_text('URLhaus results', pos=[350, 85])
        URLhaus_button = dpg.add_button(label=URL_button_DB['URLhaus_url_label'], width=120, height=65, callback=show_URLhaus_results_url, pos=[15, 170], enabled=False)
        alien_button = dpg.add_button(label=URL_button_DB['alien_url_label'], width=120, height=65, callback=show_alien_results_url, pos=[15, 270], enabled=URL_button_DB['alien_url_true'])
        hybrid_button = dpg.add_button(label=URL_button_DB['hybrid_url_label'], width=120, height=65, callback=show_hybrid_results_url, pos=[15, 370], enabled=URL_button_DB['hybrid_url_true'])
        vt_button = dpg.add_button(label=URL_button_DB['vt_url_label'], width=120, height=65, callback=show_vt_results_url, pos=[15, 470], enabled=URL_button_DB['vt_url_true'])

        # If the result is a list, it means URLhaus has a report, as we get parsed data from that report in a list.
        if type(URLhaus_result) == list:
            alive  = dpg.add_text('URL status at the time of the report:  {}'.format(URLhaus_result[0]), pos=[170, 220])
            date = dpg.add_text('When was the URL reported:  {}'.format(URLhaus_result[1]), pos=[170, 280])
            tags = dpg.add_text('Classification: ', pos=[170, 340])
            if type(URLhaus_result[2]) == list:
                tags_answer = dpg.add_input_text(default_value='{}'.format(', '.join(URLhaus_result[2])), pos=[170, 360])
            else:
                tags_answer = dpg.add_input_text(default_value='{}'.format(''), pos=[170, 360])
            query_id = URLhaus_result[3]
            full_report_text = dpg.add_text('Get full report: ', pos=[20, 570], color=[144,238,144])
            full_report_input = dpg.add_input_text(default_value="https://urlhaus.abuse.ch/url/{}/".format(query_id), pos=[150, 570])



        # This means that URLhaus didn't have a report on the hash
        elif URLhaus_result == "No available report":
            report_not_found_text = dpg.add_text('This URL was NOT reported', pos=[170, 300])

        # If we got an error, it will show it to the user.
        else:
            error = dpg.add_input_text(default_value='{}'.format(URLhaus_result), pos=[170, 125])



def show_alien_results_url():
    alien_result = URL_search.alien_results
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        ioc_text = dpg.add_text("IOC:  " + Hash_button_DB['tagger'].get_ioc(), pos=[15, 45])
        please_wait_text = dpg.add_text('Alien vault OTX results', pos=[320, 85])
        URLhaus_button = dpg.add_button(label=URL_button_DB['URLhaus_url_label'], width=120, height=65, callback=show_URLhaus_results_url, pos=[15, 170], enabled=URL_button_DB['URLhaus_url_true'])
        alien_button = dpg.add_button(label=URL_button_DB['alien_url_label'], width=120, height=65, callback=show_alien_results_url, pos=[15, 270], enabled=False)
        hybrid_button = dpg.add_button(label=URL_button_DB['hybrid_url_label'], width=120, height=65, callback=show_hybrid_results_url, pos=[15, 370], enabled=URL_button_DB['hybrid_url_true'])
        vt_button = dpg.add_button(label=URL_button_DB['vt_url_label'], width=120, height=65, callback=show_vt_results_url, pos=[15, 470], enabled=URL_button_DB['vt_url_true'])


        # If the result is a list, it means Alien Vault OTX has a report, as we get parsed data from that report in a list.
        if type(alien_result) == list:
            alive = dpg.add_text('Response code:  {}'.format(alien_result[0]), pos=[170, 220])
            date = dpg.add_text('When was the URL reported:  {}'.format(alien_result[1]), pos=[170, 280])
            hash = dpg.add_text('File that was downloaded from the URL: ', pos=[170, 340])
            if type(alien_result[2]) != None:
                hash_answer = dpg.add_input_text(default_value='{}'.format(alien_result[2]), pos=[170, 360])
            else:
                hash_answer = dpg.add_input_text(default_value='No hash is available', pos=[170, 360])
            country = dpg.add_text('Country:   {}'.format(alien_result[3]), pos=[170, 420])
            full_report_text = dpg.add_text('Get full report: ', pos=[20, 570], color=[144, 238, 144])
            full_report_input = dpg.add_input_text(default_value="https://otx.alienvault.com/indicator/url/{}".format(Hash_button_DB['tagger'].get_ioc()), pos=[150, 570])



        # This means that URLhaus didn't have a report on the hash
        elif alien_result == "No available report":
            report_not_found_text = dpg.add_text('This URL was NOT reported', pos=[170, 300])

        # If we got an error, it will show it to the user.
        else:
            error = dpg.add_input_text(default_value='{}'.format(alien_result), pos=[170, 125])



def show_hybrid_results_url():
    hybrid_result = URL_search.hybrid_results
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        ioc_text = dpg.add_text("IOC:  " + Hash_button_DB['tagger'].get_ioc(), pos=[15, 45])
        please_wait_text = dpg.add_text('Hybrid Analysis results', pos=[320, 85])
        URLhaus_button = dpg.add_button(label=URL_button_DB['URLhaus_url_label'], width=120, height=65, callback=show_URLhaus_results_url, pos=[15, 170], enabled=URL_button_DB['URLhaus_url_true'])
        alien_button = dpg.add_button(label=URL_button_DB['alien_url_label'], width=120, height=65, callback=show_alien_results_url, pos=[15, 270], enabled=URL_button_DB['alien_url_true'])
        hybrid_button = dpg.add_button(label=URL_button_DB['hybrid_url_label'], width=120, height=65, callback=show_hybrid_results_url, pos=[15, 370], enabled=False)
        vt_button = dpg.add_button(label=URL_button_DB['vt_url_label'], width=120, height=65, callback=show_vt_results_url, pos=[15, 470], enabled=URL_button_DB['vt_url_true'])


        # If the result is a list, it means Alien Vault OTX has a report, as we get parsed data from that report in a list.
        if type(hybrid_result) == list:
            alive = dpg.add_text('Hybrid analysis :  {}'.format(hybrid_result[0]), pos=[170, 220])
            datections = dpg.add_text('How many vendors detected the URL:  {}'.format(hybrid_result[1]), pos=[170, 280])

        # This means that URLhaus didn't have a report on the hash
        elif hybrid_result == "No available report":
            report_not_found_text = dpg.add_text('This URL was NOT reported', pos=[170, 300])

        # If we got an error, it will show it to the user.
        else:
            error = dpg.add_input_text(default_value='{}'.format(hybrid_result), pos=[170, 125])


def show_vt_results_url():
    vt_result = URL_search.vt_results
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        start_window_button = dpg.add_button(label='Home', width=40, height=20, callback=start_window, pos=[15, 25])
        ioc_text = dpg.add_text("IOC:  " + Hash_button_DB['tagger'].get_ioc(), pos=[15, 45])
        please_wait_text = dpg.add_text('Virus Total results', pos=[320, 85])
        URLhaus_button = dpg.add_button(label=URL_button_DB['URLhaus_url_label'], width=120, height=65, callback=show_URLhaus_results_url, pos=[15, 170], enabled=URL_button_DB['URLhaus_url_true'])
        alien_button = dpg.add_button(label=URL_button_DB['alien_url_label'], width=120, height=65, callback=show_alien_results_url, pos=[15, 270], enabled=URL_button_DB['alien_url_true'])
        hybrid_button = dpg.add_button(label=URL_button_DB['hybrid_url_label'], width=120, height=65, callback=show_hybrid_results_url, pos=[15, 370], enabled=URL_button_DB['hybrid_url_true'])
        vt_button = dpg.add_button(label=URL_button_DB['vt_url_label'], width=120, height=65, callback=show_vt_results_url, pos=[15, 470], enabled=False)


        # If the result is a list, it means Alien Vault OTX has a report, as we get parsed data from that report in a list.
        if type(vt_result) == list:
            malicious = dpg.add_text('How many vendors detected the URL as malicious:  {}'.format(vt_result[0]), pos=[170, 220])
            suspicious = dpg.add_text('How many vendors detected the URL as suspicious:  {}'.format(vt_result[1]), pos=[170, 280])
            av_names = dpg.add_text('Which vendors flagged this URL:', pos=[170, 340])
            av_names_anser = dpg.add_input_text(default_value='{}'.format(", ".join(vt_result[2])), pos=[170, 360])
            full_report_text = dpg.add_text('Get full report: ', pos=[20, 570], color=[144,238,144])
            full_report_input = dpg.add_input_text(default_value="https://www.virustotal.com/gui/url/{}".format(vt_result[3].split("-")[1]), pos=[150, 570])


        # This means that URLhaus didn't have a report on the hash
        elif vt_result == "Analysis wasn't completed in 80 seconds, please try again":
            report_not_found_text = dpg.add_text("Analysis wasn't completed in 80 seconds, please try again", pos=[170, 300])

        # If we got an error, it will show it to the user.
        else:
            error = dpg.add_input_text(default_value='{}'.format(vt_result), pos=[170, 125])


################################################# END OF URL SEARCH ##########################################################


################################################# START OF LOCAL FILE #########################################################

def local_file_get_hash():
    hash_to_search = Calc_hash.hash_a_file()
    initiate_Hash_search(item=hash_to_search)

################################################# END OF LOCAL FILE ###########################################################


def start_window():
     # Brings back the Engines button configurations to base line, so they will be ready for another analysis
    reset_engines_buttons_parameters()

    Hash_button_DB['validator'].counter_add_1()

    #Creating the start_window with 3 buttons, One for each IOC type + one for local file.
    with dpg.window(tag=Hash_button_DB['tagger'].new_tag(), label='Ultimate IOC engine', width=820, height=630):
        header_text = dpg.add_text('select IOC type', color=[133, 100, 42], pos=[355, 100])
        hash_button = dpg.add_button(label='MD5 & SHA256', width=150, height=150, callback=search_hash, pos=[25, 150])
        ip_button = dpg.add_button(label='IPv4', width=150, height=150,callback=search_ip, pos=[225, 150])
        url_button = dpg.add_button(label='URL and Domain', width=150, height=150, callback=search_url, pos=[425, 150])
        local_file_button = dpg.add_button(label='Search report\non Local file', width=150, height=150, callback=local_file_get_hash, pos=[625, 150])




if __name__ == "__main__":
    tagger = tag_handler()
    Hash_button_DB['tagger'] = tagger
    validator = request_validator()
    Hash_button_DB['validator'] = validator

    try:
        if os.path.exists(Hash_button_DB['validator'].get_validator_path()):
            shutil.rmtree(Hash_button_DB['validator'].get_validator_path())
        os.mkdir(Hash_button_DB['validator'].get_validator_path())
    except:
        pass

    #This part create the GUI
    dpg.create_context()

    #Sends us to the function that creates the first window
    start_window()

    dpg.create_viewport(title='Ultimate IOC engine. By: SilverPlate3', width=820, height=630, y_pos=20)
    dpg.setup_dearpygui()
    dpg.show_viewport()


    while dpg.is_dearpygui_running():
        #Code that will run in loops
        pass
        dpg.render_dearpygui_frame()

    dpg.destroy_context()


