# Resetting the engines button configurations
def reset_engines_buttons_parameters():
    Hash_button_DB['alien_hash_label'] = 'Alien Vault OTX \nStill Analyzing'
    Hash_button_DB['alien_hash_true'] = False

    Hash_button_DB['malbazzar_hash_label'] = 'Malware Bazaar \nStill Analyzing'
    Hash_button_DB['malbazzar_hash_true'] = False

    Hash_button_DB['URLhaus_hash_label'] = 'URLhaus \nStill Analyzing'
    Hash_button_DB['URLhaus_hash_true'] = False

    Hash_button_DB['vt_hash_label'] = 'Virus Total \nStill Analyzing'
    Hash_button_DB['vt_hash_true'] = False

    Hash_button_DB['hybrid_hash_label'] = 'Hybrid Analysis\nStill Analyzing'
    Hash_button_DB['hybrid_hash_true'] = False

    IP_button_DB['alien_ip_label'] = 'Alien Vault OTX \nStill Analyzing'
    IP_button_DB['alien_ip_true'] = False

    IP_button_DB['abusedb_ip_label'] = 'AbuseDB IP \nStill Analyzing'
    IP_button_DB['abusedb_ip_true'] = False

    IP_button_DB['vt_ip_label'] = 'Virus Total \nStill Analyzing'
    IP_button_DB['vt_ip_true'] = False

    URL_button_DB['URLhaus_url_label'] = 'URLhaus \nStill Analyzing'
    URL_button_DB['URLhaus_url_true'] = False

    URL_button_DB['alien_url_label'] = 'Alien Vault OTX \nStill Analyzing'
    URL_button_DB['alien_url_true'] = False

    URL_button_DB['vt_url_label'] = 'Virus Total \nStill Analyzing'
    URL_button_DB['vt_url_true'] = False

    URL_button_DB['hybrid_url_label'] = 'Hybrid Analysis \nStill Analyzing'
    URL_button_DB['hybrid_url_true'] = False


Hash_button_DB = {
                  'alien_hash_true': False,
                  'malbazzar_hash_true': False,
                  'URLhaus_hash_true': False,
                  'vt_hash_true': False,
                  'hybrid_hash_true': False,
                  'alien_hash_label': 'Alien Vault OTX \nStill Analyzing',
                  'malbazzar_hash_label': 'Malware Bazaar\nStill Analyzing',
                  'URLhaus_hash_label': 'URLhaus\nStill Analyzing',
                  'vt_hash_label': 'Virus Total\nStill Analyzing',
                  'hybrid_hash_label': 'Hybrid Analysis\nStill Analyzing',
                  'tagger': "This will be replaced with the tagger instance",
                  'validator': 'This will be replaced with the validator instance'

                  }


IP_button_DB = {
    'abusedb_ip_true': False,
    'alien_ip_true': False,
    'vt_ip_true': False,
    'abusedb_ip_label': 'AbuseDB IP \nStill Analyzing',
    'alien_ip_label': 'Alien Vault OTX \nStill Analyzing',
    'vt_ip_label': 'Virus Total\nStill Analyzing',
    'tagger': "This will be replaced with the tagger instance"
}


URL_button_DB = {
                  'alien_url_true': False,
                  'URLhaus_url_true': False,
                  'vt_url_true': False,
                  'hybrid_url_true': False,
                  'alien_url_label': 'Alien Vault OTX \nStill Analyzing',
                  'URLhaus_url_label': 'URLhaus\nStill Analyzing',
                  'vt_url_label': 'Virus Total\nStill Analyzing',
                  'hybrid_url_label': 'Hybrid Analysis\nStill Analyzing',
                  'tagger': "This will be replaced with the tagger instance"
                  }
