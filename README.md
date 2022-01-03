# Ultimate_IOC_Engine
Stop relying only on VirusTotal!!!  Search IOC's and local files against the TOP 6 IOC engines in one click. Get the results parsed and see ONLY the valuable data. 



# How to start it 
This project is a Plug-and-play. You just need to download the full folder as it is and initiate the GUI.py file.



# API Keys
I gifted the project users, with 1 API key for each IOC engine.  
Some API keys have a max of 4 queries a minute and 500 a day. If you are planning  to only use the "built in" Keys you may have an issue, especially if other people use them as well.  
I suggest you add at least 2 API keys for each IOC engine.  
After that you should remove the "built in" API Key!

How can you add API keys?  
↓  
1) Create a user for each of the IOC engines. This will take you 10 minutes.  
Signup to VirusTotal  -  https://www.virustotal.com/gui/join-us  
Signuu to AlienVault  -  https://otx.alienvault.com/  
Signup to HybridAnalysis  -  https://www.hybrid-analysis.com/signup  
Signup to MalwareBazaar  -  https://bazaar.abuse.ch/   (You must have a twitter account for this)  
Signup to IPabuseDB   -   https://www.abuseipdb.com/register?plan=free    
Singup to URLhaus   -    No need for an API key  
↓
2) Generate API Keys for each user   
↓
3) Add the API key's into their corresponding lists in the API_keys.py file.  


#important to acknowledge
User agent - In every API, I specified that the User Agent of the machine is *Mozilla 5.0* as it's the most widely used.  
If this isn't the case on your machine please change EVERY API function in the files: search_hash.py, search_IP.py, search_URL.py
