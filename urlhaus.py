import os
from urllib.parse import urlparse
import requests


url = "https://urlhaus.abuse.ch/downloads/text/"
headers = {}


print("Sťahujem zoznam malware URL z URLhaus...")
response = requests.get(url, headers=headers)

if response.status_code == 200:
    transformovane_riadky = []
    
    for riadok in response.text.splitlines():
        riadok = riadok.strip()
        
        if not riadok or riadok.startswith("#"):
            continue
            
        try:
            url_na_parsovanie = riadok
            if not url_na_parsovanie.startswith(("http://", "https://")):
                url_na_parsovanie = "http://" + url_na_parsovanie
            
            parsed_url = urlparse(url_na_parsovanie)
            
            domena = parsed_url.netloc
            cesta = parsed_url.path
            

            if domena.startswith("www."):
                domena = domena[4:] 
            
            if parsed_url.query:
                cesta += "?" + parsed_url.query
            if parsed_url.fragment:
                cesta += "#" + parsed_url.fragment
                
            if not cesta:
                cesta = "/"
                
            novy_riadok = f"{domena},{cesta},URLhaus"
            transformovane_riadky.append(novy_riadok)
            
        except Exception as e:
            print(f"Preskakujem neplatnú URL: {riadok} (Chyba: {e})")
            continue

    with open("urlhaus_urls.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(transformovane_riadky))
        
    print(f"Zoznam bol úspešne transformovaný. Celkovo riadkov: {len(transformovane_riadky)}")
else:
    print(f"Chyba pri sťahovaní dát: {response.status_code}")
    exit(1)
