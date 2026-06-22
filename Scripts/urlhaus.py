import os
import re
from pathlib import Path
from urllib.parse import urlparse
import requests

url = "https://urlhaus.abuse.ch/downloads/text/"

print("Sťahujem zoznam malware URL z URLhaus...")
response = requests.get(url)

if response.status_code == 200:
    unikatne_riadky = set()
    
    port_regex = re.compile(r":\d{1,5}")
    
    for riadok in response.text.splitlines():
        riadok = riadok.strip()
        
        if not riadok or riadok.startswith("#"):
            continue
            
        try:
            url_na_parsovanie = riadok
            if not url_na_parsovanie.startswith(("http://", "https://")):
                url_na_parsovanie = "http://" + url_na_parsovanie
            
            parsed_url = urlparse(url_na_parsovanie)
            
            domena_s_portom = parsed_url.netloc
            cesta_s_portom = parsed_url.path
            
            # 1. Odstránenie www.
            if domena_s_portom.startswith("www."):
                domena_s_portom = domena_s_portom[4:]
            
            # 2. Pridanie query/fragmentov k ceste
            if parsed_url.query:
                cesta_s_portom += "?" + parsed_url.query
            if parsed_url.fragment:
                cesta_s_portom += "#" + parsed_url.fragment
                
            if not cesta_s_portom:
                cesta_s_portom = "/"
                
            # 3. ODSTRÁNENIE PORTU (Kľúčové pre Flowmon)
            # Vyčistí port z domény aj z cesty (rieši media:80)
            čista_domena = port_regex.sub("", domena_s_portom)
            čista_cesta = port_regex.sub("", cesta_s_portom)
            
            # 4. Spojenie do formátu: hostname,path,comment
            novy_riadok = f"{čista_domena},{čista_cesta},URLhaus"
            unikatne_riadky.add(novy_riadok)
            
        except Exception as e:
            continue
    root_projektu = Path(__file__).resolve().parent.parent
    priecinok_lists = root_projektu / "Lists"
    
    priecinok_lists.mkdir(parents=True, exist_ok=True)
    
    vystupny_subor = priecinok_lists / "urlhaus_urls.txt"

    with open(vystupny_subor, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(unikatne_riadky)))
        
    print(f"Súbor úspešne vygenerovaný v: {vystupny_subor}")
    print(f"Celkový počet riadkov: {len(unikatne_riadky)}")
else:
    print(f"Chyba pri sťahovaní dát: {response.status_code}")
    exit(1)
