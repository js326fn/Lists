import requests

URL_ZDROJA = "https://raw.githubusercontent.com/stamparm/maltrail/ad92e6c51871616da58be6d2d5314203b506b8a5/trails/static/malware/fakeapp.txt"
VYSTUPNY_SUBOR = "Lists/maltrail_urls.txt"

def stiahni_a_rozparsuj():
    try:
        response = requests.get(URL_ZDROJA)
        response.raise_for_status() 
        
        riadky = response.text.splitlines()
    except Exception as e:
        print(f"Chyba pri sťahovaní súboru: {e}")
        return

    osetrene_riadky = []

    for riadok in riadky:
        riadok = riadok.strip()
        
        if not riadok or riadok.startswith('#'):
            continue
            
        if riadok.startswith("https://"):
            riadok = riadok[len("https://"):]
        elif riadok.startswith("http://"):
            riadok = riadok[len("http://"):]
            
        novy_riadok = f"{riadok},/,maltrail"
        osetrene_riadky.append(novy_riadok)


    with open(VYSTUPNY_SUBOR, "w", encoding="utf-8") as f:
        f.write("\n".join(osetrene_riadky) + "\n")
        
    print(f"Úspešne aktualizované! Uložených {len(osetrene_riadky)} riadkov.")

if __name__ == "__main__":
    stiahni_a_rozparsuj()
