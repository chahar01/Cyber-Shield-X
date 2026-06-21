import requests
from bs4 import BeautifulSoup
import json
import os

def analyze_website(url):
    headers = {"User-Agent": "Mozilla/5.0"}
    r = requests.get(url, headers=headers)

    soup = BeautifulSoup(r.text, "html.parser")

    
    title = soup.title.string.strip() if soup.title else "No Title"

    
    links = [a["href"] for a in soup.find_all("a", href=True)]

    
    headings = []
    for tag in ["h1", "h2", "h3"]:
        for h in soup.find_all(tag):
            headings.append(h.get_text(strip=True))

    
    images = []
    for img in soup.find_all("img"):
        src = img.get("src")
        if src:
            images.append(src)


    
    forms = []
    for form in soup.find_all("form"):
      action = form.get("action") or "N/A"
      method = form.get("method", "GET").upper()

      inputs = []
      for inp in form.find_all("input"):
        name = inp.get("name") or "N/A"
        typ = inp.get("type") or "text"

        inputs.append({
            "name": name,
            "type": typ
        })

    forms.append({
        "action": action,
        "method": method,
        "inputs": inputs
    })

    
    data = {
        "url": url,
        "title": title,
        "links": links,
        "headings": headings,
        "images": images,
        "forms": forms
    }

    
    os.makedirs("results", exist_ok=True)

    with open("results/threat.json", "w") as f:
        json.dump(data, f, indent=4)

    return data