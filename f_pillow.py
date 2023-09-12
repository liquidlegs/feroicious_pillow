import argparse, re
from requests_html import HTMLSession

REG_URLS =          r"\"[a-zA-Z]*:\/\/\S*\"" 
REG_PARAGRAPH =     r">[\w ]+[\w !@#$%^&*()+-=\/]+<|<p>[\w ,\"\'-.]+|\/a>[\w !@#$%^&*()-=+.,\'\"]+<\/p>"
REG_HASHES =        r"[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32}"
REG_M_HTTP =        r"[hxps]{4,5}[:\/\[\]]{3,5}[\w \[\]\.\/:]+|[htps]{4,5}[:\/\[\]]{3,5}[\w\/\[\]\. ]+\[\.\][\w:\/]+"
# REG_M_HTTP =        r"[hxps]{4,5}[:\/\[\]]{3,5}[\w \[\]\.\/:]+"
REG_M_IP =          r"\d{1,3}[\[\]\.]+\d{1,3}[\[\]\.]+\d{1,3}[\[\]\.]+\d{1,3}+[\w:\/.?=]+"
REG_M_DOMAIN =      r"[a-zA-Z]+[a-zA-Z\[\]\.]+\[\.\][a-zA-Z\/?=]+"


def remove_tags(data: str) -> str:
  '''Function removes angle brackets from text and p/a html tags from strings'''
  fmt_string = data
  if len(fmt_string) > 0:
    
    # Removes >/< character at the start of each line
    if fmt_string[0] == ">":
      fmt_string = fmt_string[1:]
    
    if fmt_string[len(fmt_string)-1] == "<":
      fmt_string = fmt_string[:-1]

    # Removes paragraph/anchor tags from string content.
    fmt_string = fmt_string.replace("<p>", "").replace("</p>", "").replace("<a>", "").replace("/a>", "")

  return fmt_string


def match_pattern(pattern: str, data: str) -> str:
  '''Matches all occourences of a regex pattern and returns the result.'''
  try:
    out = re.findall(pattern, data)
    return out
  except AttributeError:
    return None    


def extract_data(args):
  '''Scrapes the specified content from the html response.'''
  
  url = args.url

  # Session sends a GET request to the chosen url with javascript and cookies enabled.
  session = HTMLSession()
  resp = session.get(url)

  if args.raw == True:
    print(resp.text)
    exit(0)

  # Data holds the resulting information that will either be written to a file or displayed to the screen.
  data = []

  if args.link == True:
    # Line creates a list of extracted urls and removes all duplicates.
    out = list(set(match_pattern(REG_URLS, resp.text)))

    # Code block removed the quotation marks at the start and end of each string.
    for i in range(len(out)):
      temp = out[i]
      temp = temp[1:-1]
      out[i] = temp

    data.extend(out)

  # Scrapes text from the document.
  if args.text == True:
    out = list(set(match_pattern(REG_PARAGRAPH, resp.text)))
    
    for i in range(len(out)):
      out[i] = remove_tags(out[i])
    
    data.extend(out)

  # Scapres potential IOCs from the document.
  if args.ioc == True:
    text = resp.text

    hashes = list(set(match_pattern(REG_HASHES, text)))
    m_urls = list(set(match_pattern(REG_M_HTTP, text)))
    m_ips = list(set(match_pattern(REG_M_IP, text)))
    m_domain = list(set(match_pattern(REG_M_DOMAIN, text)))

    data.extend(hashes)
    data.extend(m_urls)
    data.extend(m_ips)
    data.extend(m_domain)
    
  
  # Writes all content in the data list to a file.
  if args.output != None:
    if len(data) > 0:
      write_file(args.output, data)
    else:
      print("No valid data to write")
      return
  else:
    for i in data:
      print(i)


def write_file(filename: str, data: list):
  '''Writes parsed content to a file.'''
  
  bytes = 0
  lines = len(data)

  for i in data:
    bytes += len(i)

  format_lines = []
  for i in data:
    format_lines.append(i + "\n")
  
  with open(filename, "w") as f:
    f.writelines(format_lines)

  print(f"Successfully wrote {lines} lines ({bytes}) bytes to {filename}")  


def main():

  parser = argparse.ArgumentParser(description="none")
  parser.add_argument("-u", "--url", action="store", help="Send a GET request to the specified url", required=True)
  parser.add_argument("-r", "--raw", action="store_true", help="Display the raw response")
  parser.add_argument("-l", "--link", action="store_true", help="Extract links from the page")
  parser.add_argument("-o", "--output", action="store", help="Writes the results to a file")
  parser.add_argument("-t", "--text", action="store_true", help="Extract text from the page")
  parser.add_argument("-i", "--ioc", action="store_true", help="Extract iocs from the page")
  args = parser.parse_args()

  url = args.url
  if url == None:
    print("A valid url is required")
    return
  
  extract_data(args)


if __name__ == "__main__":
  main()