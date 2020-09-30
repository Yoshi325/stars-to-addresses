# -*- coding: utf-8 -*-
"""
Go to Google Bookmarks: https://www.google.com/bookmarks/

On the bottom left, click "Export bookmarks": https://www.google.com/bookmarks/bookmarks.html?hl=en

After downloading the html file, run this script on it to get the addresses

This script is based on https://gist.github.com/endolith/3896948
"""

import re
import sys
import json
import time

from pprint import pprint
from typing import List
from traceback import format_exception
from traceback import TracebackException
from urllib.request import urlopen

try:
    from lxml.html import document_fromstring
except ImportError:
    print("You need to install lxml.html")
    sys.exit()

try:
    from geopy.geocoders import Nominatim
except ImportError:
    print("You need to install geopy")
    sys.exit()

try:
    import simplekml
except ImportError:
    print("You need to install simplekml")
    sys.exit()


def get_formatted_exception() -> str:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    tracebacks: List[TracebackException] = format_exception(exc_type, exc_value, exc_traceback)
    repr_tracebacks = repr(tracebacks)
    str_tracebacks = str(repr_tracebacks)
    return str_tracebacks


filename = r'GoogleBookmarks.html'

def main():
    with open(filename) as bookmarks_file:
        data = bookmarks_file.read()

    # geopy.exc.ConfigurationError: Using Nominatim with default or sample
    # `user_agent` "geopy/2.0.0" is strongly discouraged, as it violates
    # Nominatim's ToS https://operations.osmfoundation.org/policies/nominatim/
    # and may possibly cause 403 and 429 HTTP errors. Please specify a custom
    # `user_agent` with `Nominatim(user_agent="my-application")` or by
    # overriding the default `user_agent`:
    # `geopy.geocoders.options.default_user_agent = "my-application"`.
    geolocator = Nominatim(user_agent = __name__)

    kml = simplekml.Kml()

    lst = list()

    # Hacky and doesn't work for all of the stars:
    lat_re = re.compile('markers:[^\]]*latlng[^}]*lat:([^,]*)')
    lon_re = re.compile('markers:[^\]]*latlng[^}]*lng:([^}]*)')
    coords_in_url = re.compile('\?q=(-?\d{,3}\.\d*),\s*(-?\d{,3}\.\d*)')

    doc = document_fromstring(data)
    for element, attribute, url, pos in doc.body.iterlinks():
        if 'maps.google' in url:
            description = element.text or ''
            print(description)

            if coords_in_url.search(url):
                # Coordinates are in URL itself
                latitude = coords_in_url.search(url).groups()[0]
                longitude = coords_in_url.search(url).groups()[1]
            else:
                # Load map and find coordinates in source of page
                url_to_open: str = url.replace(' ', '+')
                try:
                    sock = urlopen(url_to_open)
                except Exception:
                    print('Connection problem:')
                    pprint(get_formatted_exception())

                    print('Waiting 3 minutes and trying again')
                    time.sleep(180)
                    sock = urlopen(url_to_open)

                content = sock.read()
                content_string = content.decode(encoding='utf-8')
                sock.close()
                time.sleep(5) # Don't annoy server
                try:
                    latitude = lat_re.findall(content_string)[0]
                    longitude = lon_re.findall(content_string)[0]
                except IndexError:
                    latitude = ""
                    longitude = ""
                    try:
                        lines = content_string.split('\n')  # --> ['Line 1', 'Line 2', 'Line 3']
                        for line in lines:
                            if re.search('cacheResponse\(', line):
                                splitline = line.split('(')[1].split(')')[0] + '"]'
                                null = None
                                values = eval(splitline)
                                print(values[8][0][1])
                                longitude = str(values[0][0][1])
                                latitude = str(values[0][0][2])
                                continue
                        if latitude == "":
                            # let's try something different....
                            for line in lines:
                                if re.search('APP_INITIALIZATION_STATE', line):
                                    splitline = line.split('[')[-1].split(']')[0].split(',')
                                    longitude = str(splitline[1])
                                    latitude = str(splitline[2])
                                    continue
                    except IndexError:
                        print('[Coordinates not found]')
                        continue
                    print()

            print(latitude, longitude)
            try:
                if latitude != "":
                    location = geolocator.reverse(latitude+", "+longitude)
                    print(location.address)
                else:
                    print('[Invalid coordinates]')
            except ValueError:
                print('[Invalid coordinates]')
            print()
            if latitude != "":
                kml.newpoint(name=description, coords=[(float(longitude), float(latitude))])
            else:
                kml.newpoint(name=description)
            location_address = 'error' if not location else location.address
            lst.append({'latitude': latitude,
                       'longitude': longitude,
                       'name': description,
                       'url': url,
                       'address': location_address})

            # this is here because there's a tendancy for this script to fail part way through...
            # so at least you can get a partial result
            kml.save("GoogleBookmarks.kml")
            with open('GoogleBookmarks.json', mode='w') as listdump:
                listdump.write(json.dumps(lst))
        sys.stdout.flush()

    kml.save("GoogleBookmarks.kml")
    with open('GoogleBookmarks.json', mode='w') as listdump:
        listdump.write(json.dumps(lst))

if __name__ == '__main__':
    main()
