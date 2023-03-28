import requests

ip = ''

params = ['query', 'lat', 'lon', 'country', 'countryCode', 'city', 'timezone']
resp = requests.get('http://ip-api.com/json/' + ip, params={'fields': ','.join(params)})

info = resp.json()

print(info)