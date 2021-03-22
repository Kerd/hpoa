# hpoa
Python API for HP Insight Onboard Administrator SOAP Interface.<br>
Use this library to read and update BladeSystem c7000 and c3000 configuration.

Tested on c7000 only.

Short usage example accessing some methods without authorization:

```python
import hpoa

# To output XML data using lxml.etree
po = lambda xml: print(hpoa.etree.tostring(xml, pretty_print=True).decode('utf-8'))
    
# fix for [SSL: DH_KEY_TOO_SMALL] dh key too small on modern systems
if hpoa.sys.version_info.major > 2:
    hpoa.requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
else:
    hpoa.requests.packages.urllib3.util.ssl_._DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'

# Debugging (set to DEBUG-5 to output raw (unparsed) HTTP response)
# hpoa.logging.getLogger().setLevel(hpoa.logging.DEBUG)

api = hpoa.HPOA(oa1_address)

# Or provide list of addresses, username and password
# api = hpoa.HPOA(['c7000-oa1','c7000-oa2', 192.168.10.10'], username, password)

# Even anonymous access needs login() to validate interface.
api.login()

po(api.getRackTopology2())
po(api.getOaInfoArray([1,2]))
# Or like this, for one item
po(api.getOaInfoArray(1)) 
po(api.getOaInfo(2))
# Or even this
po(api.getOaStatusArray(range(1,3)))

```

Check bottom of [hpoa.py](hpoa.py) for example.

Interface methods and their parameters are described in `hpoa.methods`. Or you may use `help(hpoa)`.
Not all data types were implemented, so if you not only want to retrieve configuration and inventory information
but also to modify settings, you probably will have to extend this library for some complex data types.
