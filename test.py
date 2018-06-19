from Crypto import Random
from Crypto.Cipher import AES
import base64
import re

p = re.compile("\\((.*)\\)\\[(.*)\\](.*)", re.IGNORECASE)

key = "IOeni0So+Ox1Pn8weo92XdLURFyFRDxiNWO+M0R2LOM="
data = "OEZZ/ehupUxEIRWzS/sFJjWLW6jgjayazRYizt+To9OgUq83rbAPs7KpRQJuFxa/aZy/arGQfCe6oIrlewCi8NMI+URUoTEpCpiiH2S2Hytvun/0GLZi6vYZF2V+u+nV"


key = base64.b64decode(key)
data = base64.b64decode(data)

x = AES.new(key, AES.MODE_CBC, data[:16])

decoded = x.decrypt(data[16:])

z = p.match(decoded).groups()
type, path, value = z

path = "/".join([ base64.b64decode(p) for p in path.split("/") ])

print type, path, value