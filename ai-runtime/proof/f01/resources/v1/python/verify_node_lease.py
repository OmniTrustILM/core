import datetime,json,sys
with open(sys.argv[1]) as stream:
    lease=json.load(stream)
def instant(text):
    value=datetime.datetime.fromisoformat(text.replace("Z","+00:00"))
    assert value.tzinfo is not None
    return value
assert lease["holderIdentity"]==sys.argv[3] and instant(lease["renewTime"])>instant(sys.argv[2]), "node lease is not newer than restart return"
