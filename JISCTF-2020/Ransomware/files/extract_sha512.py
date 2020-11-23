
f = open('./flag.enc', 'r')
content = f.read()
hashes = list(filter(lambda h: h!='', content.split('70323090')))

for h in hashes:
    print(h[::-1])

