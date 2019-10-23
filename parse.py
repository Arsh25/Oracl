import pcapkit
import json


def pcaptojson(file):
    jsonshit = pcapkit.extract(fin=file, nofile=True, format='json', auto=False, engine='deafult', extension=False, layer='Transport', tcp=True, ip=True, strict=True, store=False)
    print(jsonshit)
    print("Done parse!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    for e in jsonshit:
        thing = ''
        print(e.name)
        try:
            time = (e.info.info2dict()['time_epoch'])
            thing = thing +('{"time_epoch" : '+ '"'+str(time)+ '"}, ')
        except KeyError:
            pass
        try:
            macdstdirt = (e.info.info2dict()['ethernet']['dst'])
            macdst = []
            for shit in macdstdirt:
                if shit != '\'' and shit != '[' and shit != ']' and shit != ',' and shit != ' ':
                    macdst.append(shit)
            thing = thing + ('{"macdst" : '+ '"' + ''.join(macdst)+ '"}, ')
            
        except KeyError:
            pass 
        try:
            macsrcdirt = (e.info.info2dict()['ethernet']['src'])
            macsrc = []
            for shit in macsrcdirt:
                if shit != '\'' and shit != '[' and shit != ']' and shit != ',' and shit != ' ':
                    macsrc.append(shit)
            thing = thing +('{"macsrc" : ' + '"'+ ''.join(macsrc)+ '"}, ')
        except KeyError:
            pass
        try:
            tcpdstport = (e.info.info2dict()['ethernet']['ipv4']['tcp']['dstport'])
            thing = thing +('{"tcpdstport" : ' + '"'+ str(tcpdstport)+ '"}, ')
        except KeyError:
            pass
        try:
            tcpsrcport = (e.info.info2dict()['ethernet']['ipv4']['tcp']['srcport'])
            thing = thing +('{"tcpsrcport" : ' + '"'+ str(tcpsrcport)+ '"}, ')
        except KeyError:
            pass
        try:
            udpdstport = (e.info.info2dict()['ethernet']['ipv4']['udp']['dstport'])
            thing = thing +('{"udpdstport" : ' + '"'+ str(udpdstport)+ '"}, ')
        except KeyError:
            pass
        try:
            udpsrcport = (e.info.info2dict()['ethernet']['ipv4']['udp']['srcport'])
            thing = thing +('{"udpsrcport" : ' + '"'+ str(udpsrcport)+ '"}, ')
        except KeyError:
            pass
        try:
            ipv4proto = (e.info.info2dict()['ethernet']['ipv4']['proto'])
            thing = thing +('{"ipv4proto" : ' + '"' + str(ipv4proto)+ '"}, ')
        except KeyError:
            pass
        try:
            ipv4src = (e.info.info2dict()['ethernet']['ipv4']['src'])
            thing = thing +('{"ipv4src" : '+ '"' + str(ipv4src)+ '"}, ')
        except KeyError:
            pass
        try:
            ipv4dst = (e.info.info2dict()['ethernet']['ipv4']['dst'])
            thing = thing +('{"ipv4dst" : '+ '"' + str(ipv4dst)+ '"}, ')
        except KeyError:
            pass
        try:
            ipv6proto = (e.info.info2dict()['ethernet']['ipv6']['proto'])
            thing = thing +('{"ipv6proto" : ' + '"' + str(ipv6proto)+ '"}, ')
        except KeyError:
            pass
        try:
            ipv6src = (e.info.info2dict()['ethernet']['ipv6']['src'])
            thing = thing +('{"ipv6src" : ' + '"' + str(ipv6src)+ '"}, ')
        except KeyError:
            pass
        try:
            ipv6dst = (e.info.info2dict()['ethernet']['ipv6']['dst'])
            thing = thing +('{"ipv6dstmac" : ' + '"' + str(ipv6dst) + '"}, ' )
        except KeyError:
            pass
        try:
            ipv6tcpdstport = (e.info.info2dict()['ethernet']['ipv6']['tcp']['dstport'])
            thing = thing +('{"ipv6tcpdstport" : ' + '"' + str(ipv6tcpdstport)+ '"}, ')
        except KeyError:
            pass
        try:
            ipv6tcpsrcport = (e.info.info2dict()['ethernet']['ipv6']['tcp']['srcport'])
            thing = thing +('{"ipv6tcpsrcport" : ' + '"'+ str(ipv6tcpsrcport)+ '"}, ')
        except KeyError:
            pass
        try:
            ipv6udpdstport = (e.info.info2dict()['ethernet']['ipv6']['udp']['dstport'])
            thing = thing +('{"ipv6udpdstport" : ' + '"'+ str(ipv6udpdstport)+ '"}, ')
        except KeyError:
            pass
        try:
            ipv6udpsrcport = (e.info.info2dict()['ethernet']['ipv6']['udp']['srcport'])
            thing = thing +('{"ipv6udpsrcport" : ' + '"' + str(ipv6udpsrcport)+ '"}, ')
        except KeyError:
            pass
        newthing = thing[:-2:]
        newthing = '"' + newthing + '"'
        print(newthing)
        
        print('\n')


pcaptojson('pcaptest')