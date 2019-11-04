import pcapkit
import json
import multiprocessing
import os
# from multiprocessing.pool import ThreadPool as Pool

def pcaptojson(file) -> dict:
    return(pcapkit.extract(fin=file, nofile=True, format='json', auto=False, 
        engine='deafult', extension=False, layer='Transport', tcp=True, ip=True,strict=True, store=False))
    

def pcapparse(obj) -> dict:
    main = {}
    data = {}
    try:
        time = (obj.info.info2dict()['time_epoch'])
        main["time_epoc"] = time
    except KeyError:
        pass
    try:
        macdstdirt = (obj.info.info2dict()['ethernet']['dst'])
        macdst = []
        for delim in macdstdirt:
            if delim != '\'' and delim != '[' and delim != ']' and delim != ',' and delim != ' ':
                macdst.append(delim)
        finalmacdst = ''.join(macdst)
        data["macdst"] = finalmacdst
    except KeyError:
        pass
    try: 
        connecttype = (obj.info.info2dict()['ethernet']['type'])
        data["type"] = str(connecttype)
    except KeyError:
        pass
    try:
        macsrcdirt = (obj.info.info2dict()['ethernet']['src'])
        macsrc = []
        for delim in macsrcdirt:
            if delim != '\'' and delim != '[' and delim != ']' and delim != ',' and delim != ' ':
                macsrc.append(delim)
        finalmacsrc = ''.join(macsrc)
        data["macsrc"] = finalmacsrc
    except KeyError:
        pass
    try:
        tcpdstport = (obj.info.info2dict()['ethernet']['ipv4']['tcp']['dstport'])
        data["tcpdstport"] = tcpdstport
    except KeyError:
        pass
    try:
        tcpsrcport = (obj.info.info2dict()['ethernet']['ipv4']['tcp']['srcport'])
        data["tcpsrcport"] = tcpsrcport
    except KeyError:
        pass
    try:
        udpdstport = (obj.info.info2dict()['ethernet']['ipv4']['udp']['dstport'])
        data["udpdstport"] = udpdstport
    except KeyError:
        pass
    try:
        udpsrcport = (obj.info.info2dict()['ethernet']['ipv4']['udp']['srcport'])
        data["udpsrcport"] = udpsrcport
    except KeyError:
        pass
    try:
        ipv4proto = (obj.info.info2dict()['ethernet']['ipv4']['proto'])
        data["ipv4proto"] = str(ipv4proto)
    except KeyError:
        pass
    try:
        ipv4src = (obj.info.info2dict()['ethernet']['ipv4']['src'])
        data["ipv4src"] = str(ipv4src)
    except KeyError:
        pass
    try:
        ipv4dst = (obj.info.info2dict()['ethernet']['ipv4']['dst'])
        data["ipv4dst"] = str(ipv4dst)
    except KeyError:
        pass
    try:
        ipv6proto = (obj.info.info2dict()['ethernet']['ipv6']['proto'])
        data["ipv6proto"] = str(ipv6proto)
    except KeyError:
        pass
    try:
        ipv6src = (obj.info.info2dict()['ethernet']['ipv6']['src'])
        data["ipv6src"] = str(ipv6src)
    except KeyError:
        pass
    try:
        ipv6dst = (obj.info.info2dict()['ethernet']['ipv6']['dst'])
        data["ipv6dst"] = str(ipv6dst)
    except KeyError:
        pass
    try:
        ipv6tcpdstport = (obj.info.info2dict()['ethernet']['ipv6']['tcp']['dstport'])
        data["ipv6tcpdstport"] = ipv6tcpdstport
    except KeyError:
        pass
    try:
        ipv6tcpsrcport = (obj.info.info2dict()['ethernet']['ipv6']['tcp']['srcport'])
        data["ipv6tcpsrcport"] = ipv6tcpsrcport
    except KeyError:
        pass
    try:
        ipv6udpdstport = (obj.info.info2dict()['ethernet']['ipv6']['udp']['dstport'])
        data["ipv6udpdstport"] = ipv6udpdstport
    except KeyError:
        pass
    try:
        ipv6udpsrcport = (obj.info.info2dict()['ethernet']['ipv6']['udp']['srcport'])
        data["ipv6udpsrcport"] = ipv6udpsrcport
    except KeyError:
        pass
    main["data"] = data
    return main


def pcaplist(jsondict) -> list:
    pool = multiprocessing.Pool(processes=os.cpu_count())
    # pool = Pool(16)
    for obj in jsondict:
        # pcapparse(obj)
        pool.apply_async(pcapparse, (obj))
    pool.close()
    pool.join()

def main():
    jsondict = pcaptojson("../SampleDumps/smallFlows.pcap")
    pcaplist(jsondict)
    

if __name__ == "__main__":
    main()


