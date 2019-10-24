# Oracl
A network monitoring and analysis tool made for the Home user

## Goal
An easy to use network monitoring system that can be used to compare packets captured on a host against those seen on the network.

### Salient Features

- Parse pcaps into an easily searchable format
- Provide an API to 
 
  - Search data by time, protocol, src(MAC and IP), destination (MAC and IP), type
  - Upload pcaps to parse
  - Compare uploaded pcaps with data seen on the network
  
## Development
__Note:__ This project is under heavy development but we will always try and keep the test branch in some working state.

### Current State

`parse.py`: contains one function that takes a pcap file and returns a list of dicts with each element representing an 
ethernet frame in the pcap. To run a test against the `smallFlows.pcap` file, do the following in a Python terminal

```
import parse
frames = pcaptojson("test.pcap")
print(frames)
``` 

This should print a list of dicts where each element looks something like

`{"time_epoc": 1570231931.074622, "data": {"macdst": "01-00-5e-00-00-fb", "macsrc": "cc-2d-b7-c4-c5-8d", 
"udpdstport": 5353, "udpsrcport": 5353, "ipv4proto": "TransType.UDP", "ipv4src": "10.25.31.141", "ipv4dst": "224.0.0.251"}}`

__Note__: The current version takes around 30 minutes to parse the 15,000 frames in `smallFlow.pcap`. It takes about 10 seconds to do the 150 frames in `test.pcap`
  
  
