# python-profinet
An attempt to create a free ProfiNET daemon for Linux

This thing is completely reverse engineered without any ProfiNET documentation whatsoever. So it might not work as expected.

This work is also completely in progress and is being done in my free time.

## How do I use this thing
```
server = Profinet("eth0")
server.start()
```

This will start a raw socket receiving and sending 0x8892 frames and a UDP service on 34964 which will be used for the DCE/RPC part.

## What does work at the moment
The DCP part is more or less complete. The service will properly respond to ident requests and you will be able to change the station name via DCP.

## What does not work
Everything else :)

I am currently working on the DCE/RPC part which is a pain in the butt and I have no idea how to implement it nicely.
