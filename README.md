# CANaerospace Wireshark plugin
CANaerospace Wireshark Lua plugin

![Screenshot](images/screenshot.png?raw=true "Screenshot")

Run with: ```wireshark -X lua_script:canas-protocol.lua```

Tested with *Wireshark 4.4.7*. (Previously tested with Wireshark 3.0.5 on Ubuntu 19.10)

## Troubleshooting

### "The capture file appears to be damaged or corrupt" (Syntax Error)
If you see this error when loading a `candump` log file, it is likely because your CAN IDs are not correctly padded. Wireshark's SocketCAN parser strictly expects CAN IDs to be either **3 hex digits** (standard) or **8 hex digits** (extended).

Example: `1869F` (5 digits) will fail. It must be padded to `0001869F`.

You can fix your log file using this command:
```bash
sed -E 's/ ([0-9A-Fa-f]{1,7})#/ \1#/; :a; s/ ([0-9A-Fa-f]{1,2})#/ 0\1#/; ta; s/ ([0-9A-Fa-f]{4,7})#/ 0\1#/; ta' your_log.log
```
Or specifically for 5-digit IDs:
```bash
sed -E 's/ ([0-9A-Fa-f]{5})#/ 000\1#/' your_log.log > fixed_log.log
```