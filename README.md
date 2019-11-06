# Wireshark 802.15.4 Psot-Dissector
This is a wireshark dissector for a data-packet of the IEEE 802.15.4 protocol. It dissects the following frames of the packet:
1. Data Frame
2. Routing Frame
3. Active-Messaging Layer

## Active-Messaging Layer
The <b>Active Messaging</b> layer is used for packets that follow the Collection-Tree Protocol. It isused for transporting a higher-level frame. Since this frame was an important to our work, it has been dissected in this dissector.

# How to Install
Follow these steps to load this post-dissector into Wireshark:
1. Download the `dissector.lua` file to your local machine.
2. Open Wireshark

# Credits
This dissector was based off the <i>p2p-wireshark-dissector</i> from [hardware-pinoccio](https://github.com/Pinoccio/hardware-pinoccio/blob/master/firmware/bootloader/p2p-wireshark-dissector.lua)
