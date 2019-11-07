# Wireshark 802.15.4 Psot-Dissector
This is a wireshark dissector for a data-packet of the IEEE 802.15.4 protocol. It dissects the following frames of the packet:
1. Data Frame
2. Routing Frame
3. Active-Messaging Layer

## Active-Messaging Layer
The **Active Messaging** layer is used for packets that follow the Collection-Tree Protocol. It isused for transporting a higher-level frame. Since this frame was an important to our work, it has been dissected in this dissector.

# How to Install
Follow these steps to load this post-dissector into Wireshark:
1. Download the `dissector.lua` file to your local machine.
2. Open Wireshark. Select *Help -> About Wireshark* from the toolbar.
3. In the Help pop-up menu, select *Folders*
4. Look for *Personal Lua Plugins* and open the directory associated with it.
5. Move/Copy this post-dissector file to that same repository.
6. Close the *Help* Window on Wireshark, and select *Analyze -> Reload Lua Plugins* option.
7. Open a data-packet of the given format on Wireshark, you should see the *Collection Tree Protocol* tree in the frame details panel of Wireshark.


# Credits
This dissector was based off the <i>p2p-wireshark-dissector</i> from [hardware-pinoccio](https://github.com/Pinoccio/hardware-pinoccio/blob/master/firmware/bootloader/p2p-wireshark-dissector.lua)
