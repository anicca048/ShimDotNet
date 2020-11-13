# ShimDotNet
C# Wrapper for the portable C++ capture engine from my CP3cap project.
Mainly written for use by Kebab, but could be used for many other C# projects.

ShimDotNet and the Shim capture engine are not used to view packet contents, but
rather are used to gather metadata about packets, such as host information and
payload size.

ShimDotNet is designed for use with Npcap, and uses the Npcap sdk.
You can find the Npcap SDK on the Nmap team's site here: https://nmap.org/npcap/
