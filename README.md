![Splunk Hunt Searches](splunk.jpeg)

# [Splunk Hunting](https://github.com/runelectrics/Splunk-Search-Syntax) 


**A collection of searches using Splunk for threat hunting**

Your [contributions](contributing.md) are always welcome !

## Searches

Search | Description
---- | ----
```
| lookup open_nameservers ip 												
| stats count by ip
```
																								| Lookup nameservers from file

## References
[Hunting with Splunk: The Basics](https://www.splunk.com/blog/2017/07/06/hunting-with-splunk-the-basics.html)
