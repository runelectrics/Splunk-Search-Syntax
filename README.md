![Splunk Hunt Searches](splunk.jpeg)

# [Splunk Hunting](https://github.com/runelectrics/Splunk-Search-Syntax) 


**A collection of searches using Splunk for threat hunting**

Your [contributions](contributing.md) are always welcome !

## Searches

1. Lookup Search
```
| lookup open_nameservers ip 												
| stats count by ip
```

## References
[Hunting with Splunk: The Basics](https://www.splunk.com/blog/2017/07/06/hunting-with-splunk-the-basics.html)
