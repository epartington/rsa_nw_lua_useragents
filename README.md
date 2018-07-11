# rsa_nw_lua_useragents
Lua Parser for user agents searches (exact and substring)

## How this works
User agents are extracted from packet traffic and logs and dropped into the client metakey.  This parser reads the metakey and checks a number of tables in the parser to see if there is an exact match.  If there is no exact match then it progresses to check for substrings.
Example of what might be written to the keys below are:

client='123 wordpress hash grabber abc'
writes:
analysis.session='exploit_substring_^.*wordpress hash grabber.*'

client='theexploiter'
writes
analysis.session='exploit_substring_^.*exploit.*'
  
## Input/Output
**Input** client
**output** analysis.session, ioc

## Implementation

## Customizations required
index-concentrator-custom.xml
<!-- useragent punctuation test -->
<key description="Punctuation" format="Text" level="IndexValues" name="punctuation" valueMax="1000"/>
