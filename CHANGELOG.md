## 0.10.4
  - Fixed JSON parsing error for partial files because somehow (logstash 7?) @codec.is_a? doesn't work anymore

## 0.10.3
  - Fixed issue-1 where iplookup confguration was removed, but still used 
  - iplookup is now done by a separate plugin named logstash-filter-weblookup

## 0.10.2
  - moved iplookup to own plugin logstash-filter-lookup

## 0.10.1
  - Implemented iplookup
  - Fixed sas tokens (maybe)
  - Introduced dns_suffix

## 0.10.0
  - Plugin created with the logstash plugin generator
  - Reimplemented logstash-input-azureblob with incompatible config and data/registry
