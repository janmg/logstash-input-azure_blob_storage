## 0.11.5
  - Added optional filename into the message
  - plumbing for emulator, start_over not learning from registry

## 0.11.4
  - fixed listing 3 times, rather than retrying to list max 3 times
  - added option to migrate/save to using local registry
  - rewrote interval timing
  - reduced saving of registry to maximum once per interval, protect duplicate simultanious writes
  - added debug_timer for better tracing how long operations take
  - removing pipeline name from logfiles, logstash 7.6 and up have this in the log4j2 by default now
  - moved initialization from register to run. should make logs more readable

## 0.11.3
  - don't crash on failed codec, e.g. gzip_lines could sometimes have a corrupted file?
  - fix nextmarker loop so that more than 5000 files (or 15000 if faraday doesn't crash) 

## 0.11.2
  - implemented path_filters to to use path filtering like this **/*.log
  - implemented debug_until to debug only at the start of a pipeline until it processed enough messages

## 0.11.1
  - copied changes from irnc fork (danke!)
  - fixed trying to load the registry, three time is the charm
  - logs are less chatty, changed info to debug

## 0.11.0
  - implemented start_fresh to skip all previous logs and start monitoring new entries
  - fixed the timer, now properly sleep the interval and check again
  - work around for a Faraday Middleware v.s. Azure Storage Account bug in follow_redirect

## 0.10.6
  - fixed the rootcause of the checking the codec. Now compare the classname.

## 0.10.5
  - previous fix broke codec = "line"

## 0.10.4
  - fixed JSON parsing error for partial files because somehow (logstash 7?) @codec.is_a? doesn't work anymore

## 0.10.3
  - fixed issue-1 where iplookup confguration was removed, but still used 
  - iplookup is now done by a separate plugin named logstash-filter-weblookup

## 0.10.2
  - moved iplookup to own plugin logstash-filter-lookup

## 0.10.1
  - implemented iplookup
  - fixed sas tokens (maybe)
  - introduced dns_suffix

## 0.10.0
  - plugin created with the logstash plugin generator
  - reimplemented logstash-input-azureblob with incompatible config and data/registry
