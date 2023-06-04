## 0.12.8
  - support append blob (use json_lines)
  - change the default head and tail to an empty string, unless the logtype is nsgflowlog
  - jsonclean parameter to clean the json stream from faulty charaters to prevent parse errors
  - catch ContainerNotFound, print error message in log and sleep interval time.

## 0.12.7
  - rewrote partial_read, now the occasional json parse errors should be fixed by reading only commited blocks.
      (This may also have been related to reading a second partial_read, where the offset wasn't updated correctly?)
  - used the new header and tail block name, should now learn header and footer automatically again?
  - added addall to the configurations to add system, mac, category, time, operation to the output
  - added optional environment configuration option
  - removed the date, which was always set to --- 
  - made a start on event rewriting to make it ECS compatibility

## 0.12.6
  - Fixed the 0.12.5 exception handling, it actually caused a warning to become a fatal pipeline crashing error
  - The chuck that failed to process should be printed in debug mode, for testing use debug_until => 10000 
  - Now check if registry entry exist before loading the offsets, to avoid caught: undefined method `[]' for nil:NilClass

## 0.12.5
  - Added exception message on json parse errors

## 0.12.4
  - Connection Cache reset removed, since agents are cached per host
  - Explicit handling of json_lines and respecting line boundaries (thanks nttoshev)
  - Removed reprocessing on any exception

## 0.12.3
  - Fixed repetative processing
  - Replaced newreg with registry cleanup, using newreg to replace old registry worked in 0.11, but not in .12
  - Implemented Mutex for the save_registry thread. Also marshal @registry before thread start for better thread safety

## 0.12.2
  - Fixed the exception handling, not trying to print how many JSON fields there are while catching the exception

## 0.12.1
  - Catch NSGFLOW logs when the JSON parsing somehow failed

## 0.12.0
  - version 2 of azure-storage
  - saving current files registry, not keeping historical files

## 0.11.7
  - implemented skip_learning
  - start ignoring failed files and not retry

## 0.11.6
  - fix in json head and tail learning the max_results
  - broke out connection setup in order to call it again if connection exceptions come
  - deal better with skipping of empty files.

## 0.11.5
  - added optional addfilename to add filename in message
  - NSGFLOWLOG version 2 uses 0 as value instead of NULL in src and dst values
  - added connection exception handling when full_read files
  - rewritten json header footer learning to ignore learning from registry  
  - plumbing for emulator

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
