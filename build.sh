pushd /usr/share/logstash
/usr/share/logstash/bin/logstash-plugin remove logstash-input-azure_blob_storage
popd
sudo -u logstash gem build logstash-input-azure_blob_storage.gemspec 
sudo -u logstash gem install logstash-input-azure_blob_storage-0.11.0.gem
pushd /usr/share/logstash 
/usr/share/logstash/bin/logstash-plugin install /usr/src/logstash-input-azure_blob_storage/logstash-input-azure_blob_storage-0.11.0.gem
popd
#/usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/nsg-pipe.conf --config.reload.automatic
