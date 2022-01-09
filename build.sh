VERSION=$(grep version logstash-input-azure_blob_storage.gemspec | cut -d"'" -f 2)
GEMPWD=$(pwd)
echo "Building ${VERSION}"
#pushd /usr/share/logstash
sudo -u logstash /usr/share/logstash/bin/logstash-plugin remove logstash-input-azure_blob_storage
#popd
sudo -u logstash gem build logstash-input-azure_blob_storage.gemspec 
sudo -u logstash gem install logstash-input-azure_blob_storage-${VERSION}.gem
#pushd /usr/share/logstash 
sudo -u logstash /usr/share/logstash/bin/logstash-plugin install ${GEMPWD}/logstash-input-azure_blob_storage-${VERSION}.gem
#popd
#/usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/nsg-pipe.conf --config.reload.automatic
