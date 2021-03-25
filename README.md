# Huawei-N5368X-crawler

NEW 23.3.2021: V2 to support latest firmwares used by Finnish operators DNA and Elisa. This script uses a separate config file (huawei.ini), make sure your settings are done right. If you used the previous version (V1), and you want to continue the old measurements, use need to rename measurements according the new api names. This is done propably easiest in influx by querying:
* select * into "traffic-statistics" from uptime group by *
* select * into "traffic-statistics" from queryModemMonitorWithName group by *
* select * into "status" from getsiglevel group by *
* select * into "antenna-configuration" from getAntennaConfiguration group by *
* select * into "signal" from getSignal group by *

This script is able to login to Huawei Outdoor 5G CPE N5368X and fetch some example data. Script also includes the possibility to write data to Influx database e.g. for monitoring purposes.

NOTE! This script is intended to be used as an example. Script comes without any warranty & support.

Script has dependencies to quite a few Python packages (use pip to install) such as:

* crypto
* flatten-json
* influxdb
* pkcs1
* pyasn1
* pycrypto
* python-dateutil
* requests
* rsa
* urllib3
* uuid
