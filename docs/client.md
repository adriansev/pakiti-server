# Client usage

There are several ways how to send information from the monitored machine to the Pakiti server. The Pakiti suite
contains a [client](https://github.com/CESNET/pakiti-client/) that can be deployed on the infrastructure. Environments
utilizing the [GLPI toolset](https://glpi-project.org/) can use the glpi tools to send reports to Pakiti too. Details
on the usage are below.

## Pakiti client
Run pakiti-client -h for help

    perl /var/www/pakiti3/bin/pakiti-client -h

##### send report via https
    perl /var/www/pakiti3/bin/pakiti-client --url="https://yourdomain.com/feed/"

## GLPI
GLPI is either in your linux distribution or install it according to https://github.com/glpi-project/glpi-agent/releases

#### Create inventory in json format and save to file
    glpi-inventory --json -t Tag > /tmp/glpi
#### Send created inventory to pakiti
    glpi-injector -f /tmp/glpi -u https://yourdomain.com/feed/

#### Or in one step, without a temporary file
    glpi-inventory --json -t Tag | glpi-injector --stdin -u https://yourdomain.com/feed/

The tag (`-t`) becomes the host group of the host in Pakiti.

Pakiti uses the `from` field of each software entry: the package manager with the most
entries (`rpm` or `deb`) sets the package type of the report, which selects the version
comparison algorithm, and entries from any other origin (snap, flatpak, nix, ...) are
ignored, as no vendor advisory describes them.
