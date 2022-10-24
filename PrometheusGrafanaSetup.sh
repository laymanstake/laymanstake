#!/bin/bash

# Author : Nitish Kumar
# Download and Install Prometheus, Grafana and Node Exporter
# version 1.0 | 24/10/2022 Initial version

PROMETHEUS_VERSION=$(curl -s https://raw.githubusercontent.com/prometheus/prometheus/master/VERSION)
NODE_VERSION=$(curl -s https://raw.githubusercontent.com/prometheus/node_exporter/master/VERSION)

# Color variables for coloured text
red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`

# Ready up executables
Get-Executables (){
    args=("$@") 

    echo "${green}Creating $HOME/executables to keep downloads ...${reset}"
    mkdir -p $HOME/executables

    # Annoucing what would be downloaded
    echo "${green}Finding latest versions of ${#args[@]} packages: $(echo $@ | tr " " ",") ${reset}"

    # Capturing latest versions aailable
    if [[ "$*" == *"prometheus"* ]]
    then        
        echo "${green}The latest versions of Prometheus available is ($PROMETHEUS_VERSION), downloading the same... ${reset}"
        # quiet mode used, if you need output for troubleshooting reasons, remove -q
        wget -q https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz -P $HOME/executables
    fi

    if [[ "$*" == *"node_exporter"* ]]
    then
        echo "${green}The latest versions of Node Exporter available is ($NODE_VERSION), downloading the same... ${reset}"    
        # quiet mode used, if you need output for troubleshooting reasons, remove -q
        wget -q https://github.com/prometheus/node_exporter/releases/download/v${NODE_VERSION}/node_exporter-${NODE_VERSION}.linux-amd64.tar.gz -P $HOME/executables
    fi
    
    if [[ "$*" == *"grafana"* ]]
    then
        # Checking for Grafana oss report and creating if not there
        if [ -e /etc/yum.repos.d/grafana.repo ]
        then
            echo "${red}grafana repo is already created...${reset}"
        else
            echo "${green}Creating Grafana repo entry in yum.repos.d...${reset}"
            cat >/etc/yum.repos.d/grafana.repo <<EOL
[grafana]
name=grafana
baseurl=https://packages.grafana.com/oss/rpm
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://packages.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
EOL
        fi 
    fi
}

Install-Executables() {

    # Setup Prometheus
    if [[ "$*" == *"prometheus"* ]]
    then
        if [ -e $HOME/executables/prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz ]
        then
            # Make prometheus user
            echo "${green} Creating prometheus user ...${reset}"
            sudo useradd -rs /bin/false -c "Prometheus User" prometheus
            tar xzf $HOME/executables/prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz -C $HOME/executables/

            cd $HOME/executables/

            # Make directories and dummy files necessary for prometheus
            sudo mkdir /etc/prometheus
            sudo mkdir /var/lib/prometheus
            sudo touch /etc/prometheus/prometheus.yml        

            # permissions setup
            sudo chown -R prometheus:prometheus /etc/prometheus        
            
            sudo cp prometheus-${PROMETHEUS_VERSION}.linux-amd64/prometheus /usr/local/bin/
            sudo cp prometheus-${PROMETHEUS_VERSION}.linux-amd64/promtool /usr/local/bin/
            sudo cp -r prometheus-${PROMETHEUS_VERSION}.linux-amd64/consoles /etc/prometheus
            sudo cp -r prometheus-${PROMETHEUS_VERSION}.linux-amd64/console_libraries /etc/prometheus
            sudo cp -r prometheus-${PROMETHEUS_VERSION}.linux-amd64/prometheus.yml /etc/prometheus

            # permissions setup
            sudo chown prometheus:prometheus /var/lib/prometheus
            sudo chown -R prometheus:prometheus /etc/prometheus/consoles
            sudo chown -R prometheus:prometheus /etc/prometheus/console_libraries
            sudo chown prometheus:prometheus /usr/local/bin/prometheus
            sudo chown prometheus:prometheus /usr/local/bin/promtool
            sudo chown prometheus:prometheus /etc/prometheus/prometheus.yml

            # update service configuration
            cat >/etc/systemd/system/prometheus.service <<EOL
[Unit]
Description=Prometheus
Wants=network-online. Target
After=network-online. Target
[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
          --config.file /etc/prometheus/prometheus.yml \
          --storage.tsdb.path /var/lib/prometheus/ \
          --web.console.templates=/etc/prometheus/consoles \
          --web.console.libraries=/etc/prometheus/console_libraries
EOL

            # setup service
            echo "${green} Enabling and starting prometheus service ... ${reset}"
            sudo systemctl daemon-reload
            sudo systemctl enable prometheus
            sudo systemctl start prometheus

            # create firewall rules
            echo "${green} Creating firewall rules for prometheus service ... ${reset}"
            sudo firewall-cmd --zone=public --add-port=9090/tcp --permanent
            sudo systemctl reload firewalld

            echo "${green}If all went well, then you should be able to access Prometheus on http://localhost:9090 ...${reset}"

            # Installation cleanup
            echo "${green} Cleaning up prometheus installer files ... ${reset}"
            rm prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz
            rm -rf prometheus-${PROMETHEUS_VERSION}.linux-amd64
        else 
            echo "${red} Installer files not available at ($HOME/executables/) ... ${reset}"
        fi
    fi

    # Setup Node Exporter
    if [[ "$*" == *"node_exporter"* ]]
    then
        if [ -e $HOME/executables/node_exporter-${NODE_VERSION}.linux-amd64.tar.gz ]
        then
            # Make node_exporter user
            echo "${green} Creating nodeusr user ...${reset}"
            sudo useradd -rs /bin/false -c "Node Exporter User" nodeusr        
            tar xzf $HOME/executables/node_exporter-${NODE_VERSION}.linux-amd64.tar.gz -C $HOME/executables/

            cd $HOME/executables/

            sudo cp node_exporter-${NODE_VERSION}.linux-amd64/node_exporter /usr/local/bin/
            sudo chown nodeusr:nodeusr /usr/local/bin/node_exporter

            # update service configuration
            cat >/etc/systemd/system/node_exporter.service <<EOL
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target
[Service]
User=nodeusr
Group=nodeusr
Type=simple
ExecStart=/usr/local/bin/node_exporter --collector.systemd
[Install]
WantedBy=multi-user.target
EOL

            # setup service
            echo "${green} Enabling and starting node_exporter service ... ${reset}"
            sudo systemctl daemon-reload
            sudo systemctl enable node_exporter
            sudo systemctl start node_exporter

            # create firewall rules
            echo "${green} Creating firewall rules for node_exporter service (for windows one in addition) ... ${reset}"
            sudo firewall-cmd --zone=public --add-port=9100/tcp --permanent 
            sudo firewall-cmd --zone=public --add-port=9182/tcp --permanent # creating one of Windows Node in advance, you can comment the line if not needed
            sudo systemctl reload firewalld

            echo "${green}If all went well, then you should be able to access Node_exporter on http://localhost:9100 ...${reset}"

            # Installation cleanup
            echo "${green} Cleaning up Node Exporter installer files ... ${reset}"
            rm node_exporter-${NODE_VERSION}.linux-amd64.tar.gz
            rm -rf node_exporter-${NODE_VERSION}.linux-amd64
        else
            echo "${red} Installer files not available at ($HOME/executables/) ... ${reset}"
        fi
    fi

    if [[ "$*" == *"grafana"* ]]
    then
        sudo yum install grafana -y -q

        # setup service
        echo "${green} Enabling and starting Grafana service ... ${reset}"
        sudo systemctl daemon-reload
        sudo systemctl enable grafana-server
        sudo systemctl start grafana-server

        # create firewall rules
        echo "${green} Creating firewall rules for Grafana service ... ${reset}"
        sudo firewall-cmd --zone=public --add-port=3000/tcp --permanent
        sudo systemctl reload firewalld

        echo "${green}If all went well, then you should be able to access Grafana on http://localhost:3000 ...${reset}"
    fi
}

# Ready up executables
Get-Executables prometheus grafana node_exporter
Install-Executables prometheus grafana node_exporter
