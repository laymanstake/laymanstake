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
            useradd -rs /bin/false -c "Prometheus User" prometheus
            tar xzf $HOME/executables/prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz -C $HOME/executables/

            cd $HOME/executables/

            # Make directories and dummy files necessary for prometheus
            mkdir /etc/prometheus
            mkdir /var/lib/prometheus
            touch /etc/prometheus/prometheus.yml        

            # permissions setup
            chown -R prometheus:prometheus /etc/prometheus        
            
            cp prometheus-${PROMETHEUS_VERSION}.linux-amd64/prometheus /usr/local/bin/
            cp prometheus-${PROMETHEUS_VERSION}.linux-amd64/promtool /usr/local/bin/
            cp -r prometheus-${PROMETHEUS_VERSION}.linux-amd64/consoles /etc/prometheus
            cp -r prometheus-${PROMETHEUS_VERSION}.linux-amd64/console_libraries /etc/prometheus
            cp -r prometheus-${PROMETHEUS_VERSION}.linux-amd64/prometheus.yml /etc/prometheus

            # permissions setup
            chown prometheus:prometheus /var/lib/prometheus
            chown -R prometheus:prometheus /etc/prometheus/consoles
            chown -R prometheus:prometheus /etc/prometheus/console_libraries
            chown prometheus:prometheus /usr/local/bin/prometheus
            chown prometheus:prometheus /usr/local/bin/promtool
            chown prometheus:prometheus /etc/prometheus/prometheus.yml

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
            systemctl daemon-reload
            systemctl enable prometheus
            systemctl start prometheus

            # create firewall rules
            echo "${green} Creating firewall rules for prometheus service ... ${reset}"
            firewall-cmd --zone=public --add-port=9090/tcp --permanent
            systemctl reload firewalld

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
            useradd -rs /bin/false -c "Node Exporter User" nodeusr        
            tar xzf $HOME/executables/node_exporter-${NODE_VERSION}.linux-amd64.tar.gz -C $HOME/executables/

            cd $HOME/executables/

            cp node_exporter-${NODE_VERSION}.linux-amd64/node_exporter /usr/local/bin/
            chown nodeusr:nodeusr /usr/local/bin/node_exporter

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
            systemctl daemon-reload
            systemctl enable node_exporter
            systemctl start node_exporter

            # create firewall rules
            echo "${green} Creating firewall rules for node_exporter service (for windows one in addition) ... ${reset}"
            firewall-cmd --zone=public --add-port=9100/tcp --permanent 
            firewall-cmd --zone=public --add-port=9182/tcp --permanent # creating one of Windows Node in advance, you can comment the line if not needed
            systemctl reload firewalld

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
        yum install grafana -y -q

        # setup service
        echo "${green} Enabling and starting Grafana service ... ${reset}"
        systemctl daemon-reload
        systemctl enable grafana-server
        systemctl start grafana-server

        # create firewall rules
        echo "${green} Creating firewall rules for Grafana service ... ${reset}"
        firewall-cmd --zone=public --add-port=3000/tcp --permanent
        systemctl reload firewalld

        echo "${green}If all went well, then you should be able to access Grafana on http://localhost:3000 ...${reset}"
    fi
}

Remove-Services() {
    # Remove Node Exporter
    if [[ "$*" == *"node_exporter"* ]]
    then
        # Stop and remove Node Exporter Service
        echo "${green} Stoping and removing Node Exporter Service and related files ... ${reset}"
        systemctl stop node_exporter
        systemctl disable node_exporter
        rm -f /usr/local/bin/node_exporter
        rm -f /etc/systemd/system/node_exporter.service
        systemctl daemon-reload
        systemctl reset-failed

        # Remove firewall rule created
        echo "${green} Removing Node Exporter related firewall rules ... ${reset}"
        firewall-cmd --zone=public --remove-port=9100/tcp --permanent 
        systemctl reload firewalld

        # Remove created user for the service
        echo "${green} Removing Node Exporter related user account ... ${reset}"
        userdel -f nodeusr
    fi

    if [[ "$*" == *"prometheus"* ]]
    then
        # Stop and remove Prometheus Service
        echo "${green} Stoping and removing Prometheus Service and related files ... ${reset}"
        systemctl stop prometheus
        systemctl disable prometheus
        rm -f /usr/local/bin/prometheus
        rm -f /usr/local/bin/promtool
        rm -rf /var/lib/prometheus
        rm -rf /etc/prometheus
        rm -f /etc/systemd/system/prometheus.service
        systemctl daemon-reload
        systemctl reset-failed

        # Remove firewall rule created
        echo "${green} Removing Prometheus related firewall rules ... ${reset}"
        firewall-cmd --zone=public --remove-port=9090/tcp --permanent 
        systemctl reload firewalld

        # Remove created user for the service
        echo "${green} Removing Prometheus related user account ... ${reset}"
        userdel -f prometheus
    fi

    if [[ "$*" == *"grafana"* ]]
    then
        # Stop and remove Prometheus Service
        echo "${green} Stoping and removing Grafana Service and related files ... ${reset}"
        systemctl stop grafana-server
        systemctl disable grafana-server        
        systemctl daemon-reload
        systemctl reset-failed
        yum remove grafana -y -q
        
        # Removing Grafana Dashboards and DB
        echo "${red} Removing Grafana related firewall rules ... ${reset}"
        rm -rf /var/lib/grafana

        # Remove firewall rule created
        echo "${green} Removing Grafana related firewall rules ... ${reset}"
        firewall-cmd --zone=public --remove-port=3000/tcp --permanent 
        systemctl reload firewalld
    fi
 
}

# Ready up executables
#Get-Executables prometheus grafana node_exporter
#Install-Executables prometheus grafana node_exporter
#Remove-Services node_exporter grafana

# You would still need to add config in /etc/prometheus/prometheus.yml before you can see data from the node
