#!/bin/bash

set -e
####Deploy cluster

function terrfync {
    echo "Init modules"
	terraform init
	echo "Check config"
	terraform validate
	
	if [ $? -eq 1 ]
	then
		echo "There is a error in code"
	else 
	terraform apply
	aws eks update-kubeconfig --region eu-central-1 --name mycluster-v2
	fi
	}

terrfync