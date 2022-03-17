#!/bin/bash

####Deploy cluster


#terraform validate

#terraform apply

aws eks update-kubeconfig --region eu-central-1 --name mycluster-v2
