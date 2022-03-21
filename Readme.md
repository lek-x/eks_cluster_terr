# AWS Elastic Kubernetes Service (EKS) deploying

## Description

This code uses last versions of aws terraform modules and deploys AWS k8s cluster(EKS) with one node group.


## Requrements: 
  - AWS account
  - Terraform >= 1.0
  - kubectl on host OS
  - aws cli tool



# How to:
1. Clone repo
2. Edit variables.tf according to your preferences
3. Add AWS token to **terraform.tfvars.exmaple** and rename it to **terraform.tfvars**

4a. For auto deploy run **"./deploy_cluster.sh"**

4b. For manual deploy do next steps

Init modules:
```
terraform init
```

Check config:
```
terraform validate
```
Deploy:
```
terraform apply
```


It takes ~12-14 min to deploy the cluster. Terraform also creates ssh private key in the root of directory.
If you do manual deploy after terraform finishes work run: 

```
aws eks update-kubeconfig --region $your_region --name mycluster-v2
```

## License
GNU GPL v3