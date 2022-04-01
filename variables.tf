variable "accesskey" {}
variable "secretkey" {}
#variable "region" {
#  description = "enter region desired name"
#  type    = string
#  default = "eu-central-1"
#}

variable "token" {}
variable "address" {
    type = string
    default = "http://192.168.1.17:8200"
}
variable "inst_type" {
  description = "enter desired instance type"
  type    = string
  default = "t2.medium"
}

variable "gr_min_size" {
  description = "enter desired minimal size of group (count VMs)"
  type    = number
  default = 2
}

variable "gr_max_size" {
  description = "enter desired maximal size of group (count VMs)"
  type    = number
  default = 3
}

variable "gr_des_size" {
  description = "enter target size of group (count VMs)"
  type    = number
  default = 2
}

variable "disk_size" {
  description = "enter desired VM's disk size"
  type    = number
  default = 70
}



