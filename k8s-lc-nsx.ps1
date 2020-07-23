param (
    [string]$server=$null,
    [Parameter(Mandatory = $true)][string]$username,
    [SecureString]$password = $( Read-Host -asSecureString "Input VM password, please" ),
	[string]$nodes,
	[Parameter(Mandatory = $true)][string]$clusterName,
	[bool]$remove,
	[bool]$master,
	[Parameter(Mandatory = $true)][string]$clonefrom,
	[Parameter(Mandatory = $true)][string]$portGroup,
    [Parameter(Mandatory = $true)][string]$nsxNetwork,
	[Parameter(Mandatory = $true)][string]$nsxUsername,
	[SecureString]$nsxSecurePassword = $( Read-Host -asSecureString "Input NSX password, please" ),
	[Parameter(Mandatory = $true)][string]$nsxAddr
)


#########################################################
#Copyright © 2019 VMware, Inc. All Rights Reserved.
#SPDX-License-Identifier: GPL-3.0-or-later
#########################################################

function DoClone{
	param([string]$cloneName,[string]$clonefrom,[string]$portGroup,[string]$nsxNetwork)
	#This function clones the base VM
	Write-Host "Buidling $cloneName"
	#Get VM and Build Clone Spec
	$sourceVM = Get-VM "$clonefrom" | Get-View
	$cloneFolder = $sourceVM.parent
	$cloneSpec = new-object Vmware.Vim.VirtualMachineCloneSpec
	$cloneSpec.Snapshot = $sourceVM.Snapshot.CurrentSnapshot
	$cloneSpec.Location = new-object Vmware.Vim.VirtualMachineRelocateSpec
	$cloneSpec.Location.DiskMoveType = [Vmware.Vim.VirtualMachineRelocateDiskMoveOptions]::createNewChildDiskBacking

	#Start Clone Task Async
	$task = $sourceVM.CloneVM_Task( $cloneFolder, $cloneName, $cloneSpec )

	#Wait for task to finish
	$clonetask = Get-View $task
	while("running","queued" -contains $clonetask.Info.State){
	  sleep 1
  	$clonetask.UpdateViewData("Info.State")
	}

	Write-Host "Clone Done"

	#Get New VM
	$vm = (get-vm $cloneName )
	#Set K8 Cluster Info
	$out = ($vm | Set-Annotation -CustomAttribute "K8-Cluster" -Value $clusterName)
	try{
		start-sleep -s 2
		#Add Network Adapter On k8s network
		$newnet = New-NetworkAdapter -VM $vm -NetworkName $portGroup -StartConnected
	}catch{}
	#Power on VM
	start-vm $vm | out-null

	#Have to use opaque network adapter because verions of powercli doesn't support nvds portgroups as traditional portgroups
	$adapter = $vm | Get-NetworkAdapter -ErrorAction SilentlyContinue
	$opaqueNetwork = Get-View -ViewType OpaqueNetwork | where Name -eq $nsxNetwork
	$opaqueNetworkBacking = New-Object VMware.Vim.VirtualEthernetCardOpaqueNetworkBackingInfo
	$opaqueNetworkBacking.OpaqueNetworkId = $opaqueNetwork.Summary.OpaqueNetworkId
	$opaqueNetworkBacking.OpaqueNetworkType = $opaqueNetwork.Summary.OpaqueNetworkType
	$device = $adapter[1].ExtensionData
	$device.Backing = $opaqueNetworkBacking
	$spec = New-Object VMware.Vim.VirtualDeviceConfigSpec
	$spec.Operation = [VMware.Vim.VirtualDeviceConfigSpecOperation]::edit
	$spec.Device = $device
	$configSpec = New-Object VMware.Vim.VirtualMachineConfigSpec
	$configSpec.DeviceChange = @($spec)
	$vm.ExtensionData.ReconfigVM($configSpec)


	#get-vm -name $vm | get-networkadapter| where NetworkName -eq $portGroup | set-networkadapter -networkname (  Get-VirtualPortGroup -Name "$portGroup" -vmhost (get-vm $vm).vmhost.name) -connected $true -Confirm:$false  | out-null
	#Attach network adapter
	try{
		$results = get-vm -name $vm | get-networkadapter| set-networkadapter -Connected:$true -Confirm:$false -ErrorAction:SilentlyContinue
	}catch{}
	#Wait for VM Tools to start
	Write-Host "Wait For VMware Tools"
	wait-tools -VM (get-vm -name $vm) | out-null


	#Wait for guest to set hostname
	do{
		$name = (Get-view $vm).guest.hostname | out-null #need to wait here
	}while ($name -eq "")

	Write-Host "Wait for IP"
	$ip = $null
	#wait for vm tools to report IP
	do{
		$vm = (get-vm $cloneName)
		$ip = $vm.guest.IPAddress[0]
	}while($ip -eq $null)
	Write-host "$cloneName IP $ip"
	#Return VM object
	return $vm
}

function DoInstall{
	param([string]$cloneName,[string]$plainpassword,[string]$username,[bool]$master,$vm,[string]$joincmd,[string]$clusterName)
	#do k8s install on guest
	Write-Host "Set Hostname"
	#set guest hostname.  this uses the password provided is not secure
	$script = "echo $plainpassword | /usr/bin/sudo -S hostnamectl set-hostname $cloneName &> /tmp/k8s-master.log"
	$results = Invoke-VMScript -VM $vm -ScriptType Bash -ScriptText $script -GuestUser $username -GuestPassword $plainpassword
	Write-Host "Download NSX Components"
	#Copy NSX bits to host.  Must be in the local dir the script runs from
	Copy-VMGuestFile -source "libopenvswitch_2.9.1.9968033-1_amd64.deb" -destination "/tmp/libopenvswitch_2.9.1.9968033-1_amd64.deb" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 
	Copy-VMGuestFile -source "openvswitch-common_2.9.1.9968033-1_amd64.deb" -destination "/tmp/openvswitch-common_2.9.1.9968033-1_amd64.deb" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 
	Copy-VMGuestFile -source "openvswitch-datapath-dkms_2.9.1.9968033-1_all.deb" -destination "/tmp/openvswitch-datapath-dkms_2.9.1.9968033-1_all.deb" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 
	Copy-VMGuestFile -source "openvswitch-switch_2.9.1.9968033-1_amd64.deb" -destination "/tmp/openvswitch-switch_2.9.1.9968033-1_amd64.deb" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 
	Copy-VMGuestFile -source "nsx-cni_2.3.0.10066840_amd64.deb" -destination "/tmp/nsx-cni_2.3.0.10066840_amd64.deb" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 
	Write-Host "Download NCP.  This may take some time"
	Copy-VMGuestFile -source "nsx-ncp-ubuntu-2.3.0.10066840.tar" -destination "/tmp/nsx-ncp-ubuntu-2.3.0.10066840.tar" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 

	#If master node then create cluster
	if($master){
		Write-Host "Download and Execute Install Script"
		#copy local nsx-install script.  must be in local dir
		Copy-VMGuestFile -source "nsx-install-2.3.0" -destination "/tmp/nsx-install-2.3.0" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 
		#set runtime variables in script
		$script = "sed -i 's/##CLUSTER##/$clusterName/' /tmp/nsx-install-2.3.0 && sed -i 's/##NSXUSER##/$nsxUsername/' /tmp/nsx-install-2.3.0 && sed -i 's/##NSXPASSWORD##/$nsxPassword/' /tmp/nsx-install-2.3.0 && sed -i 's/##NSXADDR##/$nsxAddr/' /tmp/nsx-install-2.3.0 && chmod +x /tmp/nsx-install-2.3.0 &>> /tmp/k8s-master.log"
		$results = Invoke-VMScript -VM $vm -ScriptType Bash -ScriptText $script -GuestUser $username -GuestPassword $plainpassword
		#config script to install and config master none
		$script = "echo $plainpassword | /usr/bin/sudo -S /tmp/nsx-install-2.3.0 &>> /tmp/k8s-master.log"
		$script = $script + "`n"+ 'echo "cp -i /etc/kubernetes/admin.conf /home/'+ $username+'/.kube/config" >> /tmp/k8s-master.sh' +"`n"
		$script = $script + "`n"+ 'echo "chown -R '+ $username+":"+ $username+' /home/k8admin/.kube" >> /tmp/k8s-master.sh' +"`n"
		#run script and return results
		$results = Invoke-VMScript -VM $vm -ScriptType Bash -ScriptText $script -GuestUser $username -GuestPassword $plainpassword
	}else{
		#if not master then run asyc to build additional nodes
		Write-Host "Download Install Script"
		#copy local isntall script
		Copy-VMGuestFile -source "nsx-install-2.3.0-join" -destination "/tmp/nsx-install-2.3.0-join" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 
		#set +x on install script
		$script = "chmod +x /tmp/nsx-install-2.3.0-join &>> /tmp/k8s-master.log"
		$results = Invoke-VMScript -VM $vm -ScriptType Bash -ScriptText $script -GuestUser $username -GuestPassword $plainpassword
		#add join k8s cluster to end of script
		$script = 'echo "'+$joincmd+'" >> /tmp/nsx-install-2.3.0-join'
		$results = Invoke-VMScript -VM $vm -ScriptType Bash -ScriptText $script -GuestUser $username -GuestPassword $plainpassword
		Write-host "Execute Install and Joing Cluster -Async.  Will continue without checking status."
		#run script async and continue without checking results
		$script = "echo $plainpassword | /usr/bin/sudo -S /tmp/nsx-install-2.3.0-join &>> /tmp/k8s-master.log"
		$results = Invoke-VMScript -VM $vm -ScriptType Bash -ScriptText $script -GuestUser $username -GuestPassword $plainpassword -RunAsync |out-null
	}
	
	#check exit code is master
	write-host "Install Exit code " $results.exitcode
	if ($master){
		#is exicode is null then wait 30 seconds
		if($results.exitcode -eq $null){
			Write-Host "Script Timeout waiting 30seconds"
			start-sleep -s 30
		}
		#find join command in install log
		Write-Host "Get Join Command" 
		$script = 'cat /tmp/k8s-master.log | grep -Pzo "kubeadm join.*?\n.*?\n"'
 		do{
			$output = (Invoke-VMScript -VM $vm -ScriptType Bash -ScriptText $script -GuestUser $username -GuestPassword $plainpassword)
			$joincmd = $output.ScriptOutput -replace '\\','' -replace '[^ -~]+','' -replace '(\s+)',' ' 
			Write-Host "Join CMD: $joincmd"
		}while(!$joincmd -like "*join*")
		#set k8s info on vm
		$out = ($vm | Set-Annotation -CustomAttribute "K8-Role" -Value "Master")
		$out = ($vm | Set-Annotation -CustomAttribute "K8-Join" -Value $joincmd)
		#get admin.conf and copy to local machine for kubectl use
		Write-Host "Get config file"
		Copy-VMGuestFile -Source "/etc/kubernetes/admin.conf" -Destination (((Get-Item -Path ".\").FullName)+"\$clusterName.conf") -VM $vm -GuestToLocal -GuestUser $username -GuestPassword $password
		Write-Host "Config file at: "(((Get-Item -Path ".\").FullName)+"\$clusterName.conf")
	}else{
		#if not master then mark as node
		$out = ($vm | Set-Annotation -CustomAttribute "K8-Role" -Value "Node")
	}
}

function DoRemove{
	param([string]$plainpassword,[string]$username,[string]$clusterName,[string]$nodes,[bool]$master)
	#remove node, master, or all
	#find master vm for cluster name
	$mastervm = (get-vm  | Where{$_.CustomFields.Item("K8-Cluster") -eq $clusterName -and  $_.CustomFields.Item("K8-Role") -eq "Master"})
	#find node vms for cluster name
	$vms= (get-vm  | Where{$_.CustomFields.Item("K8-Cluster") -eq $clusterName -and  $_.CustomFields.Item("K8-Role") -eq "Node"})
	if($master){
		#if master set then remove all nodes
		write-host "Removing all nodes from cluster $clusterName"
		$nodes = $vms.length
	}else{
		#if master not set then scale down cluster
		Write-Host "Removing $nodes nodes from cluster $clusterName"
	}
	#loop through number of nodes requested for removal
	for($i=0;$i -lt $nodes;$i++){
		$vm = $vms[$vms.length-$i-1]
		Write-Host "Remove node $vm from cluster"
		$script = "kubectl delete node "+$vm
		#remove node from k8s before poweroff and delete
		Invoke-VMScript -VM $mastervm -ScriptType Bash -ScriptText $script -GuestUser $username -GuestPassword $plainpassword -RunAsync |out-null
		Write-Host "Power off and delete $vm"
        try{
			$results = ($vms[$vms.length-$i-1] | stop-vm -Confirm:$false)
        }catch{}
        try{
			$results = ($vms[$vms.length-$i-1] | remove-vm -DeletePermanently -Confirm:$false -RunAsync)
        }catch{}
	}
	#If master set remove master node
	if($master){
		write-host "Removing Master $master"
	    try{
			$results = ($mastervm	| stop-vm -Confirm:$false)
    	}catch{}
    	try{
			$results = ($mastervm | remove-vm -DeletePermanently -Confirm:$false)
    	}catch{}
		Write-Host "Cluster Deleted"
	}
}

function SetNSXTags{
param($vm,[string]$nsxUsername,[string]$nsxPassword,[string]$nsxIP,[string]$cluster)
	#set NSX Tages for node vm
	write-host "Set TAGs" $vm.Name
	#accept invalid certs
	add-type @"
	    using System.Net;
	    using System.Security.Cryptography.X509Certificates;
	    public class TrustAllCertsPolicy : ICertificatePolicy {
        	public bool CheckValidationResult(
	            ServicePoint srvPoint, X509Certificate certificate,
    	        WebRequest request, int certificateProblem) {
            	return true;
        	}
    	}
"@
	[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
	[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
	#set nsx manager auth
	$BaseURL = "https://" + $nsxIP 
	$Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($nsxUsername+":"+$nsxPassword))}
	$Type = "application/json"
	#build api resutest for vm
	$vmname =$vm.name
	$uri = "/api/v1/fabric/virtual-machines?display_name="+$vmname
	$response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method get -ContentType $Type
	#get external id of vm
	$externalid = $response.results.external_id
	write-host "Externalid: $externalid"
	#get local port attachment id
	$uri="/api/v1/fabric/vifs?owner_vm_id=$externalid"
	$response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method get -ContentType $Type
	$lport_attach_id = ($response.results | select * | where device_name -ne "Network adapter 1").lport_attachment_id
	if($lport_attach_id -eq $null){
		#sometimes this fails  nsx to busy or something,  rerun should probably rewrite this code
    	do{
        	start-sleep -s 5
        	Write-Host "No LPort Attach ID Try again"
        	$vmname =$vm.name
	        $uri = "/api/v1/fabric/virtual-machines?display_name="+$vmname
    	    $response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method get -ContentType $Type
        	$externalid = $response.results.external_id
	        write-host "Externalid: $externalid"
	        $uri="/api/v1/fabric/vifs?owner_vm_id=$externalid"
    	   $response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method get -ContentType $Type
        	$lport_attach_id = ($response.results | select * | where device_name -ne "Network adapter 1").lport_attachment_id
			($response.results | select * | where device_name -ne "Network adapter 1").lport_attachment_id
    	}while(!$lport_attach_id)
	}

	write-host "LPort Attach ID: $lport_attach_id"
	#get logicalport
	$uri="/api/v1/logical-ports"
	$response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method get -ContentType $Type
	#Twice Cause NSX is silly??
	$uri="/api/v1/logical-ports"
	$response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method get -ContentType $Type
	$lport = ($response.results | select id, attachment | select id,@{n="attachid";e={$_.attachment.id}} | where attachid -eq $lport_attach_id).id
	#logical switch id
	$logical_switch_id = ($response.results | select logical_switch_id, attachment | select logical_switch_id,@{n="attachid";e={$_.attachment.id}} | where attachid -eq $lport_attach_id).logical_switch_id
	#revision number for api set request
	$rev = ($response.results | select _revision, attachment | select _revision,@{n="attachid";e={$_.attachment.id}} | where attachid -eq $lport_attach_id)._revision
	Write-Host "LPort: $lport Logical Switch ID: $logical_switch_id Rev: $rev"
	#build api request to set logical port tag
	$uri="/api/v1/logical-ports/$lport"
	$body = '{"tags":[{"scope":"ncp/node_name","tag":"'+$vm.name+'"},{"scope":"ncp/cluster","tag":"'+$cluster+'"}],"logical_switch_id":"'+$logical_switch_id+'","attachment": { "attachment_type": "VIF", "id": "'+$lport_attach_id+'"},"_revision": '+$rev+',"admin_state": "UP"}'
	try{
    	$response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method put -ContentType $Type -Body $body
	}Catch{
		#run again on error must update values incase of change
    	$uri="/api/v1/logical-ports"
    	$response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method get -ContentType $Type
    	$lport = ($response.results | select id, attachment | select id,@{n="attachid";e={$_.attachment.id}} | where attachid -eq $lport_attach_id).id
    	$logical_switch_id = ($response.results | select logical_switch_id, attachment | select logical_switch_id,@{n="attachid";e={$_.attachment.id}} | where attachid -eq $lport_attach_id).logical_switch_id
    	$rev = ($response.results | select _revision, attachment | select _revision,@{n="attachid";e={$_.attachment.id}} | where attachid -eq $lport_attach_id)._revision
	    Write-Host "LPort: $lport Logical Switch ID: $logical_switch_id Rev: $rev"
    	$uri="/api/v1/logical-ports/$lport"
    	$body = '{"tags":[{"scope":"ncp/node_name","tag":"'+$vm.name+'"},{"scope":"ncp/cluster","tag":"'+$cluster+'"}],"logical_switch_id":"'+$logical_switch_id+'","attachment": { "attachment_type": "VIF", "id": "'+$lport_attach_id+'"},"_revision": '+$rev+',"admin_state": "UP"}'
	}
}


# workflow for paralle execution
workflow DoNodes{
param (
	[Parameter(Mandatory = $true)][string]$clonefrom,
	[Parameter(Mandatory = $true)][string]$portGroup,
    [Parameter(Mandatory = $true)][string]$nsxNetwork,
	[Parameter(Mandatory = $true)][string]$plainpassword,
	[Parameter(Mandatory = $true)][string]$username,
	[Parameter(Mandatory = $true)][string]$joincmd,
	[Parameter(Mandatory = $true)][string]$clusterName,
	[Parameter(Mandatory = $true)]$number,
	[Parameter(Mandatory = $true)]$remaining,
	[Parameter(Mandatory = $true)]$vcenter,
	[Parameter(Mandatory = $true)]$session,
	[Parameter(Mandatory = $true)]$path,
	[Parameter(Mandatory = $true)][string]$nsxUsername,
	[Parameter(Mandatory = $true)][string]$nsxPassword,
	[Parameter(Mandatory = $true)][string]$nsxAddr
)
	
	#run for each in number of nodes to create
	foreach -Paralle ($number in $remaining) {
		#run this inline script as workflow  should figure out how to move all code to this
		inlineScript {
			function DoClone{
				param([string]$cloneName,[string]$clonefrom,[string]$portGroup,[string]$nsxNetwork)
				Write-Host "$cloneName : Buidling $cloneName"
				$sourceVM = Get-VM "$clonefrom" | Get-View
				$cloneFolder = $sourceVM.parent
				$cloneSpec = new-object Vmware.Vim.VirtualMachineCloneSpec
				$cloneSpec.Snapshot = $sourceVM.Snapshot.CurrentSnapshot
				$cloneSpec.Location = new-object Vmware.Vim.VirtualMachineRelocateSpec
				$cloneSpec.Location.DiskMoveType = [Vmware.Vim.VirtualMachineRelocateDiskMoveOptions]::createNewChildDiskBacking
				$task = $sourceVM.CloneVM_Task( $cloneFolder, $cloneName, $cloneSpec )
				$clonetask = Get-View $task
				while("running","queued" -contains $clonetask.Info.State){
  					sleep 1
  					$clonetask.UpdateViewData("Info.State")
				}
				Write-Host "$cloneName : Clone Done"
				$vm = (get-vm $cloneName )
				$out = ($vm | Set-Annotation -CustomAttribute "K8-Cluster" -Value $using:clusterName)
				try{
					start-sleep -s 2
					$newnet = New-NetworkAdapter -VM $vm -NetworkName $portGroup -StartConnected
				}catch{}
				start-vm $vm | out-null
				#$newnet | Set-NetworkAdapter -StartConnected $true
				$adapter = $vm | Get-NetworkAdapter -ErrorAction SilentlyContinue
				#$adapter = $newnet
				$opaqueNetwork = Get-View -ViewType OpaqueNetwork | where Name -eq $nsxNetwork
				$opaqueNetworkBacking = New-Object VMware.Vim.VirtualEthernetCardOpaqueNetworkBackingInfo
				$opaqueNetworkBacking.OpaqueNetworkId = $opaqueNetwork.Summary.OpaqueNetworkId
				$opaqueNetworkBacking.OpaqueNetworkType = $opaqueNetwork.Summary.OpaqueNetworkType
				$device = $adapter[1].ExtensionData
				$device.Backing = $opaqueNetworkBacking
				$spec = New-Object VMware.Vim.VirtualDeviceConfigSpec
				$spec.Operation = [VMware.Vim.VirtualDeviceConfigSpecOperation]::edit
				$spec.Device = $device
				$configSpec = New-Object VMware.Vim.VirtualMachineConfigSpec
				$configSpec.DeviceChange = @($spec)
				$vm.ExtensionData.ReconfigVM($configSpec)
				#get-vm -name $vm | get-networkadapter| where NetworkName -eq $portGroup | set-networkadapter -networkname (  Get-VirtualPortGroup -Name "$portGroup" -vmhost (get-vm $vm).vmhost.name) -connected $true -Confirm:$false  | out-null
				try{
					$results = get-vm -name $vm | get-networkadapter| set-networkadapter -Connected:$true -Confirm:$false -ErrorAction:SilentlyContinue
				}catch{}
				Write-Host "$cloneName : Wait For VMware Tools"
				wait-tools -VM (get-vm -name $vm) | out-null
				
				do{
					$name = (Get-view $vm).guest.hostname | out-null #need to wait here
				}while ($name -eq "")
				Write-Host "$cloneName : Wait for IP"
				$ip = $null
				do{
					$vm = (get-vm $cloneName)
					$ip = $vm.guest.IPAddress[0]
				}while($ip -eq $null)
				Write-host "$cloneName : IP $ip"
				return $vm
			}

			function DoInstall{
				param([string]$cloneName,[string]$plainpassword,[string]$username,[bool]$master,$vm,[string]$joincmd,[string]$clusterName)
				Write-Host "$cloneName : Set Hostname"

				$script = "echo $plainpassword | /usr/bin/sudo -S hostnamectl set-hostname $cloneName &> /tmp/k8s-master.log"
				$results = Invoke-VMScript -VM $vm -ScriptType Bash -ScriptText $script -GuestUser $username -GuestPassword $plainpassword
				Write-Host "$cloneName : Download NSX Components"
				Copy-VMGuestFile -source $using:path"\libopenvswitch_2.9.1.9968033-1_amd64.deb" -destination "/tmp/libopenvswitch_2.9.1.9968033-1_amd64.deb" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 
				Copy-VMGuestFile -source $using:path"\openvswitch-common_2.9.1.9968033-1_amd64.deb" -destination "/tmp/openvswitch-common_2.9.1.9968033-1_amd64.deb" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 
				Copy-VMGuestFile -source $using:path"\openvswitch-datapath-dkms_2.9.1.9968033-1_all.deb" -destination "/tmp/openvswitch-datapath-dkms_2.9.1.9968033-1_all.deb" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 
				Copy-VMGuestFile -source $using:path"\openvswitch-switch_2.9.1.9968033-1_amd64.deb" -destination "/tmp/openvswitch-switch_2.9.1.9968033-1_amd64.deb" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 
				Copy-VMGuestFile -source $using:path"\nsx-cni_2.3.0.10066840_amd64.deb" -destination "/tmp/nsx-cni_2.3.0.10066840_amd64.deb" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 
				Write-Host "$cloneName : Download NCP.  This may take some time"
				Copy-VMGuestFile -source $using:path"\nsx-ncp-ubuntu-2.3.0.10066840.tar" -destination "/tmp/nsx-ncp-ubuntu-2.3.0.10066840.tar" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 
				if($master){
					Write-Host "Download and Execute Install Script"
					Copy-VMGuestFile -source "nsx-install-2.3.0" -destination "/tmp/nsx-install-2.3.0" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 
					$script = "chmod +x /tmp/nsx-install-2.3.0 &>> /tmp/k8s-master.log"
					$results = Invoke-VMScript -VM $vm -ScriptType Bash -ScriptText $script -GuestUser $username -GuestPassword $plainpassword
					$script = "echo $plainpassword | /usr/bin/sudo -S /tmp/nsx-install-2.3.0 &>> /tmp/k8s-master.log"
					$script = $script + "`n"+ 'echo "cp -i /etc/kubernetes/admin.conf /home/'+ $username+'/.kube/config" >> /tmp/k8s-master.sh' +"`n"
					$script = $script + "`n"+ 'echo "chown -R '+ $username+":"+ $username+' /home/k8admin/.kube" >> /tmp/k8s-master.sh' +"`n"
					$results = Invoke-VMScript -VM $vm -ScriptType Bash -ScriptText $script -GuestUser $username -GuestPassword $plainpassword
				}else{
					Write-Host "$cloneName : Download Install Script"
					Copy-VMGuestFile -source $using:path"\nsx-install-2.3.0-join" -destination "/tmp/nsx-install-2.3.0-join" -VM $vm -localtoguest -guestuser $username -guestpassword $plainpassword 
					$script = "chmod +x /tmp/nsx-install-2.3.0-join &>> /tmp/k8s-master.log"
					$results = Invoke-VMScript -VM $vm -ScriptType Bash -ScriptText $script -GuestUser $username -GuestPassword $plainpassword
					$script = 'echo "'+$joincmd+'" >> /tmp/nsx-install-2.3.0-join'
					$results = Invoke-VMScript -VM $vm -ScriptType Bash -ScriptText $script -GuestUser $username -GuestPassword $plainpassword
					Write-host "$cloneName : Execute Install and Joing Cluster -Async.  Will continue without checking status."
					$script = "echo $plainpassword | /usr/bin/sudo -S /tmp/nsx-install-2.3.0-join &>> /tmp/k8s-master.log"
					$results = Invoke-VMScript -VM $vm -ScriptType Bash -ScriptText $script -GuestUser $username -GuestPassword $plainpassword -RunAsync |out-null
				}
				write-host "$cloneName : Install Exit code " $results.exitcode
				if ($master){
				if($results.exitcode -eq $null){
					Write-Host "Script Timeout waiting 30seconds"
					start-sleep -s 30
				}

				Write-Host "Get Join Command" 

				$script = 'cat /tmp/k8s-master.log | grep -Pzo "kubeadm join.*?\n.*?\n"'
 				do{
					$output = (Invoke-VMScript -VM $vm -ScriptType Bash -ScriptText $script -GuestUser $username -GuestPassword $plainpassword)
					$joincmd = $output.ScriptOutput -replace '\\','' -replace '[^ -~]+','' -replace '(\s+)',' ' 
					Write-Host "Join CMD: $joincmd"
				}while(!$joincmd -like "*join*")
					$out = ($vm | Set-Annotation -CustomAttribute "K8-Role" -Value "Master")
					$out = ($vm | Set-Annotation -CustomAttribute "K8-Join" -Value $joincmd)
					Write-Host "Get config file"
					Copy-VMGuestFile -Source /etc/kubernetes/admin.conf -Destination (((Get-Item -Path ".\").FullName)+"\$clusterName.conf") -VM $vm -GuestToLocal -GuestUser $username -GuestPassword $password
					Write-Host "Config file at: "(((Get-Item -Path ".\").FullName)+"\$clusterName.conf")
				}else{
					$out = ($vm | Set-Annotation -CustomAttribute "K8-Role" -Value "Node")
				}

			}



			function SetNSXTags{
				param($vm,[string]$nsxUsername,[string]$nsxPassword,[string]$nsxIP,[string]$cluster)
				add-type @"
    				using System.Net;
    				using System.Security.Cryptography.X509Certificates;
    				public class TrustAllCertsPolicy : ICertificatePolicy {
        				public bool CheckValidationResult(
            			ServicePoint srvPoint, X509Certificate certificate,
            			WebRequest request, int certificateProblem) {
            				return true;
        				}
    				}
"@
				[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
				[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'

				$BaseURL = "https://" + $nsxIP 
				$Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($nsxUsername+":"+$nsxPassword))}
				$Type = "application/json"

				$vmname =$vm.name
				$cloneName = $vmname
				write-host "$cloneName : Set TAGs" $vm.Name

				$uri = "/api/v1/fabric/virtual-machines?display_name="+$vmname
				$response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method get -ContentType $Type
				$externalid = $response.results.external_id

				write-host "$cloneName : Externalid: $externalid"

				$uri="/api/v1/fabric/vifs?owner_vm_id=$externalid"
				$response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method get -ContentType $Type
				$lport_attach_id = ($response.results | select * | where device_name -ne "Network adapter 1").lport_attachment_id
				if($lport_attach_id -eq $null){
    				do{
        				start-sleep -s 5
        				Write-Host "$cloneName : No LPort Attach ID Try again"
        				$vmname =$vm.name
				        $uri = "/api/v1/fabric/virtual-machines?display_name="+$vmname
        				$response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method get -ContentType $Type
        				$externalid = $response.results.external_id
				        write-host "$cloneName : Externalid: $externalid"
				        $uri="/api/v1/fabric/vifs?owner_vm_id=$externalid"
        				$response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method get -ContentType $Type
        				$lport_attach_id = ($response.results | select * | where device_name -ne "Network adapter 1").lport_attachment_id
						($response.results | select * | where device_name -ne "Network adapter 1").lport_attachment_id
				    }while(!$lport_attach_id)
				}

				write-host "$cloneName : LPort Attach ID: $lport_attach_id"
				$uri="/api/v1/logical-ports"
				$response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method get -ContentType $Type
				#Twice Cause NSX is silly??
				$uri="/api/v1/logical-ports"
				$response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method get -ContentType $Type
				$lport = ($response.results | select id, attachment | select id,@{n="attachid";e={$_.attachment.id}} | where attachid -eq $lport_attach_id).id
				$logical_switch_id = ($response.results | select logical_switch_id, attachment | select logical_switch_id,@{n="attachid";e={$_.attachment.id}} | where attachid -eq $lport_attach_id).logical_switch_id
				$rev = ($response.results | select _revision, attachment | select _revision,@{n="attachid";e={$_.attachment.id}} | where attachid -eq $lport_attach_id)._revision
				Write-Host "$cloneName : LPort: $lport Logical Switch ID: $logical_switch_id Rev: $rev"
				$uri="/api/v1/logical-ports/$lport"
				$body = '{"tags":[{"scope":"ncp/node_name","tag":"'+$vm.name+'"},{"scope":"ncp/cluster","tag":"'+$cluster+'"}],"logical_switch_id":"'+$logical_switch_id+'","attachment": { "attachment_type": "VIF", "id": "'+$lport_attach_id+'"},"_revision": '+$rev+',"admin_state": "UP"}'
				try{
    				$response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method put -ContentType $Type -Body $body
				}Catch{
    				$uri="/api/v1/logical-ports"
    				$response = Invoke-RestMethod -Uri "$BaseURL$uri" -Headers $Header -Method get -ContentType $Type
    				$lport = ($response.results | select id, attachment | select id,@{n="attachid";e={$_.attachment.id}} | where attachid -eq $lport_attach_id).id
    				$logical_switch_id = ($response.results | select logical_switch_id, attachment | select logical_switch_id,@{n="attachid";e={$_.attachment.id}} | where attachid -eq $lport_attach_id).logical_switch_id
    				$rev = ($response.results | select _revision, attachment | select _revision,@{n="attachid";e={$_.attachment.id}} | where attachid -eq $lport_attach_id)._revision
				    Write-Host "$cloneName : LPort: $lport Logical Switch ID: $logical_switch_id Rev: $rev"
				    $uri="/api/v1/logical-ports/$lport"
    				$body = '{"tags":[{"scope":"ncp/node_name","tag":"'+$vm.name+'"},{"scope":"ncp/cluster","tag":"'+$cluster+'"}],"logical_switch_id":"'+$logical_switch_id+'","attachment": { "attachment_type": "VIF", "id": "'+$lport_attach_id+'"},"_revision": '+$rev+',"admin_state": "UP"}'
				}
			}

			connect-viserver -server $using:vcenter -session $using:session
			$master=$false
			$cloneName = "k8s-node-"+$using:number
			Write-Output $using:cloneName
			#$clonefrom = "ubuntu-18.0.4-lts"
			$vm = DoClone -cloneName $using:cloneName -clonefrom $using:clonefrom -portGroup $using:portGroup -nsxNetwork $using:nsxNetwork
			SetNSXTags -vm $vm -nsxUsername $using:nsxUsername -nsxPassword $using:nsxPassword -nsxIP $using:nsxAddr -cluster $using:clusterName
			$results = DoInstall -cloneName $using:cloneName -plainpassword $using:plainpassword -username $using:username -master $using:master -vm $vm -joincmd $using:joincmd -clusterName $using:clusterName
		}
	}
}

#main code 

$Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $password
$nsxCreds = New-Object System.Management.Automation.PSCredential -ArgumentList $nsxUsername, $nsxSecurePassword
$plainpassword=$Credentials.GetNetworkCredential().Password
$nsxPassword=$nsxCreds.GetNetworkCredential().Password
Import-Module VMware.PowerCLI


#connect to vc if not already connected
if($server) {connect-viserver $server}

#setup custom attrib if not alread in place
$attrib = (New-CustomAttribute -TargetType "VirtualMachine" -Name "K8-Role" -ErrorAction SilentlyContinue)
$attrib = (New-CustomAttribute -TargetType "VirtualMachine" -Name "K8-Cluster" -ErrorAction SilentlyContinue)
$attrib = (New-CustomAttribute -TargetType "VirtualMachine" -Name "K8-Join" -ErrorAction SilentlyContinue)
#set how many nodes to build
$howmany=$nodes
#check for existing k8s nodes
$vms = get-vm | where-object { $_.Name -like "k8s-node-*" }
#extract number and end of node names
$names = $vms.name -replace 'k8s-node-(.*)','$1'
#find max number
$max = $names | measure -maximum
$number = $max.maximum
#if remove is set remove nodes
if($remove){
	#call do remove 
	DoRemove -plainpassword $plainpassword -username $username -clusterName $clusterName -nodes $nodes -master $master
}else{
	#remove not set run build nodes/cluster
	Write-Host "Checking for existing cluster $cluserName"
	try {
		#check if joincmd is avalable for specific cluster
		$joincmd = (get-vm  | Where{$_.CustomFields.Item("K8-Cluster") -eq $clusterName -and  $_.CustomFields.Item("K8-Role") -eq "Master"}).CustomFields.Item("K8-Join")
		Write-Host "Scaling Cluster $clusterName with $nodes more nodes"
		$master=$false
	}catch{
		#if no cluster found then build cluster
		write-host "Cluster $clusterName not found building new cluster"
		$master=$true
		$number++
		$cloneName = "k8s-node-$number"
		#clone vm
		$vm = DoClone -cloneName $cloneName -clonefrom $clonefrom -portGroup $portGroup -nsxNetwork $nsxNetwork
		#setnsx tags
		SetNSXTags -vm $vm -nsxUsername $nsxUsername -nsxPassword $nsxPassword -nsxIP $nsxAddr -cluster $clusterName
		#install k8s + nsx bits and ncp
		$results = DoInstall -cloneName $cloneName -plainpassword $plainpassword -username $username -master $master -vm $vm -joincmd $joincmd -clusterName $clusterName
		$master=$false
		#get join command for other nodes
		$joincmd = (get-vm  | Where{$_.CustomFields.Item("K8-Cluster") -eq $clusterName -and  $_.CustomFields.Item("K8-Role") -eq "Master"}).CustomFields.Item("K8-Join")
		$howmany = $howmany - 1
	}
	$number++
	$remaining = ($number)..($number+$howmany-1)
	write-host "Building $howmany nodes Paralle"
	#build nodes 
	DoNodes -nsxUsername $nsxUsername -nsxPassword $nsxPassword -nsxAddr $nsxAddr -clonefrom $clonefrom -portGroup $portGroup -nsxNetwork $nsxNetwork -plainpassword $plainpassword -username $username -joincmd $joincmd -clusterName $clusterName -number $number -remaining $remaining -vcenter $global:DefaultVIServer.Name -session $global:DefaultVIServer.SessionSecret -path (get-location).path
#for ($i = 0; $i -lt $howmany; $i++){
#	$number++
#	$cloneName = "k8s-node-$number"
#	#$clonefrom = "ubuntu-18.0.4-lts"
#	$vm = DoClone -cloneName $cloneName -clonefrom $clonefrom -portGroup $portGroup -nsxNetwork $nsxNetwork
   #   SetNSXTags -vm $vm -nsxUsername "admin" -nsxPassword "B0xcar45!" -nsxIP "192.168.10.240" -cluster "k8s-cl1"
#   $results = DoInstall -cloneName $cloneName -plainpassword $plainpassword -username $username -master $master -vm $vm -joincmd $joincmd -clusterName $clusterName
#	$master=$false
#	$joincmd = (get-vm  | Where{$_.CustomFields.Item("K8-Cluster") -eq $clusterName -and  $_.CustomFields.Item("K8-Role") -eq "Master"}).CustomFields.Item("K8-Join")
#}
}