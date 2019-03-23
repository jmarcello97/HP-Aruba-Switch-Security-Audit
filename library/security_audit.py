from ansible.module_utils.basic import *

f = open("audit_report.txt", "w")

def port_security_audit(module):
	command_output = module.params['port_security']

	# remove unneeded lines from show port_security command
	command_output=command_output[5:]

	port_security_config=dict()

	# put port security info into a dictionary
	# port number is the key and the value is a list of [learn mode, action, eavesdrop prevention]
	for line in command_output:
		line=str(line.strip())
		info = line.split()
		if info[3] != "None":
			i = 4
			while i < len(info)-1:
				info[3]+=" "+info[i]
				i+=1
			info[4]=info[len(info)-1]
		port_security_config[int(info[0])] = [info[1],info[3],info[4]]


	return port_security_config

def arp_protect_audit(module):
	command_output = module.params['arp_protect']

	return str(command_output[3]).strip()

def dhcp_snooping_audit(module):
	command_output = module.params['dhcp_snooping']

	return str(command_output[1]).strip()

def generate_audit_report(port_security_config, arp_protect_config, dhcp_snooping_config):
	f.write("Port Security Results:\n")

	for port in sorted(port_security_config):
		seems_secure=True
		
		f.write("  Port {}:\n".format(port))

		if port_security_config[port][0] == "Continuous":
			seems_secure=False
			f.write("    Continuous learn mode active. Will learn addresses from inboud traffic of ANY connected device \n")

		if port_security_config[port][1] == "None":
			seems_secure=False
			f.write("    No action set. Consider sending an alarm or shutting down interface when attack occurs \n")

		if port_security_config[port][2] == "Disabled":
			seems_secure=False
			f.write("    Eavesdrop Prevention set to disabled. Enable this to prevent unicast flooding \n")

		if seems_secure == True:
			f.write("    Seems Secure \n")	

	f.write("\n")

	f.write("Arp Protect Results:\n")
	if "No" in arp_protect_config:
		f.write("  ARP protection is currently disabled. Enable to protect against ARP attacks.\n")

	else:
		f.write("  ARP protection is enabled, good job.\n")

	f.write("DHCP Snooping Results:\n")
	if "No" in arp_protect_config:
		f.write("  DHCP snooping is currently disabled. Enable to protect against DHCP Snooping attacks.\n")
	else:
		f.write("  DHCP snooping is enabled, good job.\n")

		
def main():

	fields = {
		"port_security": {"required": True, "type": "list"},
		"arp_protect": {"required": True, "type": "list"},
		"dhcp_snooping": {"required": True, "type": "list"}
	}

	module = AnsibleModule(argument_spec=fields)

	port_security_config = port_security_audit(module)
	arp_protect_config = arp_protect_audit(module)
	dhcp_snooping_config = dhcp_snooping_audit(module)

	generate_audit_report(port_security_config, arp_protect_config, dhcp_snooping_config)

	module.exit_json(changed=False, meta=module.params, port_security_config=port_security_config)

main()
