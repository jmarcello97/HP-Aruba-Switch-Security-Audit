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

def generate_audit_report(port_security_config):
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
		
def main():

	fields = {
		"port_security": {"required": True, "type": "list"}
	}

	module = AnsibleModule(argument_spec=fields)

	port_security_config = port_security_audit(module)

	generate_audit_report(port_security_config)

	module.exit_json(changed=False, meta=module.params, port_security_config=port_security_config)

main()
