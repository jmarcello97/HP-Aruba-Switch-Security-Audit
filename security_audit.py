from ansible.module_utils.basic import *

def main():

	fields = {
		"port_security": {"required": True, "type": "list"}
	}

	module = AnsibleModule(argument_spec=fields)

	module.exit_json(changed=False, meta=module.params)

main()
