package compliance_framework.ports

import data.ccf_libs.helpers

title := "Only approved ports are open"

violation contains {"id": "unapproved-port"} if {
	some port in input.open_ports
	not helpers.approved(port)
}
